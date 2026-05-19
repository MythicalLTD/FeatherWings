package filesystem

import (
	"context"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"golang.org/x/sync/semaphore"
)

type folderSizeEntry struct {
	size    int64
	updated time.Time
}

func (fs *Filesystem) folderSizeTTL() time.Duration {
	// Matches disk_usage.go: time.Second * fs.diskCheckInterval
	return time.Second * fs.diskCheckInterval
}

// normalizedFolderCacheKey returns a stable map key for a path under the server root.
func normalizedFolderCacheKey(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" || p == "." {
		return ""
	}
	p = filepath.ToSlash(p)
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "/")
	if p == "." {
		return ""
	}
	return p
}

func joinListedChildPath(parentKey, name string) string {
	if parentKey == "" {
		return name
	}
	return path.Join(parentKey, name)
}

func pathForDirectorySize(cacheKey string) string {
	if cacheKey == "" {
		return "/"
	}
	return cacheKey
}

func (fs *Filesystem) folderSizeFromCache(cacheKey string) (size int64, fresh bool, found bool) {
	if fs.diskCheckInterval == 0 {
		return 0, false, false
	}
	fs.folderSizeMu.Lock()
	defer fs.folderSizeMu.Unlock()
	e, ok := fs.folderSizeCache[cacheKey]
	if !ok {
		return 0, false, false
	}
	return e.size, time.Since(e.updated) < fs.folderSizeTTL(), true
}

func (fs *Filesystem) setFolderSizeCache(cacheKey string, size int64) {
	fs.folderSizeMu.Lock()
	defer fs.folderSizeMu.Unlock()
	if fs.folderSizeCache == nil {
		fs.folderSizeCache = make(map[string]folderSizeEntry)
	}
	fs.folderSizeCache[cacheKey] = folderSizeEntry{size: size, updated: time.Now()}
}

// attachDirectorySizes fills DirectorySize from cache and schedules async refresh
// for missing or stale subdirectory entries.
func (fs *Filesystem) attachDirectorySizes(out *[]Stat, listPath string) {
	if fs.diskCheckInterval == 0 || out == nil {
		return
	}

	parentKey := normalizedFolderCacheKey(listPath)
	var staleOrMissing []string

	for i := range *out {
		st := &(*out)[i]
		if !st.IsDir() {
			continue
		}
		cacheKey := normalizedFolderCacheKey(joinListedChildPath(parentKey, st.Name()))
		if cacheKey == "" {
			continue
		}

		size, fresh, found := fs.folderSizeFromCache(cacheKey)
		if found {
			sz := size
			st.DirectorySize = &sz
		}
		if !found || !fresh {
			staleOrMissing = append(staleOrMissing, cacheKey)
		}
	}
	fs.scheduleDirectorySizeRefreshes(staleOrMissing)
}

const maxConcurrentDirectorySizeWalks = 3

func (fs *Filesystem) scheduleDirectorySizeRefreshes(keys []string) {
	if len(keys) == 0 || fs.diskCheckInterval == 0 {
		return
	}
	go func(keys []string) {
		ctx := context.Background()
		sem := semaphore.NewWeighted(maxConcurrentDirectorySizeWalks)
		for _, k := range keys {
			k := k
			if err := sem.Acquire(ctx, 1); err != nil {
				return
			}
			go func() {
				defer sem.Release(1)
				fs.refreshDirectoryContentsSize(k)
			}()
		}
	}(append([]string(nil), keys...))
}

func (fs *Filesystem) refreshDirectoryContentsSize(cacheKey string) {
	v, err, _ := fs.folderSizeGroup.Do(cacheKey, func() (interface{}, error) {
		p := pathForDirectorySize(cacheKey)
		size, walkErr := fs.DirectorySize(p)
		if walkErr != nil {
			log.WithField("path", p).WithField("error", walkErr).Debug("directory size walk failed")
			return nil, walkErr
		}
		fs.setFolderSizeCache(cacheKey, size)
		return size, nil
	})
	if err != nil || v == nil {
		return
	}
}
