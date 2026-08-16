package diff

import (
	"bytes"
	"database/sql"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/zeebo/blake3"

	"github.com/mythicalltd/featherwings/config"
)

// Manager owns the revision database for one server.
type Manager struct {
	serverUUID string
	log        *log.Entry

	mu      sync.Mutex
	storage *storage
	closed  bool
}

func NewManager(serverUUID string, logger *log.Entry) *Manager {
	return &Manager{serverUUID: serverUUID, log: logger}
}

// NormalizePath returns the slash-free path key shared with collaborative editing.
func NormalizePath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.TrimLeft(p, "/")
	p = path.Clean("/" + p)
	p = strings.TrimLeft(p, "/")
	if p == "." {
		return ""
	}
	return p
}

func (m *Manager) Enabled() bool {
	return config.Get().System.FileHistory.Enabled
}

func (m *Manager) FileSizeCap() uint64 {
	return config.Get().System.FileHistory.FileSizeCap
}

func (m *Manager) open() (*storage, error) {
	if m.storage != nil {
		return m.storage, nil
	}
	if m.closed {
		return nil, os.ErrClosed
	}

	cfg := config.Get()
	if err := os.MkdirAll(cfg.System.DiffsDirectory, 0o700); err != nil {
		return nil, err
	}
	databasePath := filepath.Join(cfg.System.DiffsDirectory, filepath.Base(m.serverUUID)+".db")
	store, err := openStorage(databasePath, cfg.System.FileHistory.ZstdLevel)
	if err != nil {
		return nil, err
	}
	m.storage = store
	return store, nil
}

// RecordEdit stores the successfully written content as a compressed snapshot.
func (m *Manager) RecordEdit(filePath string, before, after []byte, userUUID string) (int64, error) {
	if !m.Enabled() || uint64(len(after)) > m.FileSizeCap() ||
		(before != nil && uint64(len(before)) > m.FileSizeCap()) {
		return 0, nil
	}
	key := NormalizePath(filePath)
	if key == "" {
		return 0, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return 0, err
	}

	hash := blake3.Sum256(after)
	latestID, latestHash, latestErr := store.latestRevision(key)
	if latestErr == nil && bytes.Equal(latestHash, hash[:]) {
		return latestID, nil
	} else if latestErr != nil && !isNotFound(latestErr) {
		return 0, latestErr
	}

	cfg := config.Get().System.FileHistory
	if cfg.KeepChains == 0 {
		cfg.KeepChains = 1
	}
	if isNotFound(latestErr) && before != nil && !bytes.Equal(before, after) {
		if _, err := store.insertSnapshot(key, before, "", cfg.KeepChains, cfg.PerFileDiskBudget, cfg.PerServerDiskBudget); err != nil {
			return 0, err
		}
	}
	revisionID, err := store.insertSnapshot(key, after, userUUID, cfg.KeepChains, cfg.PerFileDiskBudget, cfg.PerServerDiskBudget)
	if err != nil {
		return 0, err
	}
	return revisionID, nil
}

func (m *Manager) List(filePath string) ([]RevisionInfo, error) {
	if !m.Enabled() {
		return []RevisionInfo{}, nil
	}
	key := NormalizePath(filePath)
	if key == "" {
		return []RevisionInfo{}, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return nil, err
	}
	return store.list(key)
}

func (m *Manager) GetContent(revisionID int64) ([]byte, error) {
	if !m.Enabled() {
		return nil, sql.ErrNoRows
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return nil, err
	}
	return store.reconstruct(revisionID)
}

func (m *Manager) RevisionPath(revisionID int64) (string, bool, error) {
	if !m.Enabled() {
		return "", false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return "", false, err
	}
	filePath, err := store.revisionPath(revisionID)
	if isNotFound(err) {
		return "", false, nil
	}
	return filePath, err == nil, err
}

func (m *Manager) ForgetFile(filePath string) error {
	if !m.Enabled() {
		return nil
	}
	key := NormalizePath(filePath)
	if key == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return err
	}
	return store.deleteFile(key)
}

func (m *Manager) RenameFile(oldPath, newPath string) error {
	if !m.Enabled() {
		return nil
	}
	oldKey, newKey := NormalizePath(oldPath), NormalizePath(newPath)
	if oldKey == "" || newKey == "" || oldKey == newKey {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return err
	}
	return store.renameFile(oldKey, newKey)
}

func (m *Manager) Clear() error {
	if !m.Enabled() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	store, err := m.open()
	if err != nil {
		return err
	}
	if err := store.clear(); err != nil {
		return err
	}
	return store.vacuum()
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.storage == nil {
		return nil
	}
	err := m.storage.close()
	m.storage = nil
	if err != nil && m.log != nil {
		m.log.WithError(err).Warn("failed to close file history database")
	}
	return err
}
