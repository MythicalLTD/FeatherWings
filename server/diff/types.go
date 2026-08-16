package diff

import "time"

// RevisionInfo is the Calagopus-compatible representation of a file revision.
type RevisionInfo struct {
	ID         int64     `json:"id"`
	Size       int64     `json:"size"`
	StoredSize int64     `json:"stored_size"`
	User       *string   `json:"user,omitempty"`
	IsSnapshot bool      `json:"is_snapshot"`
	Created    time.Time `json:"created"`
}
