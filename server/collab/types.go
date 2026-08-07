package collab

import (
	"encoding/json"
	"errors"
)

// Outbound message events (Calagopus-compatible names).
const (
	EventSync         = "file collab sync"
	EventUpdate       = "file collab update"
	EventAwareness    = "file collab awareness"
	EventParticipants = "file collab participants"
	EventSaved        = "file collab saved"
	EventConflict     = "file collab conflict"
	EventError        = "file collab error"
)

// Inbound message events.
const (
	EventSubscribe   = "file collab subscribe"
	EventUnsubscribe = "file collab unsubscribe"
	EventUpdateIn    = "file collab update"
	EventAwarenessIn = "file collab awareness"
	EventSave        = "file collab save"
	EventReload      = "file collab reload"
)

// Permission strings expected on the websocket JWT.
const (
	PermissionReadContent = "file.read-content"
	PermissionUpdate      = "file.update"
)

var (
	ErrDisabled          = errors.New("collaborative editing is disabled")
	ErrNotSubscribed     = errors.New("not subscribed to this file")
	ErrFileNotFound      = errors.New("file not found")
	ErrNotAFile          = errors.New("file is not a file")
	ErrNotEditable       = errors.New("file is not editable as text")
	ErrTooLarge          = errors.New("file is too large for collaborative editing")
	ErrInvalidUpdate     = errors.New("invalid update encoding")
	ErrTooManySessions   = errors.New("too many collaborative sessions open on this server")
	ErrTooManyConnSubs   = errors.New("too many collaborative sessions open on this connection")
	ErrTooManyEditors    = errors.New("too many editors open for this file on this connection")
	ErrEditorIDTooLong   = errors.New("editor id is too long")
	ErrNoParent          = errors.New("file has no parent")
	ErrInvalidFileName   = errors.New("invalid file name")
	ErrAllocateSpace     = errors.New("failed to allocate space")
	ErrMissingPermission = errors.New("missing permission")
)

const maxEditorIDLen = 64

// Message is a websocket payload delivered to a specific connection.
type Message struct {
	Event string
	Args  []string
}

// Sender delivers a collab message to one websocket connection.
type Sender func(Message)

// Participant is someone currently editing a file.
type Participant struct {
	User   string  `json:"user"`
	Name   string  `json:"name"`
	Avatar *string `json:"avatar"`
}

// Conflict describes an on-disk conflict for a collab session.
type Conflict struct {
	Hash    *string `json:"hash"`
	Deleted bool    `json:"deleted"`
}

// SyncMeta is attached to a sync payload.
type SyncMeta struct {
	Dirty    bool      `json:"dirty"`
	Conflict *Conflict `json:"conflict"`
}

// Saved notifies clients that a collaborative save completed.
type Saved struct {
	User       string `json:"user"`
	RevisionID *int64 `json:"revision_id"`
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}
