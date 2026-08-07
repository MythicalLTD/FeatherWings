package collab

import (
	"encoding/base64"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/zeebo/blake3"
)

type sessionParticipant struct {
	UserUUID string
	UserName string
	Avatar   *string
}

type conflictState struct {
	Hash    *[32]byte
	Deleted bool
}

func (c conflictState) toConflict() Conflict {
	out := Conflict{Deleted: c.Deleted}
	if c.Hash != nil {
		h := hex.EncodeToString(c.Hash[:])
		out.Hash = &h
	}
	return out
}

type session struct {
	key           string
	path          string
	doc           *collabDoc
	dirty         atomic.Bool
	conflict      sync.Mutex
	conflictState *conflictState

	participantsMu sync.Mutex
	participants   map[uuid.UUID]sessionParticipant

	awarenessMu sync.Mutex
	awareness   map[uuid.UUID]map[uint64]uint64

	saveMu sync.Mutex
}

func newSession(key, path, content string) *session {
	return &session{
		key:          key,
		path:         path,
		doc:          newCollabDoc(content),
		participants: make(map[uuid.UUID]sessionParticipant),
		awareness:    make(map[uuid.UUID]map[uint64]uint64),
	}
}

func (s *session) setConflict(state *conflictState) bool {
	s.conflict.Lock()
	defer s.conflict.Unlock()
	if equalConflict(s.conflictState, state) {
		return false
	}
	s.conflictState = state
	return true
}

func (s *session) currentConflict() *conflictState {
	s.conflict.Lock()
	defer s.conflict.Unlock()
	return s.conflictState
}

func equalConflict(a, b *conflictState) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Deleted != b.Deleted {
		return false
	}
	if (a.Hash == nil) != (b.Hash == nil) {
		return false
	}
	if a.Hash != nil && *a.Hash != *b.Hash {
		return false
	}
	return true
}

func (s *session) trackAwareness(connectionID uuid.UUID, entries []awarenessEntry, maxCursors int) {
	s.awarenessMu.Lock()
	defer s.awarenessMu.Unlock()
	clients := s.awareness[connectionID]
	if clients == nil {
		clients = make(map[uint64]uint64)
		s.awareness[connectionID] = clients
	}
	trackAwarenessClients(clients, entries, maxCursors)
	if len(clients) == 0 {
		delete(s.awareness, connectionID)
	}
}

func (s *session) awarenessRemovalMessage(connectionID uuid.UUID) *Message {
	s.awarenessMu.Lock()
	clients := s.awareness[connectionID]
	delete(s.awareness, connectionID)
	s.awarenessMu.Unlock()
	if len(clients) == 0 {
		return nil
	}
	return &Message{
		Event: EventAwareness,
		Args: []string{
			s.key,
			base64.StdEncoding.EncodeToString(encodeAwarenessRemoval(clients)),
		},
	}
}

func (s *session) participantsMessage() Message {
	s.participantsMu.Lock()
	defer s.participantsMu.Unlock()

	seen := make(map[string]struct{})
	list := make([]Participant, 0, len(s.participants))
	for _, p := range s.participants {
		if _, ok := seen[p.UserUUID]; ok {
			continue
		}
		seen[p.UserUUID] = struct{}{}
		list = append(list, Participant{
			User:   p.UserUUID,
			Name:   p.UserName,
			Avatar: p.Avatar,
		})
	}
	return Message{
		Event: EventParticipants,
		Args:  []string{s.key, mustJSON(list)},
	}
}

func (s *session) conflictMessage(state *conflictState) Message {
	var payload any
	if state == nil {
		payload = nil
	} else {
		c := state.toConflict()
		payload = c
	}
	return Message{
		Event: EventConflict,
		Args:  []string{s.key, mustJSON(payload)},
	}
}

func contentHash(content string) [32]byte {
	return blake3.Sum256([]byte(content))
}
