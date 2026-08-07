package server

import (
	"context"
	"sync"

	"github.com/apex/log"
	"github.com/google/uuid"

	"github.com/mythicalltd/featherwings/server/collab"
)

// Collab returns the collaborative editing manager for this server.
func (s *Server) Collab() *collab.Manager {
	s.collabOnce.Do(func() {
		s.collab = collab.NewManager(s.ID(), s.Filesystem(), s.Context(), log.WithField("server", s.ID()).WithField("subsystem", "collab"))
	})
	return s.collab
}

type WebsocketBag struct {
	mu    sync.Mutex
	conns map[uuid.UUID]*context.CancelFunc
}

// Websockets returns the websocket bag which contains all the currently open websocket connections
// for the server instance.
func (s *Server) Websockets() *WebsocketBag {
	s.wsBagLocker.Lock()
	defer s.wsBagLocker.Unlock()

	if s.wsBag == nil {
		s.wsBag = &WebsocketBag{}
	}

	return s.wsBag
}

func (w *WebsocketBag) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.conns)
}

// Push adds a new websocket connection to the end of the stack.
func (w *WebsocketBag) Push(u uuid.UUID, cancel *context.CancelFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conns == nil {
		w.conns = make(map[uuid.UUID]*context.CancelFunc)
	}

	w.conns[u] = cancel
}

// Remove removes a connection from the stack.
func (w *WebsocketBag) Remove(u uuid.UUID) {
	w.mu.Lock()
	delete(w.conns, u)
	w.mu.Unlock()
}

// CancelAll cancels all the stored cancel functions which has the effect of
// disconnecting every listening websocket for the server.
func (w *WebsocketBag) CancelAll() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conns != nil {
		for _, cancel := range w.conns {
			(*cancel)()
		}
	}

	// Reset the connections.
	w.conns = make(map[uuid.UUID]*context.CancelFunc)
}
