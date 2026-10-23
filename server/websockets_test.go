package server

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestWebsocketBagCancelUserOnlyDisconnectsThatUser(t *testing.T) {
	var bag WebsocketBag
	cancelled := map[string]bool{}
	push := func(name, user string) {
		cancel := context.CancelFunc(func() { cancelled[name] = true })
		bag.Push(uuid.New(), &cancel, func() string { return user })
	}
	push("alice-1", "alice")
	push("alice-2", "alice")
	push("bob", "bob")
	anonymous := context.CancelFunc(func() { cancelled["anonymous"] = true })
	bag.Push(uuid.New(), &anonymous, nil)

	bag.CancelUser("alice")

	if !cancelled["alice-1"] || !cancelled["alice-2"] {
		t.Fatalf("expected both of alice's connections to be cancelled, got %v", cancelled)
	}
	if cancelled["bob"] || cancelled["anonymous"] {
		t.Fatalf("expected other connections to stay open, got %v", cancelled)
	}
	if got := bag.Len(); got != 2 {
		t.Fatalf("expected 2 remaining connections, got %d", got)
	}
}
