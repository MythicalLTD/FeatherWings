package operations

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
)

func TestManagerPublishesCalagopusEventArguments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var events [][]string
	manager := NewManager(ctx, func(event string, args ...string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, append([]string{event}, args...))
	})

	total := &atomic.Uint64{}
	total.Store(100)
	processed := &atomic.Uint64{}
	processed.Store(25)
	id, _ := manager.Add(Operation{
		Type:           "compress",
		Path:           "/root",
		BytesProcessed: processed,
		BytesTotal:     total,
	})

	if !manager.Complete(id) {
		t.Fatal("expected operation to complete")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("expected initial progress, final progress, and completion; got %d events", len(events))
	}
	if len(events[0]) != 3 || events[0][0] != ProgressEvent || events[0][1] != id.String() {
		t.Fatalf("unexpected progress arguments: %#v", events[0])
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(events[0][2]), &payload); err != nil {
		t.Fatalf("invalid progress JSON: %v", err)
	}
	if payload["bytes_processed"] != float64(25) || payload["bytes_total"] != float64(100) {
		t.Fatalf("unexpected progress counters: %#v", payload)
	}
	if len(events[2]) != 2 || events[2][0] != CompletedEvent || events[2][1] != id.String() {
		t.Fatalf("unexpected completion arguments: %#v", events[2])
	}
}

func TestManagerAbortCancelsOperationContext(t *testing.T) {
	manager := NewManager(context.Background(), nil)
	id, _ := manager.Add(Operation{Type: "decompress"})
	ctx, ok := manager.Context(id)
	if !ok {
		t.Fatal("expected operation context")
	}

	if !manager.Abort(id) {
		t.Fatal("expected registered operation to be abortable")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected abort to cancel operation context")
	}
}
