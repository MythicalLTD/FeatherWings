
package system

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// Mirrors router/websocket/listeners.go eventChan = make(chan []byte) under a slow
// WriteJSON-like consumer. Documents intermittent status/console WS loss.
func TestUnbufferedEventChanDropsUnderSlowConsumer(t *testing.T) {
	pool := NewSinkPool()
	eventChan := make(chan []byte) // production WS listener shape
	pool.On(eventChan)

	var received, published atomic.Uint64
	done := make(chan struct{})
	go func() {
		for range eventChan {
			received.Add(1)
			time.Sleep(20 * time.Millisecond) // slow send
		}
		close(done)
	}()

	for i := 0; i < 40; i++ {
		published.Add(1)
		pool.Push([]byte(fmt.Sprintf("status-%d", i)))
	}
	time.Sleep(1500 * time.Millisecond)
	pool.Off(eventChan)
	<-done

	dropped := published.Load() - received.Load()
	t.Logf("published=%d received=%d dropped=%d", published.Load(), received.Load(), dropped)
	if dropped == 0 {
		t.Fatal("expected unbuffered sink to drop under slow consumer (hypothesis B)")
	}

	// Buffered listener (recommended by SinkPool docs) should not drop the same burst.
	pool2 := NewSinkPool()
	buf := make(chan []byte, 64)
	pool2.On(buf)
	var got atomic.Uint64
	done2 := make(chan struct{})
	go func() {
		for range buf {
			got.Add(1)
			time.Sleep(20 * time.Millisecond)
		}
		close(done2)
	}()
	for i := 0; i < 40; i++ {
		pool2.Push([]byte(fmt.Sprintf("status-%d", i)))
	}
	time.Sleep(1500 * time.Millisecond)
	pool2.Off(buf)
	<-done2
	if got.Load() != 40 {
		t.Fatalf("buffered sink expected 40 got %d", got.Load())
	}
}
