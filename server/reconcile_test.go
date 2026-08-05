package server

import (
	"testing"
	"time"

	. "github.com/franela/goblin"

	"github.com/mythicalltd/featherwings/environment"
)

func TestRuntimeReconciliationHelpers(t *testing.T) {
	g := Goblin(t)

	g.Describe("runtime tracker", func() {
		g.It("defaults to healthy ok status", func() {
			s := &Server{}
			info := s.Runtime()
			g.Assert(info.Status).Equal(RuntimeStatusOK)
			g.Assert(info.Healthy).IsTrue()
		})

		g.It("tracks unhealthy desync status", func() {
			s := &Server{}
			s.setRuntimeStatus(RuntimeStatusDesynced, "pid is 0")
			info := s.Runtime()
			g.Assert(info.Status).Equal(RuntimeStatusDesynced)
			g.Assert(info.Healthy).IsFalse()
			g.Assert(info.Message).Equal("pid is 0")
			g.Assert(info.CheckedAt > 0).IsTrue()
		})

		g.It("bumps and resets failure counts", func() {
			s := &Server{}
			g.Assert(s.bumpRuntimeFailure()).Equal(1)
			g.Assert(s.bumpRuntimeFailure()).Equal(2)
			s.resetRuntimeFailures()
			g.Assert(s.bumpRuntimeFailure()).Equal(1)
		})

		g.It("records state entered timestamps", func() {
			s := &Server{}
			before := time.Now().Add(-time.Second)
			s.noteStateEntered()
			entered := s.stateEnteredAt()
			g.Assert(entered.After(before)).IsTrue()
			g.Assert(entered.Before(time.Now().Add(time.Second))).IsTrue()
		})
	})

	g.Describe("process error state", func() {
		g.It("exposes error constant for runtime failures", func() {
			g.Assert(environment.ProcessErrorState).Equal("error")
		})
	})
}
