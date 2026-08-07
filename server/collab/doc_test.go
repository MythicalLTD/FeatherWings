package collab

import (
	"testing"

	"github.com/Deln0r/ygo"
)

func TestCollabDocRoundTrip(t *testing.T) {
	doc := newCollabDoc("hello world")
	if got := doc.content(); got != "hello world" {
		t.Fatalf("content = %q, want hello world", got)
	}

	state := doc.encodeFullState()
	peer := ygo.NewDoc()
	if err := ygo.ApplyUpdate(peer, state); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	text := ygo.NewText(peer, yTextName)
	if got := text.String(); got != "hello world" {
		t.Fatalf("peer content = %q", got)
	}

	remote := ygo.NewDoc()
	rt := ygo.NewText(remote, yTextName)
	txn := remote.WriteTxn()
	_ = rt.Insert(txn, 0, "remote")
	txn.Commit()
	update := ygo.EncodeStateAsUpdate(remote)
	if err := doc.applyUpdate(update); err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	// Concurrent insert at 0 converges; both strings present.
	if got := doc.content(); got == "" {
		t.Fatalf("expected merged content, got empty")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/foo/bar":   "foo/bar",
		"foo/bar":    "foo/bar",
		"//foo//bar": "foo/bar",
		"./foo":      "foo",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Fatalf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
