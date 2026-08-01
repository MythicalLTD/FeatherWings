package backup

import (
	"math"
	"testing"
)

func TestParseHumanBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"159 B", 159, true},
		{"78.847 MiB", int64(math.Round(78.847 * 1024 * 1024)), true},
		{"10.943 GiB", int64(math.Round(10.943 * 1024 * 1024 * 1024)), true},
		{"6.68 MiB", int64(math.Round(6.68 * 1024 * 1024)), true},
		{"1 KiB", 1024, true},
		{"", 0, false},
		{"not-a-size", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseHumanBytes(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("parseHumanBytes(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseSizeFromBackupOutput(t *testing.T) {
	out := `
Starting backup: ct/76b77ae4-562b-404d-8130-e333b491df32/2026-07-28T13:09:39Z
Upload directory '/srv/data' to 'pbs:store' as server.pxar.didx
server.pxar: had to backup 78.847 MiB of 512.5 MiB (compressed 6.68 MiB) in 0.66s
server.pxar: average backup speed: 119.457 MiB/s
Uploaded backup catalog (45.525 KiB)
Duration: 0.79s
End Time: Thu Jan 11 12:01:56 2024
`
	got, ok := parseSizeFromBackupOutput(out)
	if !ok {
		t.Fatal("expected size parse to succeed")
	}
	want, _ := parseHumanBytes("512.5 MiB")
	if got != want {
		t.Fatalf("got %d, want logical size %d", got, want)
	}
}

func TestParseSizeFromBackupOutputCompressedOnlyFormat(t *testing.T) {
	out := `root.pxar: had to backup 4 MiB of 10.943 GiB (159 B compressed) in 49.30 s (average 83.09 KiB/s)`
	got, ok := parseSizeFromBackupOutput(out)
	if !ok {
		t.Fatal("expected size parse to succeed")
	}
	want, _ := parseHumanBytes("10.943 GiB")
	if got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

func TestParseSizeFromBackupOutputEmpty(t *testing.T) {
	if _, ok := parseSizeFromBackupOutput("no stats here\n"); ok {
		t.Fatal("expected parse to fail")
	}
}

func TestParseSnapshotFromBackupOutput(t *testing.T) {
	uuid := "76b77ae4-562b-404d-8130-e333b491df32"
	out := "Starting backup: ct/" + uuid + "/2026-07-28T13:09:39Z\n"
	got := parseSnapshotFromBackupOutput(out, uuid)
	want := "ct/" + uuid + "/2026-07-28T13:09:39Z"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPbsArchiveCandidates(t *testing.T) {
	got := pbsArchiveCandidates("")
	if got[0] != "root.pxar" {
		t.Fatalf("default candidate = %q, want root.pxar", got[0])
	}
	if len(got) < 2 || got[1] != "server.pxar" {
		t.Fatalf("expected legacy server.pxar fallback, got %#v", got)
	}

	got = pbsArchiveCandidates("server.pxar")
	if got[0] != "server.pxar" {
		t.Fatalf("configured name should be first, got %#v", got)
	}
}
