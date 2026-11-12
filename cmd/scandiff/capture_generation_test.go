package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestReplayRequiresTheRunThatProducedIdenticalReports(t *testing.T) {
	dir := t.TempDir()
	targets := writeTargetsFile(t, []Target{{Name: "t", Ref: "ref-t", Trivy: &TrivyFloors{}}})
	live := []string{"-targets", targets, "-capture", dir, "-assay", "a", "-grype", "g", "-trivy", "y"}
	offline := func(want int, reason string) {
		t.Helper()
		var stderr bytes.Buffer
		if got := run([]string{"-targets", targets, "-offline", dir}, io.Discard, &stderr, noExec(t)); got != want || !strings.Contains(stderr.String(), reason) {
			t.Errorf("offline exit=%d stderr=%q, want %d %q", got, stderr.String(), want, reason)
		}
	}
	scanners := newFakeExecWithTrivy(t, map[string]stub{"ref-t": {out: assayDoc(0, nil)}},
		map[string]stub{"ref-t": {out: grypeDoc(nil)}}, map[string]stub{"ref-t": {out: trivyDocBytes(nil)}})
	if code := run(live, io.Discard, io.Discard, scanners); code != exitOK {
		t.Fatal("seed:", code)
	}
	offline(exitOK, "")

	prev := writeRunRecordFile
	t.Cleanup(func() { writeRunRecordFile = prev })
	writeRunRecordFile = func(path string, data []byte) error { return os.ErrPermission }
	during := func(bin string, args ...string) ([]byte, int, error) {
		switch bin {
		case "a":
			offline(exitError, "pending") // Interrupted before any scanner returned.
		case "y":
			offline(exitError, "different run") // Assay and Grype wrote identical bytes.
		}
		return scanners(bin, args...)
	}
	if code := run(live, io.Discard, io.Discard, during); code != exitOK {
		t.Fatal("second live run:", code)
	}
	offline(exitError, "different run")
	if err := os.Remove(runRecordPath(dir, "t")); err != nil {
		t.Fatal(err)
	}
	offline(exitError, "missing run record")

	writeRunRecordFile = prev
	if code := run(live, io.Discard, io.Discard, scanners); code != exitOK {
		t.Fatal("recovery:", code)
	}
	offline(exitOK, "")
	if err := os.Remove(statePath(dir, "t", "assay")); err != nil {
		t.Fatal(err)
	}
	offline(exitError, "no matching state")
}
