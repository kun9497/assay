package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Release check of main 60c512c: a per-target run record brackets every
// live run, and the replay reads it first.

// The record is written incomplete before the target's first scan -- the
// grype stub sees it so -- and complete, with both tools' outcomes and the
// captures' SHA-256, after the last; the replay then passes. The caller's
// test first: a record nobody wrote at the start would still read complete
// at the end.
func TestRun_RC4_ARunRecordBracketsEveryTarget(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t"}
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	grypeOut := grypeDoc(nil)
	var seen *runRecord
	exec := func(bin string, args ...string) ([]byte, int, error) {
		if args[0] == "scan" {
			return assayDoc(0, nil), 0, nil
		}
		rec, err := readRunRecord(dir, "t")
		if err != nil || rec == nil {
			t.Fatalf("during the grype scan: record=%v err=%v; want the incomplete record already on disk", rec, err)
		}
		seen = rec
		return grypeOut, 0, nil
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", dir}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("live: exit=%d stderr=%q", code, errOut.String())
	}
	if seen == nil || seen.Complete || seen.ID == "" {
		t.Errorf("record seen during the run: %+v; want incomplete with an id", seen)
	}
	rec, err := readRunRecord(dir, "t")
	if err != nil || rec == nil || !rec.Complete || rec.ID != seen.ID {
		t.Fatalf("record after the run: %+v err=%v; want complete, the same id %q", rec, err, seen.ID)
	}
	if st := rec.Tools["grype"]; st.Result != captureOK || st.SHA256 != sha256Hex(grypeOut) {
		t.Errorf("grype outcome in the record: %+v; want ok with the capture's sha256", st)
	}
	if st := rec.Tools["assay"]; st.Result != captureOK {
		t.Errorf("assay outcome in the record: %+v; want ok", st)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t)); code != exitOK {
		t.Errorf("offline: exit=%d stderr=%q; want 0", code, errOut.String())
	}
}

// A run interrupted after some of its captures were written -- killed
// while trivy ran -- leaves its record incomplete, and the directory is not
// replayable: the new assay and grype captures beside the earlier run's
// trivy capture had been judged together as a pass. The next run that
// finishes makes it replayable again.
func TestRun_RC4_InterruptedRunIsNotReplayable(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t", MinAgree: 1, MinFindings: 1, MaxFindings: 10, Trivy: &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 10}}
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	live := func(trivy stub) (int, string) {
		exec := newFakeExecWithTrivy(t, map[string]stub{"ref-t": {out: assayDoc(0, []assayFinding{{Package: assayPackage{Name: "x"}, Advisory: assayAdvisory{ID: "CVE-0000-0001"}}}), code: 0}},
			map[string]stub{"ref-t": {out: grypeDoc(nil), code: 0}}, map[string]stub{"ref-t": trivy})
		var out, errOut bytes.Buffer
		code := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-trivy", "y", "-capture", dir}, &out, &errOut, exec)
		return code, errOut.String()
	}
	offline := func() (int, string) {
		var out, errOut bytes.Buffer
		code := run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t))
		return code, errOut.String()
	}
	good := stub{out: trivyDocBytes([]trivyResult{{Vulnerabilities: []trivyVuln{{VulnerabilityID: "CVE-0000-0001", PkgName: "x"}}}}), code: 0}
	if code, stderr := live(good); code != exitOK {
		t.Fatalf("first run: exit=%d stderr=%q", code, stderr)
	}
	// The second run dies while trivy runs: its assay and grype captures
	// and states are on disk, its record is not complete.
	prev := writeRunRecordFile
	var records int
	writeRunRecordFile = func(path string, data []byte) error {
		records++
		if records == 2 {
			// The run never reached its end: the completing write does
			// not happen.
			return nil
		}
		return os.WriteFile(path, data, 0o644)
	}
	code, stderr := live(stub{out: []byte(`{"error":"killed"}`), code: 2})
	writeRunRecordFile = prev
	if records != 2 {
		t.Fatalf("record writes=%d, want 2 (start and end)", records)
	}
	if code != exitError {
		t.Fatalf("second run: exit=%d stderr=%q; want 2 (trivy failed)", code, stderr)
	}
	if code, stderr := offline(); code != exitError || !strings.Contains(stderr, "did not complete") {
		t.Errorf("replay of the interrupted directory: exit=%d stderr=%q; want 2 and the incomplete run named", code, stderr)
	}
	if code, stderr := live(good); code != exitOK {
		t.Fatalf("third run: exit=%d stderr=%q", code, stderr)
	}
	if code, stderr := offline(); code != exitOK {
		t.Errorf("replay after a finished run: exit=%d stderr=%q; want 0", code, stderr)
	}
}

// A failed run whose state file could not be written (held open on Windows,
// with the earlier success capture it could not remove either) leaves the
// earlier run's `ok` state beside its own marker; the record says the run
// failed, and the replay fails as the run did. A marker beside a capture
// the record calls ok -- one the run could not remove -- is not trusted
// either.
func TestRun_RC4_ARecordOutlivesAStateFileTheRunCouldNotWrite(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t"}
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	live := func(grype stub) (int, string) {
		exec := newFakeExec(t, map[string]stub{"ref-t": {out: assayDoc(0, nil), code: 0}}, map[string]stub{"ref-t": grype})
		var out, errOut bytes.Buffer
		code := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", dir}, &out, &errOut, exec)
		return code, errOut.String()
	}
	offline := func() (int, string) {
		var out, errOut bytes.Buffer
		code := run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t))
		return code, errOut.String()
	}
	if code, stderr := live(stub{out: grypeDoc(nil), code: 0}); code != exitOK {
		t.Fatalf("seed: exit=%d stderr=%q", code, stderr)
	}
	good := filepath.Join(dir, "t.grype.json")
	earlier, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	prev := writeStateFile
	writeStateFile = func(path string, data []byte) error {
		if filepath.Base(path) == "t.grype.state.json" {
			return os.ErrPermission
		}
		return os.WriteFile(path, data, 0o644)
	}
	code, stderr := live(stub{out: []byte(`{"error":"scan failed"}`), code: 2})
	writeStateFile = prev
	if code != exitError || !strings.Contains(stderr, "warning: write capture state") {
		t.Fatalf("failed run with the state held: exit=%d stderr=%q; want 2 with the state warning", code, stderr)
	}
	// The success capture the run could not remove is back under the good
	// name, the earlier state beside it saying ok with its sha256.
	if err := os.WriteFile(good, earlier, 0o644); err != nil {
		t.Fatal(err)
	}
	if st, _ := readState(dir, "t", "grype"); st == nil || st.Result != captureOK || st.SHA256 != sha256Hex(earlier) {
		t.Fatalf("state after the failed run: %+v; the test needs the earlier ok state in place", st)
	}
	if code, stderr := offline(); code != exitError || !strings.Contains(stderr, "the last run failed") {
		t.Errorf("replay: exit=%d stderr=%q; want 2, the failed run named", code, stderr)
	}
	// Recovery removes the marker; a marker nobody removed beside an ok
	// capture is refused until a reader removes it.
	if code, stderr := live(stub{out: grypeDoc(nil), code: 0}); code != exitOK {
		t.Fatalf("recovery: exit=%d stderr=%q", code, stderr)
	}
	if code, stderr := offline(); code != exitOK {
		t.Errorf("replay after recovery: exit=%d stderr=%q; want 0", code, stderr)
	}
	marker := filepath.Join(dir, "t.grype.failed.json")
	if err := os.WriteFile(marker, []byte(`{"error":"an older failure nobody removed"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stderr := offline(); code != exitError || !strings.Contains(stderr, "could not remove") {
		t.Errorf("replay beside a stray marker: exit=%d stderr=%q; want 2, the marker named", code, stderr)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if code, stderr := offline(); code != exitOK {
		t.Errorf("replay with the marker removed: exit=%d stderr=%q; want 0", code, stderr)
	}
}

// A capture from before the record (no <name>.run.json, the weekly archive's
// shape) replays by its state files, or with none; a record that does not
// parse is an error, not a silent fallback.
func TestRun_RC4_ACaptureWithoutARecordReplaysAsBefore(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t"}
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	for name, body := range map[string][]byte{"t.assay.json": assayDoc(0, nil), "t.grype.json": grypeDoc(nil)} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t)); code != exitOK {
		t.Errorf("no record, no state: exit=%d stderr=%q; want 0", code, errOut.String())
	}
	if err := os.WriteFile(runRecordPath(dir, "t"), []byte(`{"id":`), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t)); code != exitError || !strings.Contains(errOut.String(), "read offline run record") {
		t.Errorf("unreadable record: exit=%d stderr=%q; want 2 and the record named", code, errOut.String())
	}
	raw, _ := json.Marshal(runRecord{ID: "x", Complete: true, Tools: map[string]captureState{"assay": {Result: captureOK, SHA256: sha256Hex(assayDoc(0, nil))}}})
	if err := os.WriteFile(runRecordPath(dir, "t"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t)); code != exitError || !strings.Contains(errOut.String(), "recorded no grype scan") {
		t.Errorf("record without the grype outcome: exit=%d stderr=%q; want 2 and the missing scan named", code, errOut.String())
	}
}
