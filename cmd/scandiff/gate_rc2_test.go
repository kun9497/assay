package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Release check 2026-11-11 (main 5197df4), section 4: the gate edges left
// after #281.

// grype's diagnostic object may carry `"matches": null`: not a report, live
// (with its exit 2, the hard failure) or offline. An empty array is a valid
// report of nothing.
func TestRun_RC2_GrypeNullMatchesIsNotAReport(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t", MinAgree: 1}
	code, stderr, captured, dir := rcRunLive(t, target, stub{out: assayDoc(0, nil), code: 0}, stub{out: []byte(`{"error":"scan failed","matches":null}`), code: 2})
	if code != exitError || !strings.Contains(stderr, "grype hard failure (exit 2)") || strings.Join(captured, ",") != "t.assay.json,t.assay.state.json,t.grype.failed.json,t.grype.state.json" {
		t.Errorf("live: exit=%d stderr=%q captured=%v; want 2, a hard failure, the capture filed as failed", code, stderr, captured)
	}
	// Replayed, that directory is the failed run's: the state says so.
	code, stderr = rcRunOffline(t, target, dir, nil)
	if code != exitError || !strings.Contains(stderr, "the last run failed") {
		t.Errorf("offline on the failed run's directory: exit=%d stderr=%q; want 2, the failed run named", code, stderr)
	}
	// The diagnostic object under the good name in a directory of its own
	// (an older tool's filing, no state) is malformed by shape.
	code, stderr = rcRunOffline(t, target, t.TempDir(), map[string][]byte{"t.assay.json": assayDoc(0, nil), "t.grype.json": []byte(`{"error":"scan failed","matches":null}`)})
	if code != exitError || !strings.Contains(stderr, `"matches" is not an array`) {
		t.Errorf("offline shape: exit=%d stderr=%q; want 2 and the shape named", code, stderr)
	}
	code, stderr, _, _ = rcRunLive(t, Target{Name: "t", Ref: "ref-t"}, stub{out: assayDoc(0, nil), code: 0}, stub{out: []byte(`{"matches":[]}`), code: 0})
	if code != exitOK {
		t.Errorf("empty array: exit=%d stderr=%q; want 0", code, stderr)
	}
}

// A success capture that a failed run could not remove (a reader held it
// open; Windows refuses the remove) is outlived by the failed run's marker,
// and the replay fails as that run did. The next successful run removes the
// marker and the replay is clean again. The sequence the QA built: success,
// failure under a lock, replay, unlock, replay, recovery, replay.
func TestRun_RC2_FailedRunOutlivesALockedSuccessCapture(t *testing.T) {
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
	good := stub{out: grypeDoc(nil), code: 0}
	bad := stub{out: []byte(`{"error":"scan failed"}`), code: 2}
	if code, stderr := live(good); code != exitOK {
		t.Fatalf("initial: exit=%d stderr=%q", code, stderr)
	}
	// Hold the success capture open through the failed run. On Windows the
	// remove fails and the file stays; elsewhere it is removed -- the
	// marker decides the replay either way.
	h, err := os.Open(filepath.Join(dir, "t.grype.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The marker must not sort older than the capture on a coarse clock.
	time.Sleep(20 * time.Millisecond)
	code, stderr := live(bad)
	h.Close()
	if code != exitError {
		t.Fatalf("failed run: exit=%d stderr=%q; want 2", code, stderr)
	}
	if code, stderr := offline(); code != exitError || !strings.Contains(stderr, "the last run failed") && !strings.Contains(stderr, "read offline grype capture") {
		t.Errorf("replay after the failed run: exit=%d stderr=%q; want 2, the failed run named", code, stderr)
	}
	// Unlocked, the replay still reflects the failed run.
	if code, stderr := offline(); code != exitError {
		t.Errorf("replay after unlock: exit=%d stderr=%q; want 2", code, stderr)
	}
	time.Sleep(20 * time.Millisecond)
	if code, stderr := live(good); code != exitOK {
		t.Fatalf("recovery: exit=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "t.grype.failed.json")); !os.IsNotExist(err) {
		t.Errorf("the failed marker survived the recovery: %v", err)
	}
	if code, stderr := offline(); code != exitOK {
		t.Errorf("replay after recovery: exit=%d stderr=%q; want 0", code, stderr)
	}
	// The files' times decide nothing: the state file does. Touched to an
	// hour ago, the replay is still clean; with the state removed and a
	// stray marker beside the capture, the replay refuses to guess.
	old := time.Now().Add(-time.Hour)
	for _, n := range []string{"t.grype.json", "t.grype.state.json"} {
		if err := os.Chtimes(filepath.Join(dir, n), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if code, stderr := offline(); code != exitOK {
		t.Errorf("replay with old times: exit=%d stderr=%q; want 0", code, stderr)
	}
	if err := os.WriteFile(filepath.Join(dir, "t.grype.failed.json"), []byte(`{"error":"stray"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "t.grype.state.json"))
	if code, stderr := offline(); code != exitError || !strings.Contains(stderr, "no state file") {
		t.Errorf("replay with a stray marker and no state: exit=%d stderr=%q; want 2", code, stderr)
	}
}

// An assay capture stripped of its provenance still names its image in the
// report's top-level `image` record: a digest of another image under the
// pinned ref is refused; the pinned digest there is accepted.
func TestRun_RC2_TopLevelImageDigestIdentifiesACapture(t *testing.T) {
	assayWith := func(image string) []byte {
		return []byte(`{"schemaVersion":22,"findings":[],"summary":{"components":5},"image":` + image + `}`)
	}
	pinned := Target{Name: "t", Ref: rcPinned, MinComponents: 1}
	grype := []byte(`{"matches":[],"source":{"type":"image","target":{"userInput":"` + rcPinned + `"}}}`)
	for _, tc := range []struct {
		name  string
		image string
		code  int
		want  string
	}{
		{"another image's index digest", `{"platform":"linux/amd64","manifestDigest":"sha256:aaaa","indexDigest":"` + rcOther + `"}`, exitError, "offline assay capture records no target and its image digests"},
		{"the pinned index digest", `{"platform":"linux/amd64","manifestDigest":"sha256:aaaa","indexDigest":"` + rcDigest + `"}`, exitOK, ""},
		{"the pinned manifest digest", `{"platform":"linux/amd64","manifestDigest":"` + rcDigest + `"}`, exitOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := rcRunOffline(t, pinned, t.TempDir(), map[string][]byte{"t.assay.json": assayWith(tc.image), "t.grype.json": grype})
			if code != tc.code || (tc.want != "" && !strings.Contains(stderr, tc.want)) || (tc.want == "" && strings.Contains(stderr, "error:")) {
				t.Errorf("exit=%d stderr=%q; want %d %q", code, stderr, tc.code, tc.want)
			}
		})
	}
}

// trivy's diagnostic object with exit 2 is a scanner error on a committed
// floor (ERROR, exit 2 -- not a breach of the floor) and a failed
// measurement on an informational block (a warning, no numbers to paste),
// live and offline.
func TestRun_RC2_TrivyDiagnosticJSONIsNotAMeasurement(t *testing.T) {
	diag := stub{out: []byte(`{"error":"scan failed"}`), code: 2}
	for _, tc := range []struct {
		name    string
		floors  *TrivyFloors
		code    int
		want    string
		wantNot string
		offline int
		offWant string
		offNot  string
	}{
		{"committed floor", &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 100}, exitError, "trivy hard failure (exit 2)", "breach:", exitError, `malformed trivy JSON: no "SchemaVersion" field`, "breach:"},
		{"informational", &TrivyFloors{}, exitOK, "measurement failed", "trivy measured", exitOK, "measurement failed", "trivy measured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := Target{Name: "t", Ref: "ref-t", Trivy: tc.floors}
			targetsPath := writeTargetsFile(t, []Target{target})
			dir := t.TempDir()
			exec := newFakeExecWithTrivy(t, map[string]stub{"ref-t": {out: assayDoc(0, nil), code: 0}}, map[string]stub{"ref-t": {out: grypeDoc(nil), code: 0}}, map[string]stub{"ref-t": diag})
			var out, errOut bytes.Buffer
			code := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-trivy", "tv", "-capture", dir}, &out, &errOut, exec)
			if code != tc.code || !strings.Contains(errOut.String(), tc.want) || strings.Contains(errOut.String(), tc.wantNot) {
				t.Errorf("live: exit=%d stderr=%q stdout=%q; want %d, %q, not %q", code, errOut.String(), out.String(), tc.code, tc.want, tc.wantNot)
			}
			// Offline on a diagnostic capture under the good name (as an
			// older tool would have filed it), in a directory of its own.
			dir = t.TempDir()
			for n, b := range map[string][]byte{"t.assay.json": assayDoc(0, nil), "t.grype.json": grypeDoc(nil), "t.trivy.json": diag.out} {
				if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out.Reset()
			errOut.Reset()
			code = run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t))
			if code != tc.offline || !strings.Contains(errOut.String(), tc.offWant) || strings.Contains(errOut.String(), tc.offNot) {
				t.Errorf("offline: exit=%d stderr=%q stdout=%q; want %d, %q, not %q", code, errOut.String(), out.String(), tc.offline, tc.offWant, tc.offNot)
			}
		})
	}
}
