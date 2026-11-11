package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Release check 2026-11-11 (main 42b0c09), the gate items: a comparison
// scanner's failure re-judged as success, and an offline capture identified
// by its digests when its argument is gone.

const (
	rcPinned = "registry.suse.com/bci/bci-base@sha256:c4bd6f1a43a3d80e9345e75a0e115e9a34daee55120ad4ba2f14d71bd29ba1eb"
	rcDigest = "sha256:c4bd6f1a43a3d80e9345e75a0e115e9a34daee55120ad4ba2f14d71bd29ba1eb"
	rcOther  = "sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
)

func rcRunLive(t *testing.T, target Target, assay, grype stub) (code int, stderr string, captured []string, dir string) {
	t.Helper()
	targetsPath := writeTargetsFile(t, []Target{target})
	dir = t.TempDir()
	exec := newFakeExec(t, map[string]stub{target.Ref: assay}, map[string]stub{target.Ref: grype})
	var out, errOut bytes.Buffer
	code = run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", dir}, &out, &errOut, exec)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		captured = append(captured, e.Name())
	}
	return code, errOut.String(), captured, dir
}

func rcRunOffline(t *testing.T, target Target, dir string, files map[string][]byte) (code int, stderr string) {
	t.Helper()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	targetsPath := writeTargetsFile(t, []Target{target})
	var out, errOut bytes.Buffer
	code = run([]string{"-targets", targetsPath, "-offline", dir}, &out, &errOut, noExec(t))
	return code, errOut.String()
}

// grype exit 2 with its diagnostic object (`{"error": ...}`) had decoded
// to zero matches: 101 agreements collapsed to 0 and the gate passed. It is
// the hard failure the exit code says, its capture is filed apart, and the
// same document replayed offline is malformed by shape.
func TestRun_RC1111_GrypeDiagnosticJSONIsAHardFailure(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t", MinAgree: 1}
	code, stderr, captured, dir := rcRunLive(t, target, stub{out: assayDoc(0, nil), code: 0}, stub{out: []byte(`{"error":"scan failed"}`), code: 2})
	if code != exitError || !strings.Contains(stderr, "grype hard failure (exit 2)") {
		t.Errorf("exit=%d stderr=%q; want 2 and a grype hard failure", code, stderr)
	}
	if strings.Join(captured, ",") != "t.assay.json,t.assay.state.json,t.grype.failed.json,t.grype.state.json" {
		t.Errorf("captured %v; want the grype capture filed as failed, with a state file per tool", captured)
	}
	// Replayed offline, the failed capture is not read at all...
	code, stderr = rcRunOffline(t, target, dir, nil)
	if code != exitError || !strings.Contains(stderr, "the last run failed") {
		t.Errorf("offline: exit=%d stderr=%q; want 2, the failed run named", code, stderr)
	}
	// ...and the diagnostic object under the good name is malformed by shape.
	code, stderr = rcRunOffline(t, target, t.TempDir(), map[string][]byte{"t.assay.json": assayDoc(0, nil), "t.grype.json": []byte(`{"error":"scan failed"}`)})
	if code != exitError || !strings.Contains(stderr, `malformed grype JSON: no "matches" field`) {
		t.Errorf("offline diagnostic: exit=%d stderr=%q; want 2 and the shape named", code, stderr)
	}
	// With exit 0 the shape alone names it.
	code, stderr, _, _ = rcRunLive(t, target, stub{out: assayDoc(0, nil), code: 0}, stub{out: []byte(`{"error":"scan failed"}`), code: 0})
	if code != exitError || !strings.Contains(stderr, `malformed grype JSON: no "matches" field`) {
		t.Errorf("exit 0: exit=%d stderr=%q; want 2 and the shape named", code, stderr)
	}
	// A real empty report is one.
	code, stderr, _, _ = rcRunLive(t, Target{Name: "t", Ref: "ref-t"}, stub{out: assayDoc(0, nil), code: 0}, stub{out: []byte(`{"matches":[]}`), code: 0})
	if code != exitOK {
		t.Errorf("empty report: exit=%d stderr=%q; want 0", code, stderr)
	}
}

// assay exiting 2 beside a well-formed document failed the gate live, and
// the capture that run wrote passed it offline. The capture of a failed scan
// is filed as <name>.assay.failed.json, a stale good capture beside it is
// removed, and the replay finds nothing to promote.
func TestRun_RC1111_FailedAssayCaptureIsNotReplayable(t *testing.T) {
	target := Target{Name: "t", Ref: "ref-t"}
	// TestMain already stubs retryPause for the package; nothing to restore.
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	// A good capture from an earlier run in the same directory.
	if err := os.WriteFile(filepath.Join(dir, "t.assay.json"), assayDoc(0, nil), 0o644); err != nil {
		t.Fatal(err)
	}
	exec := newFakeExec(t, map[string]stub{"ref-t": {out: assayDoc(0, nil), code: 2}}, map[string]stub{"ref-t": {out: grypeDoc(nil), code: 0}})
	var out, errOut bytes.Buffer
	if code := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", dir}, &out, &errOut, exec); code != exitError {
		t.Fatalf("live: exit=%d stderr=%q; want 2", code, errOut.String())
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "t.assay.failed.json,t.assay.state.json,t.grype.json,t.grype.state.json" {
		t.Errorf("captured %v; want the assay capture filed as failed and the stale good one gone", names)
	}
	code, stderr := rcRunOffline(t, target, dir, nil)
	if code != exitError || !strings.Contains(stderr, "the last run failed") {
		t.Errorf("offline: exit=%d stderr=%q; want 2, the failed run named", code, stderr)
	}
}

// An assay document without a summary is not a report.
func TestRun_RC1111_AssayJSONWithoutSummaryIsMalformed(t *testing.T) {
	code, stderr := rcRunOffline(t, Target{Name: "t", Ref: "ref-t"}, t.TempDir(), map[string][]byte{"t.assay.json": []byte(`{"error":"no database"}`), "t.grype.json": grypeDoc(nil)})
	if code != exitError || !strings.Contains(stderr, `malformed assay JSON: no "summary" field`) {
		t.Errorf("exit=%d stderr=%q; want 2 and the shape named", code, stderr)
	}
}

// An offline capture whose argument field is gone is identified by the
// digests the tool recorded of the image it read; one of another image
// under the pinned ref's name is an ERROR, one that records nothing at all
// is accepted with a warning, and under a ref with no digest silently.
func TestRun_RC1111_OfflineCaptureIdentifiedByDigests(t *testing.T) {
	assayWith := func(prov string) []byte {
		return []byte(`{"schemaVersion":22,"findings":[],"summary":{"components":5}` + prov + `}`)
	}
	grypeWith := func(target string) []byte {
		return []byte(`{"matches":[],"source":{"type":"image","target":{` + target + `}}}`)
	}
	trivyWith := func(meta string) []byte {
		return []byte(`{"SchemaVersion":2,"Results":[]` + meta + `}`)
	}
	good := map[string][]byte{"t.assay.json": assayWith(`,"provenance":{"target":{"argument":"` + rcPinned + `"}}`), "t.grype.json": grypeWith(`"userInput":"` + rcPinned + `"`)}
	pinned := Target{Name: "t", Ref: rcPinned, MinComponents: 1}
	withTrivy := pinned
	withTrivy.Trivy = &TrivyFloors{MinAgree: 0, MinFindings: 0, MaxFindings: 100}
	for _, tc := range []struct {
		name   string
		target Target
		files  map[string][]byte
		code   int
		want   string
	}{
		{"assay: no argument, index digest of the pinned image", pinned, map[string][]byte{"t.assay.json": assayWith(`,"provenance":{"target":{"kind":"image","image":{"manifestDigest":"sha256:aaaa","indexDigest":"` + rcDigest + `"}}}`), "t.grype.json": good["t.grype.json"]}, exitOK, ""},
		{"assay: no argument, manifest digest of the pinned image", pinned, map[string][]byte{"t.assay.json": assayWith(`,"provenance":{"target":{"kind":"image","image":{"manifestDigest":"` + rcDigest + `"}}}`), "t.grype.json": good["t.grype.json"]}, exitOK, ""},
		{"assay: no argument, digests of another image", pinned, map[string][]byte{"t.assay.json": assayWith(`,"provenance":{"target":{"kind":"image","image":{"manifestDigest":"sha256:aaaa","indexDigest":"` + rcOther + `"}}}`), "t.grype.json": good["t.grype.json"]}, exitError, "offline assay capture records no target and its image digests"},
		{"assay: no argument and no digest, pinned ref: accepted with a warning", pinned, map[string][]byte{"t.assay.json": assayWith(""), "t.grype.json": good["t.grype.json"]}, exitOK, "warning: target=t offline assay capture records no target and no digest; accepted unchecked"},
		{"assay: no argument and no digest, ref with no digest: silent", Target{Name: "t", Ref: "alpine:3.19", MinComponents: 1}, map[string][]byte{"t.assay.json": assayWith(""), "t.grype.json": grypeWith(`"userInput":"alpine:3.19"`)}, exitOK, "SILENT"},
		{"grype: no userInput, repo digest of the pinned image", pinned, map[string][]byte{"t.assay.json": good["t.assay.json"], "t.grype.json": grypeWith(`"imageID":"sha256:bbbb","repoDigests":["registry.suse.com/bci/bci-base@` + rcDigest + `"]`)}, exitOK, ""},
		{"grype: no userInput, manifest digest of another image", pinned, map[string][]byte{"t.assay.json": good["t.assay.json"], "t.grype.json": grypeWith(`"imageID":"sha256:bbbb","manifestDigest":"` + rcOther + `","repoDigests":["x@` + rcOther + `"]`)}, exitError, "offline grype capture records no target and its image digests"},
		{"trivy: no ArtifactName, repo digest of the pinned image", withTrivy, map[string][]byte{"t.assay.json": good["t.assay.json"], "t.grype.json": good["t.grype.json"], "t.trivy.json": trivyWith(`,"Metadata":{"ImageID":"sha256:bbbb","RepoDigests":["registry.suse.com/bci/bci-base@` + rcDigest + `"]}`)}, exitOK, ""},
		{"trivy: no ArtifactName, repo digest of another image", withTrivy, map[string][]byte{"t.assay.json": good["t.assay.json"], "t.grype.json": good["t.grype.json"], "t.trivy.json": trivyWith(`,"Metadata":{"RepoDigests":["x@` + rcOther + `"]}`)}, exitError, "offline trivy capture records no target and its image digests"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := rcRunOffline(t, tc.target, t.TempDir(), tc.files)
			if code != tc.code {
				t.Errorf("exit=%d stderr=%q; want %d", code, stderr, tc.code)
			}
			switch {
			case tc.want == "SILENT":
				if stderr != "" {
					t.Errorf("stderr=%q; want nothing", stderr)
				}
			case tc.want != "" && !strings.Contains(stderr, tc.want):
				t.Errorf("stderr=%q; want it to contain %q", stderr, tc.want)
			case tc.want == "" && strings.Contains(stderr, "error:"):
				t.Errorf("stderr=%q; want no error", stderr)
			}
		})
	}
}
