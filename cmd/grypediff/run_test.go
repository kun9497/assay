package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// --- fixture helpers -------------------------------------------------------

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func writeTargetsFile(t *testing.T, targets []Target) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, mustMarshal(t, targets), 0o644); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	return path
}

// assayDoc builds a minimal, schema-8-shaped assay document. Collision-free
// per-test identifiers are the caller's job (CLAUDE.md's substring rule);
// this helper only assembles the shape.
func assayDoc(notEvaluated int, findings []assayFinding) []byte {
	b, _ := json.Marshal(assayDocument{
		SchemaVersion: 8,
		Findings:      findings,
		Summary:       assaySummary{NotEvaluated: notEvaluated, Findings: len(findings)},
	})
	return b
}

func grypeDoc(matches []grypeMatch) []byte {
	b, _ := json.Marshal(grypeDocument{Matches: matches})
	return b
}

// stub is one canned execFunc response.
type stub struct {
	out  []byte
	code int
	err  error
}

// newFakeExec routes assay calls ("scan <ref> --output json") and grype
// calls ("<ref> -o json") to canned responses keyed by ref. No test in this
// file ever launches a real process -- that is the whole point of D93's
// execScan seam.
func newFakeExec(t *testing.T, assayStubs, grypeStubs map[string]stub) execFunc {
	t.Helper()
	return func(bin string, args ...string) ([]byte, int, error) {
		if len(args) > 0 && args[0] == "scan" {
			ref := args[1]
			s, ok := assayStubs[ref]
			if !ok {
				t.Fatalf("no assay stub registered for ref %q (args=%v)", ref, args)
			}
			return s.out, s.code, s.err
		}
		ref := args[0]
		s, ok := grypeStubs[ref]
		if !ok {
			t.Fatalf("no grype stub registered for ref %q (args=%v)", ref, args)
		}
		return s.out, s.code, s.err
	}
}

func noExec(t *testing.T) execFunc {
	t.Helper()
	return func(bin string, args ...string) ([]byte, int, error) {
		t.Fatalf("execScan must not be called in this test (bin=%s args=%v)", bin, args)
		return nil, 0, nil
	}
}

// --- caller-first tests: run()'s observable behaviour -----------------------

func TestRun_AllFloorsHeld_ExitOK(t *testing.T) {
	target := Target{Name: "held", Ref: "ref-held", MinAgree: 1, MinFindings: 1, MaxFindings: 5}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "openssl"}, Advisory: assayAdvisory{ID: "OSV-1", Aliases: []string{"CVE-2024-1111"}}},
	})
	grypeBytes := grypeDoc([]grypeMatch{
		{Artifact: grypeArtifact{Name: "openssl"}, Vulnerability: grypeVuln{ID: "CVE-2024-1111"}},
	})
	exec := newFakeExec(t,
		map[string]stub{"ref-held": {out: assayBytes, code: 0}},
		map[string]stub{"ref-held": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	captureDir := t.TempDir()
	got := run([]string{"-targets", targetsPath, "-assay", "assay.exe", "-grype", "grype.exe", "-capture", captureDir},
		&stdout, &stderr, exec)

	if got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "held") || !strings.Contains(stdout.String(), "ok") {
		t.Errorf("stdout table = %q, want it to name the target and verdict ok", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty when every floor holds", stderr.String())
	}
	// Captures were written for a human to re-judge locally (D93's own point
	// of the -capture directory).
	for _, kind := range []string{"assay", "grype"} {
		p := filepath.Join(captureDir, "held."+kind+".json")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected capture file %s to exist: %v", p, err)
		}
	}
}

func TestRun_AgreeCollapse_ExitFindingsNamingTargetAndFloor(t *testing.T) {
	// D90's own shape: findings are present on both sides, but they stopped
	// agreeing with each other -- the failure minFindings alone would miss.
	target := Target{Name: "agree-collapse", Ref: "ref-collapse", MinAgree: 2, MinFindings: 1, MaxFindings: 10}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "libx"}, Advisory: assayAdvisory{ID: "OSV-2", Aliases: []string{"CVE-2025-2222"}}},
		{Package: assayPackage{Name: "liby"}, Advisory: assayAdvisory{ID: "OSV-3", Aliases: []string{"CVE-2025-3333"}}},
	})
	grypeBytes := grypeDoc([]grypeMatch{
		{Artifact: grypeArtifact{Name: "libz"}, Vulnerability: grypeVuln{ID: "CVE-2025-4444"}},
	})
	exec := newFakeExec(t,
		map[string]stub{"ref-collapse": {out: assayBytes, code: 0}},
		map[string]stub{"ref-collapse": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=agree-collapse floor=minAgree want=>=2 got=0"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

func TestRun_FindingsBelowMinFindings_ExitFindings(t *testing.T) {
	target := Target{Name: "below-min", Ref: "ref-below-min", MinAgree: 0, MinFindings: 3, MaxFindings: 10}
	targetsPath := writeTargetsFile(t, []Target{target})

	doc := []assayFinding{{Package: assayPackage{Name: "curl"}, Advisory: assayAdvisory{ID: "OSV-4", Aliases: []string{"CVE-2026-5555"}}}}
	assayBytes := assayDoc(0, doc)
	grypeBytes := grypeDoc([]grypeMatch{{Artifact: grypeArtifact{Name: "curl"}, Vulnerability: grypeVuln{ID: "CVE-2026-5555"}}})
	exec := newFakeExec(t,
		map[string]stub{"ref-below-min": {out: assayBytes, code: 0}},
		map[string]stub{"ref-below-min": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=below-min floor=minFindings want=>=3 got=1"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

func TestRun_FindingsAboveMaxFindings_ExitFindings(t *testing.T) {
	target := Target{Name: "above-max", Ref: "ref-above-max", MinAgree: 0, MinFindings: 0, MaxFindings: 1}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "pkg-a"}, Advisory: assayAdvisory{ID: "OSV-5", Aliases: []string{"CVE-2026-6001"}}},
		{Package: assayPackage{Name: "pkg-b"}, Advisory: assayAdvisory{ID: "OSV-6", Aliases: []string{"CVE-2026-6002"}}},
	})
	grypeBytes := grypeDoc(nil)
	exec := newFakeExec(t,
		map[string]stub{"ref-above-max": {out: assayBytes, code: 0}},
		map[string]stub{"ref-above-max": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=above-max floor=maxFindings want=<=1 got=2"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

func TestRun_NotEvaluatedAppearsWhereFloorIsZero_ExitFindings(t *testing.T) {
	target := Target{Name: "not-eval-zero", Ref: "ref-not-eval-zero", MinAgree: 0, MinFindings: 0, MaxFindings: 10}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(1, nil)
	grypeBytes := grypeDoc(nil)
	exec := newFakeExec(t,
		map[string]stub{"ref-not-eval-zero": {out: assayBytes, code: 0}},
		map[string]stub{"ref-not-eval-zero": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=not-eval-zero floor=maxNotEvaluated want=<=0 got=1"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

func TestRun_NotEvaluatedGrowsPastMax_ExitFindings(t *testing.T) {
	target := Target{Name: "not-eval-grow", Ref: "ref-not-eval-grow", MaxNotEvaluated: 2}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(3, nil)
	grypeBytes := grypeDoc(nil)
	exec := newFakeExec(t,
		map[string]stub{"ref-not-eval-grow": {out: assayBytes, code: 0}},
		map[string]stub{"ref-not-eval-grow": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=not-eval-grow floor=maxNotEvaluated want=<=2 got=3"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

func TestRun_AssayScanExitsTwo_ExitError(t *testing.T) {
	target := Target{Name: "assay-fatal", Ref: "ref-assay-fatal"}
	targetsPath := writeTargetsFile(t, []Target{target})

	exec := newFakeExec(t,
		map[string]stub{"ref-assay-fatal": {out: nil, code: 2}},
		map[string]stub{"ref-assay-fatal": {out: grypeDoc(nil), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=assay-fatal") || !strings.Contains(stderr.String(), "assay scan exited 2") {
		t.Errorf("stderr = %q, want it to name the target and the assay exit-2 reason", stderr.String())
	}
	if !strings.Contains(stdout.String(), "assay-fatal") || !strings.Contains(stdout.String(), "ERROR") {
		t.Errorf("stdout = %q, want the table to still list assay-fatal with verdict ERROR", stdout.String())
	}
}

func TestRun_Live_MalformedGrypeJSON_ExitError(t *testing.T) {
	target := Target{Name: "grype-garbage", Ref: "ref-grype-garbage"}
	targetsPath := writeTargetsFile(t, []Target{target})

	exec := newFakeExec(t,
		map[string]stub{"ref-grype-garbage": {out: assayDoc(0, nil), code: 0}},
		map[string]stub{"ref-grype-garbage": {out: []byte("not json"), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=grype-garbage") || !strings.Contains(stderr.String(), "malformed grype JSON") {
		t.Errorf("stderr = %q, want it to name the target and say malformed grype JSON", stderr.String())
	}
}

func TestRun_Live_GrypeHardFailure_ExitError(t *testing.T) {
	target := Target{Name: "grype-crash", Ref: "ref-grype-crash"}
	targetsPath := writeTargetsFile(t, []Target{target})

	exec := newFakeExec(t,
		map[string]stub{"ref-grype-crash": {out: assayDoc(0, nil), code: 0}},
		map[string]stub{"ref-grype-crash": {out: nil, code: 1}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "grype hard failure (exit 1)") {
		t.Errorf("stderr = %q, want it to say grype hard failure with the exit code, distinct from malformed JSON", stderr.String())
	}
}

func TestRun_Live_MalformedAssayJSON_ExitError(t *testing.T) {
	target := Target{Name: "assay-garbage", Ref: "ref-assay-garbage"}
	targetsPath := writeTargetsFile(t, []Target{target})

	exec := newFakeExec(t,
		map[string]stub{"ref-assay-garbage": {out: []byte("<<not json>>"), code: 0}},
		map[string]stub{"ref-assay-garbage": {out: grypeDoc(nil), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=assay-garbage") || !strings.Contains(stderr.String(), "malformed assay JSON") {
		t.Errorf("stderr = %q, want it to name the target and say malformed assay JSON", stderr.String())
	}
}

func TestRun_TargetsFileMissing_ExitErrorWithUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// -offline given (not live flags): isolates this from the separate
	// "live mode requires -assay/-grype/-capture" check below, which would
	// otherwise also fire on an empty *targetsPath-derived targets slice and
	// mask a deleted loadTargets error check (caught by mutation testing --
	// the first version of this test passed even with that check deleted).
	got := run([]string{"-targets", filepath.Join(t.TempDir(), "does-not-exist.json"), "-offline", t.TempDir()},
		&stdout, &stderr, noExec(t))

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr = %q, want usage to be printed", stderr.String())
	}
	if !strings.Contains(stderr.String(), "does-not-exist.json") {
		t.Errorf("stderr = %q, want it to name the unreadable targets file", stderr.String())
	}
}

func TestRun_TargetsFileInvalidJSON_ExitErrorWithUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("write invalid targets file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	// -offline given for the same isolation reason as the missing-file case
	// above.
	got := run([]string{"-targets", path, "-offline", t.TempDir()}, &stdout, &stderr, noExec(t))

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr = %q, want usage to be printed", stderr.String())
	}
}

func TestRun_LiveModeRequiresAssayGrypeCapture_ExitError(t *testing.T) {
	targetsPath := writeTargetsFile(t, []Target{{Name: "x", Ref: "ref-x"}})

	var stdout, stderr bytes.Buffer
	// -grype and -capture omitted, and -offline not given either: this must
	// not silently try to launch an empty-string binary.
	got := run([]string{"-targets", targetsPath, "-assay", "a"}, &stdout, &stderr, noExec(t))

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "live mode requires") {
		t.Errorf("stderr = %q, want it to explain live mode's required flags", stderr.String())
	}
}

func TestRun_MultipleTargets_OneBreaches_StillRunsRestAndTableShowsBoth(t *testing.T) {
	held := Target{Name: "held-target", Ref: "ref-held-target", MinAgree: 1, MinFindings: 1, MaxFindings: 5}
	breaching := Target{Name: "breach-target", Ref: "ref-breach-target", MinAgree: 0, MinFindings: 9, MaxFindings: 99}
	targetsPath := writeTargetsFile(t, []Target{held, breaching})

	heldAssay := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "zlib"}, Advisory: assayAdvisory{ID: "OSV-7", Aliases: []string{"CVE-2026-7001"}}}})
	heldGrype := grypeDoc([]grypeMatch{{Artifact: grypeArtifact{Name: "zlib"}, Vulnerability: grypeVuln{ID: "CVE-2026-7001"}}})
	breachAssay := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "sed"}, Advisory: assayAdvisory{ID: "OSV-8", Aliases: []string{"CVE-2026-7002"}}}})
	breachGrype := grypeDoc(nil)

	exec := newFakeExec(t,
		map[string]stub{"ref-held-target": {out: heldAssay, code: 0}, "ref-breach-target": {out: breachAssay, code: 0}},
		map[string]stub{"ref-held-target": {out: heldGrype, code: 0}, "ref-breach-target": {out: breachGrype, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "held-target") || !strings.Contains(out, "breach-target") {
		t.Fatalf("stdout table = %q, want a row for both targets", out)
	}
	if !strings.Contains(stderr.String(), "target=breach-target") {
		t.Errorf("stderr = %q, want the breach line to name breach-target", stderr.String())
	}
	if strings.Contains(stderr.String(), "target=held-target") {
		t.Errorf("stderr = %q, want no breach line for held-target", stderr.String())
	}
}

func TestRun_MultipleTargets_OneFatal_StillRunsRest(t *testing.T) {
	ok := Target{Name: "ok-target", Ref: "ref-ok-target"}
	fatal := Target{Name: "fatal-target", Ref: "ref-fatal-target"}
	targetsPath := writeTargetsFile(t, []Target{ok, fatal})

	exec := newFakeExec(t,
		map[string]stub{"ref-ok-target": {out: assayDoc(0, nil), code: 0}, "ref-fatal-target": {out: nil, code: 2}},
		map[string]stub{"ref-ok-target": {out: grypeDoc(nil), code: 0}, "ref-fatal-target": {out: grypeDoc(nil), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ok-target") || !strings.Contains(out, "fatal-target") {
		t.Fatalf("stdout table = %q, want a row for both targets", out)
	}
}

func TestRun_PrecedenceErrorBeatsBreachRegardlessOfOrder(t *testing.T) {
	// D11's rule, restated for this tool: an untrustworthy result outranks
	// the content of the result. A breach on the FIRST target processed
	// must not stick as the final exit code once a later target turns out
	// fatal.
	breaching := Target{Name: "breach-first", Ref: "ref-breach-first", MinAgree: 0, MinFindings: 9, MaxFindings: 99}
	fatal := Target{Name: "fatal-second", Ref: "ref-fatal-second"}
	targetsPath := writeTargetsFile(t, []Target{breaching, fatal})

	breachAssay := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "gawk"}, Advisory: assayAdvisory{ID: "OSV-11", Aliases: []string{"CVE-2026-7005"}}}})
	exec := newFakeExec(t,
		map[string]stub{"ref-breach-first": {out: breachAssay, code: 0}, "ref-fatal-second": {out: nil, code: 2}},
		map[string]stub{"ref-breach-first": {out: grypeDoc(nil), code: 0}, "ref-fatal-second": {out: grypeDoc(nil), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (a breach earlier must not outrank a fatal target later)", got, exitError)
	}
}

func TestRun_StdoutStaysMachineCleanInLiveMode(t *testing.T) {
	target := Target{Name: "clean", Ref: "ref-clean", MinAgree: 1, MinFindings: 1, MaxFindings: 5}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "tar"}, Advisory: assayAdvisory{ID: "OSV-9", Aliases: []string{"CVE-2026-7003"}}}})
	grypeBytes := grypeDoc([]grypeMatch{{Artifact: grypeArtifact{Name: "tar"}, Vulnerability: grypeVuln{ID: "CVE-2026-7003"}}})
	exec := newFakeExec(t,
		map[string]stub{"ref-clean": {out: assayBytes, code: 0}},
		map[string]stub{"ref-clean": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitOK {
		t.Fatalf("exit = %d, want %d", got, exitOK)
	}
	if strings.Contains(stdout.String(), "error") || strings.Contains(stdout.String(), "breach") {
		t.Errorf("stdout = %q, diagnostics must go to stderr only", stdout.String())
	}
}

func TestRun_Offline_AllFloorsHeld_ExitOK(t *testing.T) {
	target := Target{Name: "off-held", Ref: "unused-in-offline-mode", MinAgree: 1, MinFindings: 1, MaxFindings: 5}
	targetsPath := writeTargetsFile(t, []Target{target})

	dir := t.TempDir()
	assayBytes := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "bash"}, Advisory: assayAdvisory{ID: "OSV-10", Aliases: []string{"CVE-2026-7004"}}}})
	grypeBytes := grypeDoc([]grypeMatch{{Artifact: grypeArtifact{Name: "bash"}, Vulnerability: grypeVuln{ID: "CVE-2026-7004"}}})
	if err := os.WriteFile(filepath.Join(dir, "off-held.assay.json"), assayBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "off-held.grype.json"), grypeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir}, &stdout, &stderr, noExec(t))

	if got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "off-held") {
		t.Errorf("stdout = %q, want the target row", stdout.String())
	}
}

func TestRun_Offline_MalformedGrypeJSON_ExitError(t *testing.T) {
	target := Target{Name: "off-garbage", Ref: "unused-in-offline-mode"}
	targetsPath := writeTargetsFile(t, []Target{target})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "off-garbage.assay.json"), assayDoc(0, nil), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "off-garbage.grype.json"), []byte("{{{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir}, &stdout, &stderr, noExec(t))

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=off-garbage") || !strings.Contains(stderr.String(), "malformed grype JSON") {
		t.Errorf("stderr = %q, want it to name the target and say malformed grype JSON", stderr.String())
	}
}

func TestRun_Offline_MissingCaptureFile_ExitError(t *testing.T) {
	target := Target{Name: "off-missing", Ref: "unused-in-offline-mode"}
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir() // no capture files written at all

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir}, &stdout, &stderr, noExec(t))

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=off-missing") {
		t.Errorf("stderr = %q, want it to name the target", stderr.String())
	}
}

// TestRun_TableColumnsKeepDirection pins WHICH side each disagreement column
// reports: onlyAssay counts tuples only assay found, onlyGrype the reverse.
// Every other test in this file happened to use fixtures where the two
// columns' values were equal or one side was empty, so swapping compareSets'
// two arguments survived the whole suite (found by an independent mutation
// on 2026-08-26) -- a differential whose columns silently trade places
// reports a grype-side data gap as an assay regression and vice versa,
// which is precisely the judgment this tool exists to automate. The
// asymmetric fixture (1 assay-only vs 2 grype-only) plus a positional
// assertion on the row is what makes the swap visible.
func TestRun_TableColumnsKeepDirection(t *testing.T) {
	target := Target{Name: "direction", Ref: "ref-direction", MinAgree: 1, MinFindings: 1, MaxFindings: 10}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "libdir"}, Advisory: assayAdvisory{ID: "OSV-DIR-1", Aliases: []string{"CVE-2026-1111"}}},
		{Package: assayPackage{Name: "libdir"}, Advisory: assayAdvisory{ID: "OSV-DIR-2", Aliases: []string{"CVE-2026-2222"}}},
	})
	grypeBytes := grypeDoc([]grypeMatch{
		{Artifact: grypeArtifact{Name: "libdir"}, Vulnerability: grypeVuln{ID: "CVE-2026-2222"}},
		{Artifact: grypeArtifact{Name: "libdir"}, Vulnerability: grypeVuln{ID: "CVE-2026-3333"}},
		{Artifact: grypeArtifact{Name: "libdir"}, Vulnerability: grypeVuln{ID: "CVE-2026-4444"}},
	})
	exec := newFakeExec(t,
		map[string]stub{"ref-direction": {out: assayBytes, code: 0}},
		map[string]stub{"ref-direction": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)
	if got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr.String())
	}
	var rowLine string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.Contains(line, "direction") {
			rowLine = line
		}
	}
	if rowLine == "" {
		t.Fatalf("no table row for target; stdout=%q", stdout.String())
	}
	// Positional, not presence: ASSAY GRYPE AGREE ONLY_ASSAY ONLY_GRYPE
	// NOTEVAL. Presence alone would pass with the columns traded.
	want := []string{"direction", "2", "3", "1", "1", "2", "0", "ok"}
	if got := strings.Fields(rowLine); !slices.Equal(got, want) {
		t.Errorf("row = %v, want %v", got, want)
	}
}

// TestRun_AssayScanExitsUnexpectedCode_ExitError is the QA-round-5 close for
// runAssay's "unexpected code" guard (D93). Exit 0, 1, and 2 are all handled
// by other tests; a code OUTSIDE {0,1,2} — a scanner that died on a signal
// (137) or returned a wrapper's own error code — must be treated as
// untrustworthy, not silently trusted as a scan whose result can be read.
// Deleting the guard entirely left the suite green.
func TestRun_AssayScanExitsUnexpectedCode_ExitError(t *testing.T) {
	target := Target{Name: "assay-137", Ref: "ref-assay-137"}
	targetsPath := writeTargetsFile(t, []Target{target})

	exec := newFakeExec(t,
		map[string]stub{"ref-assay-137": {out: nil, code: 137}},
		map[string]stub{"ref-assay-137": {out: grypeDoc(nil), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=assay-137") || !strings.Contains(stderr.String(), "unexpected code 137") {
		t.Errorf("stderr = %q, want it to name the target and the unexpected exit code", stderr.String())
	}
}
