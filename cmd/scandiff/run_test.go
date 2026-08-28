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

func trivyDocBytes(results []trivyResult) []byte {
	b, _ := json.Marshal(trivyDocument{Results: results})
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

// newFakeExecWithTrivy extends newFakeExec with a third scanner: trivy is
// invoked as `trivy image --format json --quiet <ref>`, so args[0] ==
// "image" is what distinguishes a trivy call from grype's (args[0] == the
// ref itself) and assay's (args[0] == "scan"). Only tests that exercise a
// target with a trivy block use this helper -- every test that does NOT
// need trivy keeps using newFakeExec unchanged, and that absence is itself
// load-bearing: newFakeExec has no "image" case, so if run.go ever called
// execScan for trivy on a target with no trivy block, it would fall into
// the grype branch, look up grypeStubs["image"], find nothing registered,
// and t.Fatalf loudly -- see TestRun_TargetWithoutTrivyBlock_NeverInvokesTrivy.
func newFakeExecWithTrivy(t *testing.T, assayStubs, grypeStubs, trivyStubs map[string]stub) execFunc {
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
		if len(args) > 0 && args[0] == "image" {
			ref := args[len(args)-1]
			s, ok := trivyStubs[ref]
			if !ok {
				t.Fatalf("no trivy stub registered for ref %q (args=%v)", ref, args)
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

// --- D105: the optional trivy comparison -----------------------------------

// TestRun_TargetWithoutTrivyBlock_NeverInvokesTrivy is the caller-first test
// for D105: a target with no "trivy" key in the floors file must not
// provoke a trivy invocation, and no <name>.trivy.json capture file. It
// uses newFakeExec (not the trivy-aware helper), so a wrongly-added trivy
// call fails loudly via t.Fatalf rather than silently succeeding -- see
// newFakeExecWithTrivy's own doc comment.
func TestRun_TargetWithoutTrivyBlock_NeverInvokesTrivy(t *testing.T) {
	target := Target{Name: "no-trivy", Ref: "ref-no-trivy", MinAgree: 1, MinFindings: 1, MaxFindings: 5}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "openssl"}, Advisory: assayAdvisory{ID: "OSV-100", Aliases: []string{"CVE-2026-8001"}}},
	})
	grypeBytes := grypeDoc([]grypeMatch{
		{Artifact: grypeArtifact{Name: "openssl"}, Vulnerability: grypeVuln{ID: "CVE-2026-8001"}},
	})
	exec := newFakeExec(t,
		map[string]stub{"ref-no-trivy": {out: assayBytes, code: 0}},
		map[string]stub{"ref-no-trivy": {out: grypeBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	captureDir := t.TempDir()
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", captureDir}, &stdout, &stderr, exec)

	if got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(captureDir, "no-trivy.trivy.json")); err == nil {
		t.Errorf("no-trivy.trivy.json exists, want no trivy capture for a target with no trivy block")
	}
}

// TestRun_TargetWithTrivyBlock_RunsComparisonAndBreachesOnFloor is the
// caller-first proof that a target WITH a committed (non-informational)
// trivy block DOES run the comparison: trivy reports zero tuples, so
// trivy.minAgree trips, which could not happen if trivyPhase were never
// invoked.
func TestRun_TargetWithTrivyBlock_RunsComparisonAndBreachesOnFloor(t *testing.T) {
	target := Target{
		Name: "with-trivy", Ref: "ref-with-trivy",
		MinAgree: 0, MinFindings: 0, MaxFindings: 5,
		Trivy: &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 5},
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "openssl"}, Advisory: assayAdvisory{ID: "OSV-101", Aliases: []string{"CVE-2026-8002"}}},
	})
	grypeBytes := grypeDoc(nil)
	trivyBytes := trivyDocBytes(nil) // clean per trivy: zero tuples

	exec := newFakeExecWithTrivy(t,
		map[string]stub{"ref-with-trivy": {out: assayBytes, code: 0}},
		map[string]stub{"ref-with-trivy": {out: grypeBytes, code: 0}},
		map[string]stub{"ref-with-trivy": {out: trivyBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	captureDir := t.TempDir()
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-trivy", "tv", "-capture", captureDir}, &stdout, &stderr, exec)

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=with-trivy floor=trivy.minAgree want=>=1 got=0"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
	if !strings.Contains(stdout.String(), "with-trivy") || !strings.Contains(stdout.String(), "BREACH") {
		t.Errorf("stdout table = %q, want the row for with-trivy marked BREACH", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(captureDir, "with-trivy.trivy.json")); err != nil {
		t.Errorf("expected trivy capture file to exist: %v", err)
	}
}

// TestRun_InformationalTrivyBlock_MeasuresAndNeverBreaches proves D105's
// seeding mode: an empty "trivy" block (every floor zero) must never
// breach, no matter what trivy measures, and the measured numbers must
// appear on stdout in ready-to-paste JSON form.
func TestRun_InformationalTrivyBlock_MeasuresAndNeverBreaches(t *testing.T) {
	target := Target{
		Name: "info-target", Ref: "ref-info-target",
		MinAgree: 0, MinFindings: 0, MaxFindings: 5,
		Trivy: &TrivyFloors{}, // all zero: informational
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, []assayFinding{
		{Package: assayPackage{Name: "curl"}, Advisory: assayAdvisory{ID: "OSV-102", Aliases: []string{"CVE-2026-8003"}}},
	})
	grypeBytes := grypeDoc(nil)
	// trivy sees the same CVE (agree=1) plus one extra (findings=2), which
	// would trip a real trivy.maxFindings=1 floor if this were gating --
	// proving the informational block truly never breaches, not just that
	// this fixture happens to hold.
	trivyBytes := trivyDocBytes([]trivyResult{
		{Class: "os-pkgs", Vulnerabilities: []trivyVuln{
			{PkgName: "curl", VulnerabilityID: "CVE-2026-8003"},
			{PkgName: "curl", VulnerabilityID: "CVE-2026-8004"},
		}},
	})

	exec := newFakeExecWithTrivy(t,
		map[string]stub{"ref-info-target": {out: assayBytes, code: 0}},
		map[string]stub{"ref-info-target": {out: grypeBytes, code: 0}},
		map[string]stub{"ref-info-target": {out: trivyBytes, code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-trivy", "tv", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitOK {
		t.Fatalf("exit = %d, want %d (informational must never breach; stderr=%q)", got, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "info-target") || !strings.Contains(stdout.String(), "ok") {
		t.Errorf("stdout table = %q, want the row for info-target marked ok", stdout.String())
	}
	wantSnippet := `{"minAgree":1,"minFindings":2,"maxFindings":2}`
	if !strings.Contains(stdout.String(), wantSnippet) {
		t.Errorf("stdout = %q, want it to contain the measured, ready-to-paste snippet %q", stdout.String(), wantSnippet)
	}
	if !strings.Contains(stderr.String(), "target=info-target") || !strings.Contains(stderr.String(), "trivy measured") {
		t.Errorf("stderr = %q, want an informational measurement notice naming the target", stderr.String())
	}
}

// TestRun_TrivyHardFailureOnGatingTarget_ExitError proves a trivy failure on
// a target with a COMMITTED (non-zero) floor is a real failure: the target
// becomes untrustworthy (ERROR), same as an assay or grype fatal.
func TestRun_TrivyHardFailureOnGatingTarget_ExitError(t *testing.T) {
	target := Target{
		Name: "trivy-crash", Ref: "ref-trivy-crash",
		MinAgree: 0, MinFindings: 0, MaxFindings: 5,
		Trivy: &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 5},
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, nil)
	grypeBytes := grypeDoc(nil)
	exec := newFakeExecWithTrivy(t,
		map[string]stub{"ref-trivy-crash": {out: assayBytes, code: 0}},
		map[string]stub{"ref-trivy-crash": {out: grypeBytes, code: 0}},
		map[string]stub{"ref-trivy-crash": {out: nil, code: 1}}, // not JSON, nonzero exit
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-trivy", "tv", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=trivy-crash") || !strings.Contains(stderr.String(), "trivy hard failure (exit 1)") {
		t.Errorf("stderr = %q, want it to name the target and the trivy hard failure", stderr.String())
	}
	if !strings.Contains(stdout.String(), "trivy-crash") || !strings.Contains(stdout.String(), "ERROR") {
		t.Errorf("stdout = %q, want the table to mark trivy-crash ERROR", stdout.String())
	}
}

// TestRun_TrivyFailureOnInformationalTarget_WarnsAndStaysOK proves the
// opposite of the previous test: the identical trivy failure on an
// INFORMATIONAL target must only warn, never touch the exit code.
func TestRun_TrivyFailureOnInformationalTarget_WarnsAndStaysOK(t *testing.T) {
	target := Target{
		Name: "trivy-crash-info", Ref: "ref-trivy-crash-info",
		MinAgree: 0, MinFindings: 0, MaxFindings: 5,
		Trivy: &TrivyFloors{}, // informational
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	assayBytes := assayDoc(0, nil)
	grypeBytes := grypeDoc(nil)
	exec := newFakeExecWithTrivy(t,
		map[string]stub{"ref-trivy-crash-info": {out: assayBytes, code: 0}},
		map[string]stub{"ref-trivy-crash-info": {out: grypeBytes, code: 0}},
		map[string]stub{"ref-trivy-crash-info": {out: []byte("not json"), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-trivy", "tv", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitOK {
		t.Fatalf("exit = %d, want %d (an informational trivy failure must not affect the exit code; stderr=%q)", got, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning: target=trivy-crash-info trivy (informational)") {
		t.Errorf("stderr = %q, want a warning naming the target, not an error", stderr.String())
	}
	if !strings.Contains(stdout.String(), "trivy-crash-info") || !strings.Contains(stdout.String(), "ok") {
		t.Errorf("stdout = %q, want the table to still mark trivy-crash-info ok", stdout.String())
	}
}

// TestRun_Live_NoTrivyBinConfigured_GatingTarget_ExitError proves -trivy can
// be omitted safely when no target needs it (see the other tests above,
// none of which would compile-fail without -trivy either) but is a fatal
// per-target configuration error when a target DOES carry a committed trivy
// floor and -trivy was never given.
func TestRun_Live_NoTrivyBinConfigured_GatingTarget_ExitError(t *testing.T) {
	target := Target{
		Name: "needs-trivy-bin", Ref: "ref-needs-trivy-bin",
		Trivy: &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 5},
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	exec := newFakeExec(t, // no trivy stubs at all -- execScan must never be called for trivy
		map[string]stub{"ref-needs-trivy-bin": {out: assayDoc(0, nil), code: 0}},
		map[string]stub{"ref-needs-trivy-bin": {out: grypeDoc(nil), code: 0}},
	)

	var stdout, stderr bytes.Buffer
	// -trivy deliberately omitted.
	got := run([]string{"-targets", targetsPath, "-assay", "a", "-grype", "g", "-capture", t.TempDir()}, &stdout, &stderr, exec)

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=needs-trivy-bin") || !strings.Contains(stderr.String(), "-trivy binary not configured") {
		t.Errorf("stderr = %q, want it to name the target and explain the missing -trivy binary", stderr.String())
	}
}

// TestRun_Offline_TargetWithTrivyBlock_ReadsTrivyCaptureFile proves offline
// mode reads <dir>/<name>.trivy.json for a target with a trivy block. The
// captured trivy document deliberately disagrees with assay's tuple (a
// different CVE, so trivy.minAgree=1 cannot be satisfied) so the exit code
// itself depends on the file having been read: a build that silently
// stopped reading the trivy capture (or stopped calling trivyPhase at all)
// would see no trivy data, judge nothing against trivy.minAgree, and exit
// exitOK instead of exitFindings -- exactly what CLAUDE.md's "helper is
// covered; nothing calls it" rule asks a caller-first test to catch. A
// bare "exit == exitOK" assertion here (the first version of this test)
// would have passed either way and proven nothing.
func TestRun_Offline_TargetWithTrivyBlock_ReadsTrivyCaptureFile(t *testing.T) {
	target := Target{
		Name: "off-trivy", Ref: "unused-in-offline-mode",
		MinAgree: 1, MinFindings: 1, MaxFindings: 5,
		Trivy: &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 5},
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	dir := t.TempDir()
	assayBytes := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "libz"}, Advisory: assayAdvisory{ID: "OSV-103", Aliases: []string{"CVE-2026-8005"}}}})
	grypeBytes := grypeDoc([]grypeMatch{{Artifact: grypeArtifact{Name: "libz"}, Vulnerability: grypeVuln{ID: "CVE-2026-8005"}}})
	// No overlap with assay's tuple at all: trivy.minAgree=1 can only be
	// satisfied if this file gets read AND intersected against assay's set.
	trivyBytes := trivyDocBytes([]trivyResult{{Class: "os-pkgs", Vulnerabilities: []trivyVuln{{PkgName: "unrelated-pkg", VulnerabilityID: "CVE-2026-9999"}}}})
	for name, b := range map[string][]byte{
		"off-trivy.assay.json": assayBytes,
		"off-trivy.grype.json": grypeBytes,
		"off-trivy.trivy.json": trivyBytes,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir}, &stdout, &stderr, noExec(t))

	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (a non-agreeing trivy capture must trip trivy.minAgree; stderr=%q)", got, exitFindings, stderr.String())
	}
	want := "target=off-trivy floor=trivy.minAgree want=>=1 got=0"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

// TestRun_Offline_TargetWithTrivyBlock_MissingCaptureFile_ExitError proves a
// committed-floor target with no <name>.trivy.json is treated as
// untrustworthy, not silently judged as zero trivy findings.
func TestRun_Offline_TargetWithTrivyBlock_MissingCaptureFile_ExitError(t *testing.T) {
	target := Target{
		Name: "off-trivy-missing", Ref: "unused-in-offline-mode",
		Trivy: &TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 5},
	}
	targetsPath := writeTargetsFile(t, []Target{target})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "off-trivy-missing.assay.json"), assayDoc(0, nil), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "off-trivy-missing.grype.json"), grypeDoc(nil), 0o644); err != nil {
		t.Fatal(err)
	}
	// off-trivy-missing.trivy.json deliberately not written.

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir}, &stdout, &stderr, noExec(t))

	if got != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target=off-trivy-missing") || !strings.Contains(stderr.String(), "read offline trivy capture") {
		t.Errorf("stderr = %q, want it to name the target and explain the missing trivy capture", stderr.String())
	}
}

// TestRun_Offline_BridgeRecoversABareAdvisoryJoin drives run() itself
// through the bridge: assay falls back bare on FEDORA-2026-dddd (no CVE
// anywhere in its record) while grype names that advisory beside its own
// CVE. Without bridgeBareIDs in run's flow, agree is 0 and the minAgree
// floor breaches -- so deleting the call site turns THIS test red, which
// the direct bridge unit tests cannot do.
func TestRun_Offline_BridgeRecoversABareAdvisoryJoin(t *testing.T) {
	target := Target{Name: "off-bridge", Ref: "unused-in-offline-mode", MinAgree: 1, MinFindings: 1, MaxFindings: 5}
	targetsPath := writeTargetsFile(t, []Target{target})

	dir := t.TempDir()
	assayBytes := assayDoc(0, []assayFinding{{Package: assayPackage{Name: "vim-data"}, Advisory: assayAdvisory{ID: "FEDORA-2026-dddd"}}})
	grypeBytes := grypeDoc([]grypeMatch{{Artifact: grypeArtifact{Name: "vim-data"}, Vulnerability: grypeVuln{
		ID: "CVE-2026-77002", Advisories: []grypeAdvisory{{ID: "FEDORA-2026-dddd"}}}}})
	if err := os.WriteFile(filepath.Join(dir, "off-bridge.assay.json"), assayBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "off-bridge.grype.json"), grypeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir}, &stdout, &stderr, noExec(t))
	if got != exitOK {
		t.Fatalf("exit = %d, want %d -- the bridged advisory join must satisfy minAgree (stderr=%q)", got, exitOK, stderr.String())
	}
}
