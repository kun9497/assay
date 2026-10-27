package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assayOnlyDoc is written as literal JSON, in the spelling assay's report
// emits (fixState, evidence.fixed), so a misspelled struct tag on this side
// cannot round-trip its way to green. Package and CVE names are chosen not to
// collide with one another (CLAUDE.md's substring rule).
const assayOnlyDoc = `{"schemaVersion":8,"summary":{"components":5},"findings":[
 {"package":{"name":"pkg-fixed"},"advisory":{"id":"CVE-2099-1001"},"fixState":"fixed","evidence":{"fixed":"1.2-1"}},
 {"package":{"name":"pkg-notfixed"},"advisory":{"id":"CVE-2099-1002"},"fixState":"not-fixed","evidence":{}},
 {"package":{"name":"pkg-wontfix"},"advisory":{"id":"CVE-2099-1003"},"fixState":"wont-fix","evidence":{}},
 {"package":{"name":"pkg-wontfix-versioned"},"advisory":{"id":"CVE-2099-1007"},"fixState":"wont-fix","evidence":{"fixed":"9.9"}},
 {"package":{"name":"pkg-nofixver"},"advisory":{"id":"CVE-2099-1004"},"fixState":"unknown","evidence":{}},
 {"package":{"name":"pkg-fixed-elsewhere"},"advisory":{"id":"CVE-2099-1005"},"fixState":"fixed","evidence":{}},
 {"package":{"name":"pkg-shared"},"advisory":{"id":"CVE-2099-1006"},"fixState":"fixed","evidence":{"fixed":"2.0"}}
]}`

// The one tuple grype also reports: shared, so not assay-only however it is
// fixed.
var sharedGrype = grypeDoc([]grypeMatch{{
	Vulnerability: grypeVuln{ID: "CVE-2099-1006"},
	Artifact:      grypeArtifact{Name: "pkg-shared", Type: "rpm"},
}})

func runAssayOnly(t *testing.T, target Target, extra ...string) (int, string) {
	t.Helper()
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	writeOffline(t, dir, map[string][]byte{
		target.Name + ".assay.json": []byte(assayOnlyDoc),
		target.Name + ".grype.json": sharedGrype,
	})
	var stdout, stderr bytes.Buffer
	args := append([]string{"-targets", targetsPath, "-offline", dir}, extra...)
	got := run(args, &stdout, &stderr, noExec(t))
	return got, stderr.String()
}

// Two of the seven findings count, both with fixState "fixed": pkg-fixed,
// and pkg-fixed-elsewhere, whose displayed evidence names no version because
// the record that won on severity had none while another of its ratings did
// (review wf_ae5d4af9-5a3; Finding.FixState reads every rating, Evidence only
// the winner). Not the no-fix states grype never reports, even one carrying a
// version; not "unknown"; not the tuple grype shares.
func TestRun_AssayOnlyFixedCountsOnlyUnsharedTuplesWithAFix(t *testing.T) {
	target := Target{Name: "ao-count", Ref: "unused", MaxFindings: 50, MaxAssayOnlyFixed: 1}
	got, stderr := runAssayOnly(t, target)
	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr)
	}
	if want := "breach: target=ao-count floor=maxAssayOnlyFixed want=<=1 got=2"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

func TestRun_AssayOnlyFixedAtItsCeilingHolds(t *testing.T) {
	target := Target{Name: "ao-held", Ref: "unused", MaxFindings: 50, MaxAssayOnlyFixed: 2}
	if got, stderr := runAssayOnly(t, target); got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr)
	}
}

// A ceiling, like maxFindings: it grows when an upstream publishes advisories
// grype has not picked up yet (alpaquita and liberica21's BELL batch, az2023's
// ALAS batch in 2026-10), which the candidate database cannot cause, so the
// publish gate reports it and the weekly run judges it.
func TestRun_RegressionsOnly_AssayOnlyFixedIsInfoNotBreach(t *testing.T) {
	target := Target{Name: "ao-gate", Ref: "unused", MaxFindings: 50, MaxAssayOnlyFixed: 1}
	got, stderr := runAssayOnly(t, target, "-regressions-only")
	if got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr)
	}
	if want := "info: target=ao-gate ceiling=maxAssayOnlyFixed want=<=1 got=2"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if strings.Contains(stderr, "breach:") {
		t.Errorf("stderr = %q: a ceiling must not breach the publish gate", stderr)
	}
}

func TestLoadTargets_MaxAssayOnlyFixedParsesAndRefusesNegative(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.json")
	os.WriteFile(ok, []byte(`[{"name":"n","ref":"r","maxAssayOnlyFixed":7}]`), 0o644)
	ts, err := loadTargets(ok)
	if err != nil || ts[0].MaxAssayOnlyFixed != 7 {
		t.Fatalf("loadTargets = %+v, %v; want maxAssayOnlyFixed 7", ts, err)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`[{"name":"n","ref":"r","maxAssayOnlyFixed":-1}]`), 0o644)
	if _, err := loadTargets(bad); err == nil || !strings.Contains(err.Error(), "maxAssayOnlyFixed") {
		t.Errorf("loadTargets(negative) err = %v, want a refusal naming maxAssayOnlyFixed", err)
	}
}

// Omitted means zero, and zero trips on the first assay-only tuple with a fix,
// so a target added without measuring its own count would breach the weekly
// run every time. Every committed target names the key on purpose.
func TestCommittedTargets_EverySeedsMaxAssayOnlyFixed(t *testing.T) {
	b, err := os.ReadFile("../../.github/scanner-diff-targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, o := range raw {
		if _, ok := o["maxAssayOnlyFixed"]; !ok {
			t.Errorf("target %s has no maxAssayOnlyFixed; seed it from a measured run (max(2x, x+25))", o["name"])
		}
	}
}
