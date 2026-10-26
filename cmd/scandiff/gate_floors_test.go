package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// incompleteDoc is assayDoc with the two incompleteness counters the gate
// read nothing of before A17 (2026-10-22 audit): a candidate database whose
// advisory bounds stopped parsing reports every check incomplete and no
// finding, and nothing else in the document moves.
func incompleteDoc(incompleteChecks, targetIncomplete int) []byte {
	b, _ := json.Marshal(assayDocument{
		SchemaVersion: 8,
		Summary:       assaySummary{IncompleteChecks: incompleteChecks, TargetIncomplete: targetIncomplete},
	})
	return b
}

func runOfflineGate(t *testing.T, target Target, assayBytes []byte) (int, string) {
	t.Helper()
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	writeOffline(t, dir, map[string][]byte{
		target.Name + ".assay.json": assayBytes,
		target.Name + ".grype.json": grypeDoc(nil),
	})
	var stdout, stderr bytes.Buffer
	got := run([]string{"-targets", targetsPath, "-offline", dir, "-regressions-only"}, &stdout, &stderr, noExec(t))
	return got, stderr.String()
}

func TestRun_RegressionsOnly_IncompleteChecksGrowthBreaches(t *testing.T) {
	target := Target{Name: "inc-up", Ref: "unused", MaxFindings: 50, MaxIncompleteChecks: 1}
	got, stderr := runOfflineGate(t, target, incompleteDoc(2, 0))
	if got != exitFindings {
		t.Fatalf("exit = %d, want %d -- incomplete checks are a regression floor (stderr=%q)", got, exitFindings, stderr)
	}
	if want := "breach: target=inc-up floor=maxIncompleteChecks want=<=1 got=2"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

func TestRun_IncompleteChecksWithinAllowanceHolds(t *testing.T) {
	target := Target{Name: "inc-held", Ref: "unused", MaxFindings: 50, MaxIncompleteChecks: 1}
	got, stderr := runOfflineGate(t, target, incompleteDoc(1, 0))
	if got != exitOK {
		t.Fatalf("exit = %d, want %d -- one incomplete check is this target's measured allowance (stderr=%q)", got, exitOK, stderr)
	}
}

func TestRun_RegressionsOnly_TargetIncompleteWhereFloorIsZeroBreaches(t *testing.T) {
	// incompleteChecks held at its allowance so only targetIncomplete can trip:
	// the two are counted separately (report.Summary: targetIncomplete is a
	// subtotal of neither notEvaluated nor incompleteChecks).
	target := Target{Name: "tinc-zero", Ref: "unused", MaxFindings: 50, MaxIncompleteChecks: 3}
	got, stderr := runOfflineGate(t, target, incompleteDoc(3, 1))
	if got != exitFindings {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitFindings, stderr)
	}
	if want := "breach: target=tinc-zero floor=maxTargetIncomplete want=<=0 got=1"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if strings.Contains(stderr, "floor=maxIncompleteChecks") {
		t.Errorf("stderr = %q: incompleteChecks 3 is within its allowance of 3", stderr)
	}
}

func TestRun_TargetIncompleteWithinAllowanceHolds(t *testing.T) {
	target := Target{Name: "tinc-held", Ref: "unused", MaxFindings: 50, MaxTargetIncomplete: 2}
	got, stderr := runOfflineGate(t, target, incompleteDoc(0, 2))
	if got != exitOK {
		t.Fatalf("exit = %d, want %d (stderr=%q)", got, exitOK, stderr)
	}
}

// TestCommittedTargets_LosingEveryMatchBreaches is A8's reproduction against
// the floors file CI actually reads: a candidate that still catalogs the image
// but lost every match must trip something on every target. az2023 and wolfi
// carried minAgree 0 / minFindings 0 from the 2026-08-28 seeding, so a
// database that matched nothing on Amazon Linux 2023 or Wolfi passed the D114
// gate and the weekly run with "ok".
//
// Components are set far above any minComponents so that floor cannot stand
// in for the agreement and finding floors this test is about, and trivy
// blocks are dropped so a trivy floor cannot either.
func TestCommittedTargets_LosingEveryMatchBreaches(t *testing.T) {
	// The one target whose honest finding count is zero: its floor is
	// minComponents (see Target.MinComponents), which this test deliberately
	// holds, so losing every match is indistinguishable there from being clean.
	exempt := map[string]bool{"cleanstart-postgres": true}

	targets, err := loadTargets("../../.github/scanner-diff-targets.json")
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := json.Marshal(assayDocument{SchemaVersion: 8, Summary: assaySummary{Components: 1 << 20}})
	for _, tg := range targets {
		if exempt[tg.Name] {
			continue
		}
		tg.Trivy = nil
		got, stderr := runOfflineGate(t, tg, empty)
		if got != exitFindings {
			t.Errorf("%s: exit = %d with every match lost, want %d (minAgree=%d minFindings=%d; stderr=%q)",
				tg.Name, got, exitFindings, tg.MinAgree, tg.MinFindings, stderr)
		}
	}
}

// The two tests above build both documents from this package's own structs,
// so a misspelled JSON tag would round-trip and stay green. These read the
// spellings the real producers write: assay's report.Summary and the floors
// file a human edits.
func TestRun_IncompleteCountersReadFromAssaySpelling(t *testing.T) {
	target := Target{Name: "inc-literal", Ref: "unused", MaxFindings: 50}
	doc := []byte(`{"schemaVersion":8,"findings":[],"summary":{"incompleteChecks":2,"targetIncomplete":1}}`)
	_, stderr := runOfflineGate(t, target, doc)
	for _, want := range []string{
		"breach: target=inc-literal floor=maxIncompleteChecks want=<=0 got=2",
		"breach: target=inc-literal floor=maxTargetIncomplete want=<=0 got=1",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
}

func TestLoadTargets_IncompleteAllowancesParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	body := `[{"name":"n","ref":"r","maxIncompleteChecks":3,"maxTargetIncomplete":4}]`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ts, err := loadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	if ts[0].MaxIncompleteChecks != 3 || ts[0].MaxTargetIncomplete != 4 {
		t.Errorf("parsed %+v, want maxIncompleteChecks 3 and maxTargetIncomplete 4", ts[0])
	}
}
