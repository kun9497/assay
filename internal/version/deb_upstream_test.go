//go:build upstreamvectors

// This file checks the Deb comparer against the real dpkg binary, which is a
// stronger oracle than any file: it is the implementation the ordering is
// defined by, not a transcription of it.
//
// Run it with:
//
//	go test -tags upstreamvectors ./internal/version/
//
// dpkg ships no machine-readable vector file the way apk-tools does — its
// vectors live inside a Perl test module and a C unit test — so there is
// nothing to fetch. What there is instead, on every Debian or Ubuntu machine
// and on GitHub's ubuntu-latest runners, is `dpkg --compare-versions`. That is
// the better oracle anyway, and it costs no network at all.
package version

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestDebAgainstDpkg replays every row of debTests, plus the Policy chain,
// through the real dpkg and fails on any disagreement.
//
// Unlike the apk replay this has no known-divergence list, and it must not grow
// one. The apk comparer diverges from apk-tools deliberately, because apk falls
// back to a string sort for input it cannot parse and guessing an order is the
// wrong call for a scanner. dpkg has no such fallback: it either parses a
// version or refuses it. So any disagreement here is a defect in this package,
// and there is no case where the honest answer is to record it and move on.
func TestDebAgainstDpkg(t *testing.T) {
	dpkg, err := exec.LookPath("dpkg")
	if err != nil {
		// Skipping is right for a developer on a machine without dpkg and
		// wrong for CI, which is the only place this test runs at all: a skip
		// there turns the strongest check this comparer has into a no-op and
		// still reports green.
		requireCI(t, "dpkg is not installed (%v)", err)
		return
	}

	// dpkg's own answer for one pair, as -1/0/1. Asked as two questions rather
	// than one because `--compare-versions` is a predicate, not a comparator:
	// it exits 0 for true and 1 for false.
	compare := func(a, b string) (int, bool) {
		run := func(op string) (bool, bool) {
			err := exec.Command(dpkg, "--compare-versions", a, op, b).Run()
			if err == nil {
				return true, true
			}
			var ee *exec.ExitError
			if ok := asExitError(err, &ee); ok && ee.ExitCode() == 1 {
				return false, true
			}
			// Exit code 2 is dpkg refusing to parse one of the operands, which
			// is a real answer about the input rather than a failure to ask.
			return false, false
		}
		lt, ok := run("lt")
		if !ok {
			return 0, false
		}
		if lt {
			return -1, true
		}
		gt, ok := run("gt")
		if !ok {
			return 0, false
		}
		if gt {
			return 1, true
		}
		return 0, true
	}

	var c Deb
	checked, refusedByDpkg := 0, 0
	check := func(a, b string) {
		t.Helper()
		want, ok := compare(a, b)
		if !ok {
			// dpkg would not parse it. This package may legitimately be
			// stricter, so a refusal upstream is not evidence either way —
			// counted rather than asserted on.
			refusedByDpkg++
			return
		}
		got, err := c.Compare(a, b)
		if err != nil {
			t.Errorf("Compare(%q, %q) errored but dpkg orders them (%d): %v", a, b, want, err)
			return
		}
		checked++
		if got != want {
			t.Errorf("MISMATCH Compare(%q, %q) = %d, dpkg says %d", a, b, got, want)
		}
	}

	for _, tc := range debTests {
		check(tc.a, tc.b)
		check(tc.b, tc.a)
	}
	// Every pair of the Policy chain, not only neighbours — the same reason
	// assertAscending checks them all.
	chain := []string{
		"1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a", "1.0+",
		"1.0.1", "1.0.1-1", "1.0.1-1+b1", "1.0.1-1+deb11u1", "1.1", "1:0.1",
	}
	for i := range chain {
		for j := range chain {
			check(chain[i], chain[j])
		}
	}

	// A run that checked almost nothing would otherwise pass. The floor is well
	// below the real count so that pruning a row or two from debTests does not
	// fail the build for the wrong reason.
	if checked < 150 {
		t.Fatalf("only %d comparisons were checked against dpkg; the oracle is not "+
			"being exercised", checked)
	}
	t.Logf("%d comparisons agreed with dpkg; %d pairs dpkg would not parse", checked, refusedByDpkg)
}

// requireCI fails in CI and skips elsewhere. Extracted so both upstream replays
// state the same rule the same way: a check that can silently become a no-op is
// worse than one that is absent, because it is counted as coverage.
func requireCI(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format+" -- refusing to pass by skipping in CI", args...)
	}
	t.Skipf(format, args...)
}

// asExitError is errors.As, spelled out so the helper above reads without an
// import that exists for one call.
func asExitError(err error, target **exec.ExitError) bool { return errors.As(err, target) }
