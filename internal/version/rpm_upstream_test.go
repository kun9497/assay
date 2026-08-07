//go:build upstreamvectors

// This file checks the RPM comparer against the real rpm binary, which is a
// stronger oracle than any file: it is the implementation the ordering is
// defined by, not a transcription of it.
//
// Run it with:
//
//	go test -tags upstreamvectors ./internal/version/
//
// rpm's own vectors live in tests/rpmvercmp.at, an autotest file that is not
// distributed with the binary, so there is nothing to fetch. What there is
// instead, on any machine with rpm installed, is its embedded Lua interpreter:
// `rpm --eval '%{lua:print(rpm.vercmp(a, b))}'` calls rpmvercmp() itself. That
// is the better oracle anyway, and it costs no network at all.
package version

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestRPMAgainstUpstream replays every segment-ordering row and the
// tilde/caret chain through the real rpm and fails on any disagreement.
//
// Like the dpkg replay this has no known-divergence list and must not grow
// one. rpmvercmp has no fallback path and no undefined input: it orders any
// two byte strings, deterministically. So a disagreement here is a defect in
// this package, and there is no case where recording it and moving on is the
// honest answer.
func TestRPMAgainstUpstream(t *testing.T) {
	rpmBin, err := exec.LookPath("rpm")
	if err != nil {
		// Skipping is right for a developer without rpm and wrong for CI,
		// which is the only place this test runs at all: a skip there turns
		// the strongest check this comparer has into a no-op and still reports
		// green.
		requireCI(t, "rpm is not installed (%v)", err)
		return
	}

	// rpm's answer for one pair, via its own Lua binding.
	ask := func(a, b string) (int, error) {
		expr := fmt.Sprintf("%%{lua:print(rpm.vercmp('%s', '%s'))}", a, b)
		out, err := exec.Command(rpmBin, "--eval", expr).Output()
		if err != nil {
			return 0, fmt.Errorf("rpm --eval: %w", err)
		}
		s := strings.TrimSpace(string(out))
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("rpm printed %q, not a number", s)
		}
		return n, nil
	}

	// Probe before replaying anything. An rpm built without Lua, or one whose
	// binding is spelled differently, echoes the macro back unexpanded — and
	// a loop that treated every such answer as "cannot ask" would report
	// success having checked nothing.
	if n, err := ask("1.0", "2.0"); err != nil || n != -1 {
		t.Fatalf("rpm's Lua vercmp is not usable (got %d, %v); this test cannot run without it, "+
			"and skipping would report green on an unchecked comparer", n, err)
	}

	checked := 0
	check := func(a, b string) {
		t.Helper()
		// The Lua expression quotes both operands, so anything that could end
		// the string early would make rpm answer a question this test did not
		// ask. Refused rather than escaped: no real version contains either.
		if strings.ContainsAny(a+b, "'"+string(rune(92))) {
			t.Fatalf("cannot ask rpm about %q vs %q: quoting characters", a, b)
		}
		// The oracle is unambiguous only for strings with no epoch and no
		// release, because whether rpm's binding parses a full EVR differs
		// between releases. Asserted rather than trusted, so a later row that
		// broke the rule would fail here instead of silently comparing a
		// different thing.
		if strings.ContainsAny(a+b, ":-") {
			t.Fatalf("row %q vs %q carries an epoch or release separator; the upstream "+
				"replay only covers segment ordering", a, b)
		}
		want, err := ask(a, b)
		if err != nil {
			t.Fatalf("asking rpm about %q vs %q: %v", a, b, err)
		}
		got, err := RPM{}.Compare(a, b)
		if err != nil {
			t.Errorf("Compare(%q, %q) errored but rpm orders them (%d): %v", a, b, want, err)
			return
		}
		checked++
		if got != want {
			t.Errorf("MISMATCH Compare(%q, %q) = %d, rpm says %d", a, b, got, want)
		}
	}

	for _, tc := range rpmSegmentTests {
		check(tc.a, tc.b)
		check(tc.b, tc.a)
	}
	// Every pair of the tilde/caret chain, not only neighbours — the same
	// reason assertAscending checks them all.
	chain := []string{
		"1.0~~", "1.0~~a", "1.0~", "1.0~a", "1.0", "1.0^",
		"1.0^a", "1.0^1", "1.0a", "1.0.1", "1.01", "1.2",
	}
	for i := range chain {
		for j := range chain {
			check(chain[i], chain[j])
		}
	}

	// A run that checked almost nothing would otherwise pass. The floor is
	// well below the real count so that pruning a row or two from the table
	// does not fail the build for the wrong reason.
	if checked < 150 {
		t.Fatalf("only %d comparisons were checked against rpm; the oracle is not being exercised", checked)
	}
	t.Logf("%d comparisons agreed with rpm", checked)
}
