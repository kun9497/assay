package version

import "testing"

// lineSep is a newline, assembled rather than typed. CLAUDE.md records the
// hazard and it fired four times in the session that added these tests: a
// literal escape written into a file by a generator collapses into the byte it
// denotes, and the file stops compiling.
var lineSep = string(rune(10))

// The ordered chains the two specifications publish in their own text.
//
// These are here because the alternative was worse. Neither specification ships
// machine-readable test data — semver/semver is eleven files and none is a
// fixture, and PEP 440 is prose — so the choice was between transcribing eleven
// and thirteen strings that have not changed since 2013 and 2014, or scraping
// markdown and reStructuredText at test time. Transcription wins outright: the
// chains cannot drift, and an offline table runs in the default suite where the
// network-gated replays do not.
//
// Every adjacent pair AND every non-adjacent pair is checked, so a chain of n
// strings yields n(n-1)/2 comparisons rather than n-1. That is where the value
// is: a comparer can get neighbours right and transitivity wrong.

// semverSpecChain is semver.org §11.2, §11.3 and §11.4, joined through 1.0.0
// into one total order. Verbatim from semver.md:
//
//	§11.2  Example: 1.0.0 < 2.0.0 < 2.1.0 < 2.1.1.
//	§11.3  Example: 1.0.0-alpha < 1.0.0.
//	§11.4  Example: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta <
//	                1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 <
//	                1.0.0.
var semverSpecChain = []string{
	"1.0.0-alpha",
	"1.0.0-alpha.1",
	"1.0.0-alpha.beta",
	"1.0.0-beta",
	"1.0.0-beta.2",
	"1.0.0-beta.11", // 11 > 2 numerically; the pair a lexical comparer inverts
	"1.0.0-rc.1",
	"1.0.0",
	"2.0.0",
	"2.1.0",
	"2.1.1",
}

func TestSemVer_SpecChain(t *testing.T) {
	assertAscending(t, SemVer{}, semverSpecChain, "semver.org §11")
}

// pep440SpecChain is PEP 440's own ordering, drawn from its "Summary of
// permitted suffixes and relative ordering" and the epoch section. Every
// element is a strictly later version than the one before it.
//
// The dev/pre/post/final ordering is the half a hand-written table is most
// likely to get subtly wrong, and it is the half PEP 440 states most
// explicitly: .devN sorts before everything at the same release, a pre-release
// before the final, and .postN after it.
var pep440SpecChain = []string{
	"1.0.dev456",
	"1.0a1",
	"1.0a2.dev456",
	"1.0a12.dev456",
	"1.0a12", // 12 > 2 numerically; a lexical comparer puts 1.0a12 below 1.0a2
	"1.0b1.dev456",
	"1.0b2",
	"1.0b2.post345.dev456",
	"1.0b2.post345",
	"1.0rc1.dev456",
	"1.0rc1",
	"1.0",
	"1.0.post456.dev34",
	"1.0.post456",
	"1.0.1",
	"1.1.dev1",
	// An epoch outranks every version without one, however large. This is the
	// pair the packaging corpus covers well and prose alone covers badly.
	"1!1.0",
}

func TestPEP440_SpecChain(t *testing.T) {
	assertAscending(t, PEP440{}, pep440SpecChain, "PEP 440")
}

// assertAscending checks every ordered pair in a chain, not only neighbours.
//
// Neighbours alone would let a comparer that is right locally and wrong
// transitively pass — and transitivity is exactly what a range walk depends on,
// because InRange sorts events before deciding whether a version sits inside a
// window.
func assertAscending(t *testing.T, c Comparer, chain []string, source string) {
	t.Helper()
	pairs := 0
	for i := range chain {
		// Every version equals itself. A comparer that errors here cannot
		// order anything, and it is worth one assertion rather than being
		// inferred from the pairs below.
		if got, err := c.Compare(chain[i], chain[i]); err != nil || got != 0 {
			t.Errorf("%s: Compare(%q, %q) = %d, %v; want 0, nil", source, chain[i], chain[i], got, err)
		}
		for j := i + 1; j < len(chain); j++ {
			lo, hi := chain[i], chain[j]
			pairs++
			got, err := c.Compare(lo, hi)
			if err != nil {
				t.Errorf("%s: Compare(%q, %q): %v", source, lo, hi, err)
				continue
			}
			if got != -1 {
				t.Errorf("%s: Compare(%q, %q) = %d, want -1 — the specification "+
					"lists %q before %q", source, lo, hi, got, lo, hi)
			}
			// Antisymmetry, checked here rather than in its own test: a
			// comparer that returns -1 both ways would satisfy every assertion
			// above and order nothing.
			if rev, err := c.Compare(hi, lo); err != nil || rev != 1 {
				t.Errorf("%s: Compare(%q, %q) = %d, %v; want 1, nil (antisymmetry)",
					source, hi, lo, rev, err)
			}
		}
	}
	// A chain that lost its entries would otherwise pass by checking nothing.
	if pairs < 50 {
		t.Fatalf("%s: only %d pairs checked; the chain has been truncated", source, pairs)
	}
	t.Logf("%s: %d ordered pairs", source, pairs)
}
