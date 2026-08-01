package severity

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// replayV4Corpus checks every "score\tmacrovector\tvector" row in a file.
func replayV4Corpus(t *testing.T, path string, minRows int) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	seenMacro := map[string]bool{}
	var n, mismatched int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("malformed corpus line %q", line)
		}
		want, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			t.Fatalf("malformed corpus score %q: %v", fields[0], err)
		}
		wantMacro, vector := fields[1], fields[2]
		n++
		seenMacro[wantMacro] = true

		// The macrovector is checked separately from the score because they
		// fail differently. A wrong macrovector is a wrong equivalence class
		// — a whole region of the metric space misrouted — while a right
		// macrovector with a wrong score is the interpolation. Comparing only
		// the score leaves the two indistinguishable in the output.
		metrics := v4Metrics{}
		parsed, err := parseVector(vector, "CVSS:4.0")
		if err != nil {
			t.Errorf("parseVector(%s): %v", vector, err)
			mismatched++
			continue
		}
		metrics = parsed
		gotMacro, err := macroVector(metrics)
		if err != nil {
			t.Errorf("macroVector(%s): %v", vector, err)
			mismatched++
			continue
		}
		if gotMacro != wantMacro {
			mismatched++
			if mismatched <= 25 {
				t.Errorf("macroVector(%s) = %s, want %s", vector, gotMacro, wantMacro)
			}
			continue
		}

		got, err := scoreV4(vector)
		if err != nil {
			t.Errorf("scoreV4(%s): %v", vector, err)
			mismatched++
			continue
		}
		if got != want {
			mismatched++
			if mismatched <= 25 {
				t.Errorf("scoreV4(%s) [mv %s] = %.1f, want %.1f", vector, wantMacro, got, want)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if mismatched > 25 {
		t.Errorf("... and %d further mismatches", mismatched-25)
	}
	if n < minRows {
		t.Fatalf("%s holds %d vectors, want at least %d", path, n, minRows)
	}
	t.Logf("%s: %d vectors, %d macrovectors, %d mismatches", path, n, len(seenMacro), mismatched)
	return seenMacro
}

// Every distinct CVSS:4.0 vector in the live database, scored by FIRST's
// reference calculator. Selection is by the vector's own prefix, so the one
// record filing a CVSS:3.1 vector under CVSS_V4 is not in here — it belongs
// to the v3 corpus, which is the point of dispatching on the vector.
func TestCVSS4AgainstReferenceScores(t *testing.T) {
	replayV4Corpus(t, "testdata/v4-expected.tsv", 1384)
}

// The live corpus reaches only 78 of the 270 macrovectors. Interpolation is
// per-macrovector — different next-lower neighbours, different depths, and
// for EQ3/EQ6 a different branch of the "which way is down" logic — so the
// other 192 are code paths no live vector executes. This corpus is a
// deterministic sweep of the whole metric space, six vectors per macrovector,
// scored by the same reference.
//
// Building it took three attempts, each of which looked like it had worked:
// a seeded LCG whose multiply overflowed float64 and degenerated to 36
// macrovectors; enumerating SI:S / SA:S in the base metrics, which are not
// base values at all, leaving all 90 EQ4=0 macrovectors unreachable; and
// drawing one threat/environmental combination per base vector, which tied
// MSI:S to the VC/VI loop position and made 000000 — the top of the scale —
// unreachable. Only the printed coverage count showed any of it.
func TestCVSS4AcrossEveryMacrovector(t *testing.T) {
	seen := replayV4Corpus(t, "testdata/v4-sweep.tsv", 1620)
	if len(seen) != 270 {
		t.Errorf("sweep reaches %d macrovectors, want all 270", len(seen))
	}
	for mv := range cvssLookup {
		if !seen[mv] {
			t.Errorf("macrovector %s is in the lookup table but no test vector reaches it", mv)
		}
	}
}

// The lookup table is data the scorer cannot work without, and it is embedded
// rather than fetched (D14). If it ever ships truncated, every score silently
// changes rather than failing.
func TestLookupTableIsComplete(t *testing.T) {
	if len(cvssLookup) != 270 {
		t.Fatalf("lookup table has %d entries, want 270", len(cvssLookup))
	}
	if got := cvssLookup["000000"]; got != 10 {
		t.Errorf("the maximal macrovector scores %v, want 10", got)
	}
	if got := cvssLookup["212221"]; got != 0.1 {
		t.Errorf("the minimal macrovector scores %v, want 0.1", got)
	}
}

// One live vector ends in a separator with nothing after it. Rejecting it
// turns a scorable finding into an unrated one: the metrics before it are
// complete and unambiguous.
func TestCVSS4_ToleratesATrailingSeparator(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
	want, err := scoreV4(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := scoreV4(base + "/")
	if err != nil {
		t.Fatalf("scoreV4 with a trailing separator: %v", err)
	}
	if got != want {
		t.Errorf("trailing separator changed the score: %.1f vs %.1f", got, want)
	}
}

// Absent threat and environmental metrics default to their WORST case, not a
// neutral one: E:X is E:A, and CR/IR/AR:X are H. Nearly every stored vector is
// base-only, so this path decides the score for almost all real data —
// defaulting the other way would under-score the entire database at once.
func TestCVSS4_AbsentMetricsDefaultToTheWorstCase(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	bare, err := scoreV4(base)
	if err != nil {
		t.Fatal(err)
	}
	spelled, err := scoreV4(base + "/E:A/CR:H/IR:H/AR:H")
	if err != nil {
		t.Fatal(err)
	}
	if bare != spelled {
		t.Errorf("omitting E/CR/IR/AR scored %.1f, spelling out the worst case scored %.1f", bare, spelled)
	}
	// And the defaults are the worst case, so naming a lesser value can only
	// lower the score.
	lower, err := scoreV4(base + "/E:U")
	if err != nil {
		t.Fatal(err)
	}
	if lower >= bare {
		t.Errorf("E:U scored %.1f, not below the E:X default of %.1f", lower, bare)
	}
}

// A vector with no impact anywhere scores 0.0 by an explicit shortcut, before
// any table lookup. Without it the macrovector path produces a nonzero score
// for a vulnerability that does nothing.
func TestCVSS4_NoImpactIsZero(t *testing.T) {
	got, err := scoreV4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("scoreV4(no impact) = %.1f, want 0", got)
	}
	if b, score, err := Of("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"); err != nil ||
		b != None || score != 0 {
		t.Errorf("Of(no impact) = %v/%.1f/%v, want none/0/nil", b, score, err)
	}
}

// EQ4=0 is defined on MSI:S / MSA:S — Safety is a modified subsequent metric,
// and there is no base SI:S. Reading it off the base metric instead makes 90
// of the 270 macrovectors unreachable, every one of them the most severe
// EQ4 class, so the error is always downward.
func TestCVSS4_SafetyIsAModifiedMetric(t *testing.T) {
	// Deliberately not a maximal vector: with AV:N/AC:L/PR:N/UI:N and full
	// impact the score caps at 10.0 either way, and the assertion below
	// passes on two clamped values rather than on the metric.
	const base = "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H"
	metrics, err := parseVector(base, "CVSS:4.0")
	if err != nil {
		t.Fatal(err)
	}
	if mv, _ := macroVector(metrics); mv[3] != '1' {
		t.Errorf("macroVector(%s) EQ4 = %c, want 1", base, mv[3])
	}
	safety, err := parseVector(base+"/MSI:S", "CVSS:4.0")
	if err != nil {
		t.Fatal(err)
	}
	if mv, _ := macroVector(safety); mv[3] != '0' {
		t.Errorf("macroVector(... MSI:S) EQ4 = %c, want 0", mv[3])
	}
	withSafety, err := scoreV4(base + "/MSI:S")
	if err != nil {
		t.Fatal(err)
	}
	without, err := scoreV4(base)
	if err != nil {
		t.Fatal(err)
	}
	if withSafety <= without {
		t.Errorf("MSI:S scored %.1f, not above %.1f - safety impact must raise it", withSafety, without)
	}
}

// v4 rounds to nearest, v3 rounds up. They are different specifications and
// the reference implementation is the authority for each.
//
// This is not asserted on a hand-picked vector: whether the two disagree
// depends on the pre-rounding value, which is internal. The corpus tests
// carry it - swapping math.Round for roundup turns them red on 262 of the
// 3004 vectors, each one shifted up by a tenth, and some across a band
// boundary. Verified as a mutation, recorded here so the next reader knows
// where the guard lives.

func TestCVSS4_Rejects(t *testing.T) {
	for _, tt := range []struct{ name, vector string }{
		{"empty", ""},
		{"not a vector", "nonsense"},
		{"a v3 vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"a version we do not score", "CVSS:5.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"a missing base metric", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"},
		{"an invalid base value", "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"an invalid threat value", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z"},
		{"an invalid environmental value", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:Z"},
		{"a base metric given twice", "CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := scoreV4(tt.vector); err == nil {
				t.Errorf("scoreV4(%q) = %.1f, want an error", tt.vector, got)
			}
		})
	}
}

// Supplemental metrics carry no score and must not be treated as unknown
// values. They are present in the live data.
func TestCVSS4_IgnoresSupplementalMetrics(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	want, err := scoreV4(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := scoreV4(base + "/S:P/AU:Y/R:A/V:D/RE:L/U:Red")
	if err != nil {
		t.Fatalf("scoreV4 with supplemental metrics: %v", err)
	}
	if got != want {
		t.Errorf("supplemental metrics moved the score: %.1f vs %.1f", got, want)
	}
}

// Of routes v4 vectors to the v4 scorer, and the two live CVSS_V4 findings on
// the Alpine image go through this path.
func TestOf_ScoresV4(t *testing.T) {
	b, score, err := Of("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if err != nil {
		t.Fatal(err)
	}
	if b != Critical || score != 10.0 {
		t.Errorf("Of(maximal v4) = %v/%.1f, want critical/10.0", b, score)
	}
}
