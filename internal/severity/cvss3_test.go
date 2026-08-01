package severity

import (
	"bufio"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Every distinct CVSS:3.x vector in the live database, scored by RedHat's
// `cvss` Python library. These are expected scores for our own data, not a
// transcription of someone's implementation — the vectors are what the
// database actually holds, and the scores are what an independent
// implementation says about them.
//
// The corpus is selected by the vector's own prefix, not by the record's
// declared type. 1180 distinct vectors: 925 at CVSS:3.1, 256 at CVSS:3.0,
// and one that the database files under CVSS_V4 while carrying a CVSS:3.1
// vector. That last one is why Of takes a vector and no type — selecting on
// the prefix picks it up, selecting on the label sends it to the v4 scorer.
// 30 of the vectors also carry temporal or environmental metrics.
func TestCVSS3AgainstReferenceScores(t *testing.T) {
	f, err := os.Open("testdata/v3-expected.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var n, mismatched int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		wantStr, vector, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("malformed corpus line %q", line)
		}
		want, err := strconv.ParseFloat(wantStr, 64)
		if err != nil {
			t.Fatalf("malformed corpus score %q: %v", wantStr, err)
		}
		n++

		got, err := scoreV3(vector)
		if err != nil {
			t.Errorf("scoreV3(%s): %v", vector, err)
			mismatched++
			continue
		}
		// Exact: both sides are one-decimal values, so any difference at
		// all is a real disagreement rather than float noise.
		if got != want {
			mismatched++
			// Report every mismatch rather than stopping at the first. A
			// systematic error in one metric shows up as a pattern across
			// the corpus, and the first line alone hides the pattern.
			if mismatched <= 25 {
				t.Errorf("scoreV3(%s) = %.1f, want %.1f", vector, got, want)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if mismatched > 25 {
		t.Errorf("... and %d further mismatches", mismatched-25)
	}
	// A corpus that silently shrank to nothing would let every assertion
	// above pass vacuously.
	if n < 1000 {
		t.Fatalf("corpus holds %d vectors, expected the full live set", n)
	}
	t.Logf("%d vectors, %d mismatches", n, mismatched)
}

// PR is the one metric in v3 whose weight depends on another metric. Fixing
// it at the S:U value is a silent under-score on every scope-changed vector
// with privileges required, which is a large share of the corpus.
func TestCVSS3_ScopeChangesThePRWeight(t *testing.T) {
	// Identical but for S, and PR:L is 0.62 unchanged vs 0.68 changed.
	unchanged, err := scoreV3("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := scoreV3("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != 8.8 {
		t.Errorf("S:U PR:L = %.1f, want 8.8", unchanged)
	}
	if changed != 9.9 {
		t.Errorf("S:C PR:L = %.1f, want 9.9", changed)
	}
	// PR:N is 0.85 under both scopes, so a scope-blind implementation still
	// agrees here. Stating it keeps a future "just use the S:C table"
	// simplification from passing the test above by accident.
	for _, v := range []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1},
	} {
		got, err := scoreV3(v.vector)
		if err != nil {
			t.Fatal(err)
		}
		if got != v.want {
			t.Errorf("scoreV3(%s) = %.1f, want %.1f", v.vector, got, v.want)
		}
	}
}

// The spec's roundup, not math.Round. It is defined as the smallest number to
// one decimal place that is not less than the input, and v3.1 gives it in
// integer arithmetic precisely because floating point makes the naive version
// disagree — on boundaries, which is exactly where bands change.
func TestRoundup(t *testing.T) {
	for _, tt := range []struct{ in, want float64 }{
		{0, 0},
		{4.0, 4.0},   // already on a boundary: must not climb to 4.1
		{4.01, 4.1},  // any excess at all rounds up...
		{4.02, 4.1},  // ...including where math.Round would go down
		{6.94, 7.0},  // math.Round gives 6.9 — a Medium that is really High
		{8.95, 9.0},  // the High/Critical boundary
		{10.0, 10.0}, // the cap must not become 10.1
	} {
		if got := roundup(tt.in); got != tt.want {
			t.Errorf("roundup(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
	// The case the spec's integer arithmetic exists for, and the reason
	// ceil(x*10)/10 is not good enough: 0.1+0.2 is held as
	// 0.30000000000000004, which ceil lifts to 0.4. Nothing in the v3 metric
	// space reaches such a value — over all 3888 base-metric combinations the
	// two definitions agree exactly — but v4's interpolation does arithmetic
	// with no such guarantee, and roundup is shared.
	//
	// Through variables, not literals: Go evaluates a constant expression
	// like `0.1 + 0.2` with arbitrary precision at compile time, yielding
	// exactly 0.3 and testing nothing. The slop only exists in float64.
	for _, tt := range []struct{ a, b, want float64 }{
		{0.1, 0.2, 0.3},   // 0.30000000000000004 - ceil gives 0.4
		{8.7, 0.2, 8.9},   // 8.899999999999999   - ceil gives 8.9 too, but
		{0.7, 0.1, 0.8},   // 0.7999999999999999
		{2.9, 0.1, 3.0},   // 3.0000000000000004  - ceil gives 3.1
		{1.005, 0.0, 1.1}, // and genuine excess still rounds up
	} {
		if got := roundup(tt.a + tt.b); got != tt.want {
			t.Errorf("roundup(%v+%v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}

	// The property, over the whole range this is used on: never less than
	// the input, never more than a tenth above it, always a tenth-multiple.
	for i := 0; i <= 10000; i++ {
		in := float64(i) / 1000
		got := roundup(in)
		if got < in-1e-9 {
			t.Fatalf("roundup(%v) = %v, which is below its input", in, got)
		}
		if got > in+0.1 {
			t.Fatalf("roundup(%v) = %v, more than a tenth above its input", in, got)
		}
		if math.Abs(got*10-math.Round(got*10)) > 1e-9 {
			t.Fatalf("roundup(%v) = %v, not a one-decimal value", in, got)
		}
	}
}

// Temporal and environmental metrics are present in the live data and are not
// malformedness. Banding uses the base score; rejecting the vector would drop
// a perfectly scorable finding into `unknown`, which is a false negative for
// any --fail-on threshold.
func TestCVSS3_IgnoresTemporalAndEnvironmentalMetrics(t *testing.T) {
	base := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
	want, err := scoreV3(base)
	if err != nil {
		t.Fatal(err)
	}
	// The shape a live record actually carries, plus a full environmental
	// set — none of which may move the base score.
	for _, extra := range []string{
		"/E:U/RL:O/RC:R",
		"/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
	} {
		got, err := scoreV3(base + extra)
		if err != nil {
			t.Errorf("scoreV3(%s): %v", base+extra, err)
			continue
		}
		if got != want {
			t.Errorf("scoreV3(base+%q) = %.1f, want the base score %.1f", extra, got, want)
		}
	}
}

// Seven points in the v3 metric space produce a raw score above 10 — every
// one of them scope-changed and fully impactful — and none of them is in the
// live corpus, so the corpus alone does not exercise the cap. 10.0 is the top
// of the scale by definition; a finding printed as 10.7 is visibly broken and
// sorts above findings that are equally maximal.
func TestCVSS3_ScoreIsCappedAtTen(t *testing.T) {
	// All seven, since they are few and they are the whole of the uncapped
	// region: every one is AV:N/AC:L/PR:N/UI:N/S:C, differing only in how the
	// impact is distributed. Raw scores run 10.42 to 10.73.
	for _, v := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",
	} {
		got, err := scoreV3(v)
		if err != nil {
			t.Fatal(err)
		}
		if got != 10.0 {
			t.Errorf("scoreV3(%s) = %.2f, want 10.0", v, got)
		}
	}
}

func TestCVSS3_Rejects(t *testing.T) {
	for _, tt := range []struct{ name, vector string }{
		{"empty", ""},
		{"not a vector", "nonsense"},
		{"a version we do not score", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		// The prefix has to be checked in its own right. This one carries a
		// complete and valid set of v3 base metrics, so every other guard in
		// the function passes it; only the version check rejects it. Without
		// that check a vector claiming a version whose formula differs would
		// be scored by v3's, quietly.
		{"v3 metrics under a version that is not v3", "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"a v4 vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"an invalid metric value", "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"a missing base metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{"a base metric given twice", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"an empty metric value", "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := scoreV3(tt.vector); err == nil {
				t.Errorf("scoreV3(%q) = %.1f, want an error", tt.vector, got)
			}
		})
	}
}

// Of is the package's front door: it picks the scorer from the vector string
// and hands back the band the verdict is built on.
func TestOf(t *testing.T) {
	// The mislabelled live record: a CVSS:3.1 vector filed as CVSS_V4. Of
	// takes no type parameter, so there is nothing for the label to corrupt.
	b, score, err := Of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
	if err != nil {
		t.Fatal(err)
	}
	// 6.5, verified against the reference: ISCbase .3916 -> impact 2.5140,
	// exploitability 3.8873, sum 6.4013, roundup 6.5. The plan wrote 6.4
	// from a hand calculation; the corpus disagreed, and the corpus is the
	// one with an independent implementation behind it.
	if b != Medium || score != 6.5 {
		t.Errorf("Of = %v/%.1f, want medium/6.5", b, score)
	}
	// A zero base score is `none`, a real band, and distinct from unrated.
	if b, score, err := Of("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"); err != nil ||
		b != None || score != 0 {
		t.Errorf("Of(all-none) = %v/%.1f/%v, want none/0.0/nil", b, score, err)
	}
}

func TestOf_UnparseableIsUnknown(t *testing.T) {
	for _, v := range []string{
		"",
		"nonsense",
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	} {
		b, score, err := Of(v)
		if err == nil {
			t.Errorf("Of(%q) returned no error", v)
		}
		if !errors.Is(err, ErrUnscorable) {
			t.Errorf("Of(%q) err = %v, want one wrapping ErrUnscorable", v, err)
		}
		if b != Unknown {
			t.Errorf("Of(%q) band = %v, want unknown", v, b)
		}
		if score != 0 {
			t.Errorf("Of(%q) score = %v, want 0", v, score)
		}
	}
}

// A record carrying several vectors is as severe as its worst rating. Taking
// the first would make the band depend on OSV's ordering within the record.
func TestHighest(t *testing.T) {
	b, score := Highest([]string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", // 6.5 medium
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 critical
		"garbage",
	})
	if b != Critical || score != 9.8 {
		t.Errorf("Highest = %v/%.1f, want critical/9.8", b, score)
	}
	// Order must not matter: the same set the other way round.
	if b, score := Highest([]string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
	}); b != Critical || score != 9.8 {
		t.Errorf("Highest(reversed) = %v/%.1f, want critical/9.8", b, score)
	}
	// The other side of that difference, and the one no test covered: a
	// record whose only vector genuinely rates 0.0 is None - "rated
	// harmless" - not Unknown. Ten of the 1180 live v3 vectors score 0.0, so
	// this is a real input, and the `best == Unknown ||` half of Highest's
	// comparison is the only thing that records the first of them. Without
	// this case, dropping that half leaves the whole suite green while
	// `--fail-on none` stops firing and `--fail-on-unknown` starts.
	if b, score := Highest([]string{"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"}); b != None || score != 0 {
		t.Errorf("Highest(a vector that rates 0.0) = %v/%.1f, want none/0", b, score)
	}

	// Nothing scorable is unknown, not none: "we could not tell" is not the
	// same claim as "rated zero", and D17 turns on the difference.
	for _, in := range [][]string{nil, {}, {"garbage", ""}} {
		if b, score := Highest(in); b != Unknown || score != 0 {
			t.Errorf("Highest(%v) = %v/%.1f, want unknown/0", in, b, score)
		}
	}
	// One unscorable vector must not suppress a scorable sibling.
	if b, _ := Highest([]string{"garbage", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}); b != Medium {
		t.Errorf("Highest(garbage, medium) = %v, want medium", b)
	}
}
