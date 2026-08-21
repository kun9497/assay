package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// lineIndex returns which output line first contains want, or -1. Used for the
// ordering assertions below, which cannot be made with Contains alone: a table
// printed in the wrong order contains every string it should.
func lineIndex(out, want string) int {
	for i, l := range strings.Split(out, "\n") {
		if strings.Contains(l, want) {
			return i
		}
	}
	return -1
}

// TestReportTimings_SlowestFirst is the property the whole table exists for.
// Run order is already in the log; this output is read to decide what to fix,
// and an unsorted table makes the reader do the sorting.
func TestReportTimings_SlowestFirst(t *testing.T) {
	var buf bytes.Buffer
	reportTimings(&buf, []stageTiming{
		{Kind: "provider", Name: "quick", Elapsed: 2 * time.Second, Records: 1},
		{Kind: "provider", Name: "slowest", Elapsed: 90 * time.Minute, Records: 2},
		{Kind: "enricher", Name: "middling", Elapsed: 10 * time.Minute, Records: 3},
	}, time.Now().Add(-100*time.Minute))
	out := buf.String()

	slow, mid, quick := lineIndex(out, "slowest"), lineIndex(out, "middling"), lineIndex(out, "quick")
	if slow < 0 || mid < 0 || quick < 0 {
		t.Fatalf("a stage is missing from the table:\n%s", out)
	}
	if !(slow < mid && mid < quick) {
		t.Errorf("rows are not slowest-first (slowest=%d middling=%d quick=%d):\n%s",
			slow, mid, quick, out)
	}
}

// TestReportTimings_FailedStageIsListedAndMarked. A provider that died after
// forty minutes is the row a reader most needs, and it is exactly the row a
// summary printed only on success would never show.
func TestReportTimings_FailedStageIsListedAndMarked(t *testing.T) {
	var buf bytes.Buffer
	reportTimings(&buf, []stageTiming{
		{Kind: "provider", Name: "died", Elapsed: 40 * time.Minute, Failed: true},
		{Kind: "provider", Name: "fine", Elapsed: time.Second},
	}, time.Now().Add(-41*time.Minute))
	out := buf.String()

	i := lineIndex(out, "died")
	if i < 0 {
		t.Fatalf("the failed stage is absent:\n%s", out)
	}
	row := strings.Split(out, "\n")[i]
	if !strings.Contains(row, "40m0s") {
		t.Errorf("the failed stage does not show how long it ran: %q", row)
	}
	if !strings.Contains(row, "failed") {
		t.Errorf("the failed stage is not marked, so it reads as a completed one: %q", row)
	}
	// And a successful neighbour is not marked, or the mark says nothing.
	if fine := strings.Split(out, "\n")[lineIndex(out, "fine")]; strings.Contains(fine, "failed") {
		t.Errorf("a successful stage is marked failed: %q", fine)
	}
}

// TestReportTimings_UnaccountedTimeIsNamed. A build whose stages sum to a
// fraction of its wall clock is saying the bottleneck is somewhere this table
// does not look. Left as a silent gap, that reads as the stages being the whole
// story.
func TestReportTimings_UnaccountedTimeIsNamed(t *testing.T) {
	var buf bytes.Buffer
	reportTimings(&buf, []stageTiming{
		{Kind: "provider", Name: "osv", Elapsed: 10 * time.Minute},
	}, time.Now().Add(-30*time.Minute))
	out := buf.String()
	if !strings.Contains(out, "everything else") {
		t.Errorf("20 minutes are unaccounted for and the table does not say so:\n%s", out)
	}
	if !strings.Contains(out, "20m0s") {
		t.Errorf("the unaccounted remainder is not quantified:\n%s", out)
	}
}

// TestReportTimings_NoRemainderRowWhenStagesAccountForEverything. The row is
// information, not decoration: printing "everything else 0s" on every build
// trains the reader to stop seeing it, which is the state the row is meant to
// break out of.
func TestReportTimings_NoRemainderRowWhenStagesAccountForEverything(t *testing.T) {
	var buf bytes.Buffer
	// Elapsed deliberately exceeds the wall clock, which is what a stage timed
	// across a clock adjustment looks like. The remainder is negative and must
	// not be rendered.
	reportTimings(&buf, []stageTiming{
		{Kind: "provider", Name: "osv", Elapsed: time.Hour},
	}, time.Now().Add(-time.Second))
	if out := buf.String(); strings.Contains(out, "everything else") {
		t.Errorf("a negative remainder was rendered:\n%s", out)
	}
}

// TestReportTimings_EmptyRunPrintsNothing. `db build` with no providers is a
// real invocation, and a bare "timing (0s total):" header with no rows under it
// is noise on every one of them.
func TestReportTimings_EmptyRunPrintsNothing(t *testing.T) {
	var buf bytes.Buffer
	reportTimings(&buf, nil, time.Now())
	if out := buf.String(); out != "" {
		t.Errorf("output = %q, want nothing for a run with no stages", out)
	}
}

// TestRoundDur pins the two regimes. This output is compared between runs, and
// microsecond precision on an hour-long stage is noise that makes two identical
// builds look different.
func TestRoundDur(t *testing.T) {
	for _, tt := range []struct {
		in   time.Duration
		want string
	}{
		{90*time.Minute + 400*time.Millisecond, "1h30m0s"},
		{61 * time.Second, "1m1s"},
		{time.Minute, "1m0s"},
		// Below a minute the millisecond matters: it is how a fast stage is
		// told apart from one that did nothing at all. Rounding is half away
		// from zero, which is Go's own Round and not worth diverging from.
		{2*time.Second + 400*time.Millisecond, "2.4s"},
		{1234 * time.Microsecond, "1ms"},
		{1500 * time.Microsecond, "2ms"},
		{0, "0s"},
	} {
		if got := roundDur(tt.in); got != tt.want {
			t.Errorf("roundDur(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// dyingProvider fails after emitting nothing, which is what a feed that goes
// away mid-fetch looks like from here.
type dyingProvider struct{ name string }

func (d dyingProvider) Name() string { return d.name }

func (d dyingProvider) Fetch(context.Context, func(advisory.Advisory) error) (store.Provenance, error) {
	return store.Provenance{}, errors.New("the feed went away")
}

// TestUpdate_ReportsTimingWhenAProviderFails is the claim D56 rests on, and
// nothing else holds it: a mutation removing BOTH failure-path calls to
// reportTimings left every other test in this package green.
//
// A build that dies after forty minutes is exactly when someone needs to know
// which stage ate the time, and a summary printed only on success is
// guaranteed to be missing from every run where it would have mattered.
func TestUpdate_ReportsTimingWhenAProviderFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	code := Update(context.Background(), path, "", "",
		false, []provider.Provider{dyingProvider{name: "doomed"}}, nil, nil, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("Update = %d, want 2 for a provider that failed", code)
	}
	s := errOut.String()
	if !strings.Contains(s, "timing (") {
		t.Errorf("a failed build printed no timing table:\n%s", s)
	}
	// And the row names the stage that died, marked — a table listing only
	// the stages that finished would be empty on exactly this run.
	//
	// Scoped to the lines AFTER the timing header. The first line mentioning
	// the provider is its own "fetching doomed…" progress line, and a search
	// over the whole output finds that instead — the substring collision
	// CLAUDE.md documents, met while writing the test for it.
	header := lineIndex(s, "timing (")
	table := strings.Join(strings.Split(s, "\n")[header:], "\n")
	i := lineIndex(table, "doomed")
	if i < 0 {
		t.Fatalf("the failed provider is absent from the table:\n%s", table)
	}
	if row := strings.Split(table, "\n")[i]; !strings.Contains(row, "failed") {
		t.Errorf("the failed provider is not marked: %q", row)
	}
}

// TestReportTimings_StoreSplitIsShownWhenMeasured is the row this table gained
// to answer a question its totals could not: OSV was 48m16s of a 50m51s build,
// and nothing in that number said whether to add concurrency or to batch the
// writes — opposite fixes, and concurrency makes a store-bound stage worse,
// because bolt permits one write transaction at a time.
//
// Both halves are printed rather than one plus a total, so the reader is not
// left subtracting to find the number that decides the work.
func TestReportTimings_StoreSplitIsShownWhenMeasured(t *testing.T) {
	var buf bytes.Buffer
	reportTimings(&buf, []stageTiming{
		{Kind: "provider", Name: "osv", Elapsed: 50 * time.Minute,
			Stored: 40 * time.Minute, Records: 149495},
	}, time.Now().Add(-51*time.Minute))
	out := buf.String()
	// 50 total, 40 in the store, so 10 fetching. A row showing only the total
	// or only one half would satisfy a Contains check on "osv".
	if !strings.Contains(out, "10m0s fetch") {
		t.Errorf("the fetch half is missing or wrong:"+ln+"%s", out)
	}
	if !strings.Contains(out, "40m0s store") {
		t.Errorf("the store half is missing or wrong:"+ln+"%s", out)
	}
}

// TestReportTimings_NoStoreSplitWhenNotMeasured. An annotator or enricher does
// not write through the emit callback this instruments, so its Stored is zero
// — and rendering "[0s fetch, 0s store]" on those rows would be a measurement
// nobody took, printed as though someone had.
func TestReportTimings_NoStoreSplitWhenNotMeasured(t *testing.T) {
	var buf bytes.Buffer
	reportTimings(&buf, []stageTiming{
		{Kind: "enricher", Name: "KISA", Elapsed: 2 * time.Minute, Records: 18552},
	}, time.Now().Add(-3*time.Minute))
	if out := buf.String(); strings.Contains(out, "store]") {
		t.Errorf("a split was rendered for a stage that never measured one:"+ln+"%s", out)
	}
}

// ln avoids writing a newline escape inside a generated string, which this
// project has lost three times in transit (CLAUDE.md).
const ln = string(rune(10))

// TestUpdate_ReportsTheStoreSplit is the wiring, and nothing else held it: a
// mutation dropping Stored from the row Update builds left every other test in
// this package green. reportTimings rendering a split correctly proves nothing
// if the value reaching it is always zero.
func TestUpdate_ReportsTheStoreSplit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	p := fakeProvider{
		name:   "fake",
		covers: []string{"Go"},
		advs: []advisory.Advisory{
			{ID: "GHSA-a", Affected: []advisory.Affected{{Ecosystem: "Go", Name: "x"}}},
			{ID: "GHSA-b", Affected: []advisory.Affected{{Ecosystem: "Go", Name: "y"}}},
		},
	}
	if code := Update(context.Background(), path, "", "",
		false, []provider.Provider{p}, nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := errOut.String()
	if !strings.Contains(s, "store]") {
		t.Errorf("the provider row carries no store split, so Update never "+
			"measured one:"+ln+"%s", s)
	}
}

// countingProvider emits n advisories and reports how many times the store was
// asked to write, by counting the batches its emit callback triggered.
type countingProvider struct {
	name string
	n    int
}

func (c countingProvider) Name() string { return c.name }

func (c countingProvider) Fetch(_ context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	for i := 0; i < c.n; i++ {
		a := advisory.Advisory{
			ID:       "GHSA-" + strconv.Itoa(i),
			Affected: []advisory.Affected{{Ecosystem: "Go", Name: "example.com/x"}},
		}
		if err := emit(a); err != nil {
			return store.Provenance{}, err
		}
	}
	return store.Provenance{Ecosystems: []string{"Go"}, Records: c.n}, nil
}

// TestUpdate_RecordsSurviveBatchBoundaries pins what a batched write can
// plausibly get wrong: an advisory dropped at the seam between two batches, or
// a tail shorter than putBatchSize never written at all. The fixture is two
// full batches plus a partial one for exactly that reason.
//
// It does NOT pin the mid-fetch flush, and the name says so because the first
// version of this test claimed to. A mutation removing that flush survives
// this and the rest of the suite, and it should: every record still lands via
// the tail. What the flush protects is the MEMORY BOUND — without it the
// caller's buffer grows to the whole corpus — and that is not observable
// through any seam this package exposes. Recorded here rather than covered by
// a test that cannot fail on its own subject.
func TestUpdate_RecordsSurviveBatchBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	// Two full batches and a partial one, so a single-flush implementation
	// and a correct one differ in how many times the store is entered.
	const n = putBatchSize*2 + 7
	if code := Update(context.Background(), path, "", "",
		false, []provider.Provider{countingProvider{name: "counter", n: n}}, nil, nil, nil,
		&out, &errOut); code != 0 {
		t.Fatalf("Update = %d (stderr: %s)", code, errOut.String())
	}
	// Every advisory landed, whichever way it was flushed.
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.Lookup("Go", "example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Errorf("Lookup = %d advisories, want %d — records were lost between"+
			" the batches", len(got), n)
	}
}
