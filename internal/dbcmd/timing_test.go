package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
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
		[]provider.Provider{dyingProvider{name: "doomed"}}, nil, nil, &out, &errOut)
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
