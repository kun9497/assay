package nvd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// windowLineFor runs one whole Annotate against a stub that answers every
// window with a single rated record, and returns the FIRST line written to
// Options.Progress. First, not "some line containing": the window line is the
// evidence a post-merge log check reads before anything else, so a version of
// it emitted after the paging output - or only on the error path - is a
// failure, not a formatting difference.
func windowLineFor(t *testing.T, now time.Time, since time.Time, seed store.Provenance) string {
	t.Helper()
	oldNow := nowUTC
	nowUTC = func() time.Time { return now }
	t.Cleanup(func() { nowUTC = oldNow })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1,"timestamp":"2026-09-21T00:00:01.000","vulnerabilities":[{"cve":{"id":"CVE-2026-0001","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
	}))
	t.Cleanup(srv.Close)
	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, Since: since, Pause: durPtr(0), Progress: &progress})
	if err := p.ResumeFrom(seed); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}
	line, _, ok := strings.Cut(progress.String(), string(rune(10)))
	if !ok {
		t.Fatalf("no progress line written: %q", progress.String())
	}
	return line
}

// A widened delta says so, names the seed field it was widened from, and
// reports the configured start it displaced. Without the origin phrase a
// nightly log shows a window that simply looks wrong; with it, the log proves
// which branch of the resume logic ran.
func TestAnnotate_WindowLine_WidenedFromCoversUntil(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	since := now.Add(-3 * 24 * time.Hour)
	seed := store.Provenance{CoversUntil: now.Add(-10 * 24 * time.Hour), CoversUntilKnown: true}
	got := windowLineFor(t, now, since, seed)
	want := "nvd: requesting modified 2026-09-10..2026-09-21 in 1 window(s) of at most 120 days -- " +
		"start widened to the seed's recorded request end (CoversUntil) minus 24h; configured start was 2026-09-18"
	if got != want {
		t.Fatalf("window line\n got: %s\nwant: %s", got, want)
	}
}

// A checkpoint that is NEWER than the configured start changes nothing, and
// the line has to say that too: "resume ran and had nothing to widen" and
// "resume never ran" produce the same window, and only the origin phrase
// tells them apart in a log.
func TestAnnotate_WindowLine_ConfiguredStartKept(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	since := now.Add(-3 * 24 * time.Hour)
	seed := store.Provenance{CoversUntil: now.Add(-24 * time.Hour), CoversUntilKnown: true}
	got := windowLineFor(t, now, since, seed)
	want := "nvd: requesting modified 2026-09-18..2026-09-21 in 1 window(s) of at most 120 days -- " +
		"configured start kept; the seed's recorded request end (CoversUntil) minus 24h (2026-09-19) is not earlier"
	if got != want {
		t.Fatalf("window line\n got: %s\nwant: %s", got, want)
	}
}

// A legacy seed names the field it really came from. The two sources widen by
// the same 24h, so the dates alone cannot show that the fallback was taken -
// which is the whole question when an old artifact resumes badly.
func TestAnnotate_WindowLine_WidenedFromLegacyDataAsOf(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	since := now.Add(-3 * 24 * time.Hour)
	seed := store.Provenance{DataAsOf: now.Add(-10 * 24 * time.Hour)}
	got := windowLineFor(t, now, since, seed)
	want := "nvd: requesting modified 2026-09-10..2026-09-21 in 1 window(s) of at most 120 days -- " +
		"start widened to the seed's legacy response timestamp (DataAsOf) minus 24h; configured start was 2026-09-18"
	if got != want {
		t.Fatalf("window line\n got: %s\nwant: %s", got, want)
	}
}

// A clamped start says it was clamped. This is the one origin a reader is
// most likely to mistake for an operator error -- the log shows a start date
// nobody configured -- and the clamp is only safe BECAUSE it is disclosed
// (see Annotate's comment on maxWindow). The count matters as much as the
// phrase: clamping shrinks the span to exactly the maximum, so it must come
// out as one window, never two.
func TestAnnotate_WindowLine_ClampedToNVDsMaximum(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	since := now.Add(-200 * 24 * time.Hour)
	got := windowLineFor(t, now, since, store.Provenance{})
	// Asserted as a suffix rather than a Contains, so a longer origin phrase
	// that merely starts this way cannot satisfy it.
	want := "in 1 window(s) of at most 120 days -- configured start clamped to NVD's 120-day maximum"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("window line\n got: %s\nwant suffix: %s", got, want)
	}
	// ...and the window it names is the clamped one, not the 200-day range
	// that was asked for. Without this the line could disclose the clamp in
	// words while reporting coverage the run does not have.
	if bad := since.UTC().Format("2006-01-02"); strings.Contains(got, bad) {
		t.Fatalf("window line names the unhonoured configured start %s: %s", bad, got)
	}
}

// The ordinary nightly delta: no seed to widen from, nothing to clamp. It
// still announces its origin, because "configured start" is what makes the
// other four phrases meaningful -- a line that said nothing here would leave
// a reader unable to tell an un-widened run from an older binary that had no
// origin phrase at all.
func TestAnnotate_WindowLine_PlainConfiguredStart(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	since := now.Add(-3 * 24 * time.Hour)
	got := windowLineFor(t, now, since, store.Provenance{})
	want := "in 1 window(s) of at most 120 days -- configured start"
	// A suffix, so "configured start kept; ..." or "configured start clamped
	// to ..." cannot pass as this case: the whole point of this row is the
	// SHORT phrase, and Contains would accept either longer one.
	if !strings.HasSuffix(got, want) {
		t.Fatalf("window line\n got: %s\nwant suffix: %s", got, want)
	}
	// Stated separately as well, because the suffix check above is about
	// shape and these three words are about meaning: this run neither
	// resumed nor was narrowed, and saying either would be a false claim
	// about what was requested.
	for _, bad := range []string{"kept", "widened", "clamped"} {
		if strings.Contains(got, bad) {
			t.Fatalf("window line claims %q on a plain configured start: %s", bad, got)
		}
	}
}

// The whole feed is the seven-hour run. It is announced with the same line as
// every other origin so a log reader never has to infer it from an absence --
// a missing start date reads exactly like an unbounded one, and those are the
// two runs it is most expensive to confuse.
func TestAnnotate_WindowLine_WholeFeed(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	got := windowLineFor(t, now, time.Time{}, store.Provenance{})
	want := "nvd: requesting the whole feed in 1 window(s) of at most 120 days -- whole feed"
	if got != want {
		t.Fatalf("window line\n got: %s\nwant: %s", got, want)
	}
}

func TestAnnotate_ResumesAcrossMultipleAPIWindows(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	oldNow := nowUTC
	nowUTC = func() time.Time { return now }
	t.Cleanup(func() { nowUTC = oldNow })
	checkpoint := now.Add(-250 * 24 * time.Hour)
	var starts, ends []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, e1 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("lastModStartDate"))
		end, e2 := time.Parse(time.RFC3339Nano, r.URL.Query().Get("lastModEndDate"))
		if e1 != nil || e2 != nil {
			t.Error("missing/invalid bounds")
			w.WriteHeader(400)
			return
		}
		if end.Sub(start) > maxWindow {
			t.Error("API window exceeds 120 days")
		}
		if r.URL.Query().Get("startIndex") != "0" {
			t.Error("pagination not reset between windows")
		}
		starts, ends = append(starts, start), append(ends, end)
		fmt.Fprintf(w, `{"totalResults":1,"timestamp":"2026-09-21T00:00:01.000","vulnerabilities":[{"cve":{"id":"CVE-2026-%d","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`, len(starts))
	}))
	defer srv.Close()
	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, Since: now.Add(-3 * 24 * time.Hour), Pause: durPtr(0), Progress: &progress})
	if err := p.ResumeFrom(store.Provenance{CoversUntil: checkpoint, CoversUntilKnown: true}); err != nil {
		t.Fatal(err)
	}
	var ratings []advisory.Rating
	got, err := p.Annotate(context.Background(), func(r advisory.Rating) error { ratings = append(ratings, r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(starts) != 3 || len(ratings) != 3 || got.Records != 3 {
		t.Fatalf("windows=%d ratings=%d provenance=%+v", len(starts), len(ratings), got)
	}
	if !starts[0].Equal(checkpoint.Add(-24*time.Hour)) || !ends[2].Equal(now) {
		t.Fatalf("incorrect resume span: %v..%v", starts[0], ends[2])
	}
	for i := 1; i < len(starts); i++ {
		if !starts[i].Equal(ends[i-1]) {
			t.Fatal("gap between requests")
		}
	}
	if !got.CoversSince.Equal(starts[0]) || !got.CoversUntil.Equal(now) || !got.CoversUntilKnown {
		t.Fatalf("incorrect checkpoint: %+v", got)
	}
	// The announced split has to match the split that just happened above:
	// this is the one case where the count is not 1, so a window line that
	// simply hard-coded a single window would pass every other test.
	line, _, _ := strings.Cut(progress.String(), string(rune(10)))
	want := "nvd: requesting modified 2026-01-13..2026-09-21 in 3 window(s) of at most 120 days -- " +
		"start widened to the seed's recorded request end (CoversUntil) minus 24h; configured start was 2026-09-18"
	// len(starts) == 3 is asserted above, so the two together tie the
	// announced count to the number of requests actually made.
	if line != want {
		t.Fatalf("window line\n got: %s\nwant: %s", line, want)
	}
}

func TestResumeFrom_LegacyAndExplicitBackfill(t *testing.T) {
	now := time.Now().UTC()
	seed := store.Provenance{DataAsOf: now.Add(-10 * 24 * time.Hour), CoversSinceKnown: true}
	p := New(Options{Since: now.Add(-3 * 24 * time.Hour)})
	if err := p.ResumeFrom(seed); err != nil {
		t.Fatal(err)
	}
	if !p.resumeSince.Equal(seed.DataAsOf.Add(-24 * time.Hour)) {
		t.Fatal("legacy timestamp not used")
	}
	p.until = now.Add(-120 * 24 * time.Hour)
	if err := p.ResumeFrom(seed); err != nil {
		t.Fatal(err)
	}
	if !p.resumeSince.IsZero() {
		t.Fatal("explicit backfill was widened")
	}
	p.until = time.Time{}
	if err := p.ResumeFrom(store.Provenance{CoversSinceKnown: true}); err == nil {
		t.Fatal("unknown seed checkpoint accepted")
	}
}

func TestAnnotate_ResumeFailureDoesNotClaimCoverage(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		io.WriteString(w, `{"totalResults":0,"timestamp":"2026-09-21T00:00:00.000","vulnerabilities":[]}`)
	}))
	defer srv.Close()
	p := New(Options{BaseURL: srv.URL, Since: now.Add(-3 * 24 * time.Hour), Pause: durPtr(0)})
	if err := p.ResumeFrom(store.Provenance{CoversUntil: now.Add(-150 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil || got.CoversSinceKnown || got.CoversUntilKnown || calls != 2 {
		t.Fatalf("partial resume accepted: calls=%d prov=%+v err=%v", calls, got, err)
	}
}
