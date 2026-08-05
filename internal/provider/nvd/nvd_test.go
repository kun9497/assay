package nvd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// durPtr takes the address of a duration literal, for Options.Pause: a
// *time.Duration cannot be constructed with & directly against a literal or
// a constant expression.
func durPtr(d time.Duration) *time.Duration { return &d }

// New resolves Options.Pause without ever sleeping: a nil Pause gets the
// rate-limit default (6.5s unauthenticated, 0.65s with a key), and a set
// Pause - including an explicit zero - is used exactly as given. Asserted on
// the resolved field rather than on elapsed time, so this stays fast and
// deterministic: a wall-clock version of this test would either sleep for
// real or not test the default at all.
func TestNew_ResolvesPause(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want time.Duration
	}{
		{"nil Pause, no key: the unauthenticated rate-limit default", Options{}, defaultPause},
		{"nil Pause, with a key: the authenticated rate-limit default", Options{APIKey: "k"}, defaultPauseWithKey},
		{"an explicit zero Pause is honoured, not defaulted", Options{Pause: durPtr(0)}, 0},
		{"an explicit non-default Pause is honoured verbatim", Options{Pause: durPtr(3 * time.Second)}, 3 * time.Second},
		{"an explicit Pause wins even with a key set", Options{APIKey: "k", Pause: durPtr(9 * time.Second)}, 9 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.opts)
			if p.pause != tc.want {
				t.Errorf("pause = %v, want %v", p.pause, tc.want)
			}
		})
	}
}

// The client is bounded.
//
// Held here rather than by the two timeout tests below, which set
// p.client.Timeout themselves and so pass against a client that ships with
// none. An unbounded client turns a stalled page into a sync that hangs
// forever, and the retry schedule -- the thing this file spends twelve
// minutes of budget on -- never gets its chance to fire, because nothing
// ever returns an error for it to judge. That is the defect
// TestRetryable_JudgesTheCallersContextNotTheError repairs, one layer up.
func TestNew_TheClientIsBounded(t *testing.T) {
	p := New(Options{})
	if p.client == nil {
		t.Fatal("client is nil")
	}
	if p.client.Timeout <= 0 {
		t.Error("client has no timeout; a stalled page would hang the sync forever " +
			"and no retry could fire, because no error would ever be returned")
	}
}

// The pagination contract: keep requesting until startIndex covers
// totalResults, and emit every record along the way.
func TestAnnotate_PaginatesUntilComplete(t *testing.T) {
	var pages int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pages, 1)
		start := r.URL.Query().Get("startIndex")
		// Three records over two pages, so an implementation that stops after
		// the first page emits 2 and fails the count below.
		switch start {
		case "0":
			io.WriteString(w, `{"totalResults":3,"timestamp":"2024-01-01T00:00:00.000","vulnerabilities":[
			  {"cve":{"id":"CVE-2025-1","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}},
			  {"cve":{"id":"CVE-2025-2","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}}]}}}]}`)
		default:
			// A distinct, later timestamp than page 1's - the aggregate must
			// take the earliest (D12), not the last one seen.
			io.WriteString(w, `{"totalResults":3,"timestamp":"2024-06-01T00:00:00.000","vulnerabilities":[
			  {"cve":{"id":"CVE-2025-3","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"}}]}}}]}`)
		}
	}))
	defer srv.Close()

	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	prov, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d ratings, want 3 - a single page is not the whole feed", len(got))
	}
	if atomic.LoadInt32(&pages) != 2 {
		t.Errorf("made %d requests, want 2", pages)
	}
	if prov.Source == "" {
		t.Error("Provenance.Source is empty; a reader cannot check where this came from")
	}
	// Records is computed alongside DataAsOf but was previously never
	// asserted anywhere in this file - a build that leaves it at its zero
	// value passed the whole suite.
	if prov.Records != 3 {
		t.Errorf("Provenance.Records = %d, want 3 (one per rating actually emitted)", prov.Records)
	}
	// D12: freshness is measured from the upstream data, not from now. Pinned
	// to the exact value the feed's earlier page carried - not just "non
	// zero" - because time.Now() is never zero either, and a check that only
	// rules out the zero value would pass just as happily on the clock as on
	// the feed's own timestamp. Pinned to page 1's timestamp specifically
	// (the earlier of the two pages) rather than page 2's, so a mutation
	// that keeps the LAST page's timestamp instead of the earliest is also
	// caught.
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(want) {
		t.Errorf("Provenance.DataAsOf = %v, want %v - the feed's own timestamp "+
			"from its earliest page, not time.Now() and not the latest page seen",
			prov.DataAsOf, want)
	}
}

// A record with no CVSS metric is skipped, not emitted with an empty vector.
//
// Checked rather than assumed: severity.Highest(nil) already returns unknown,
// so an empty rating would NOT be coerced to none - the band would be right.
// The reason to skip it is different. A rating that says nothing still shows
// up as a source in the Ratings array and in --explain's breakdown, so the
// report would name NVD as having weighed in on 372,628 CVEs it has no
// opinion about. That is noise in the one view built to explain a verdict.
func TestAnnotate_ARecordWithNoScoreIsNotEmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":2,"vulnerabilities":[
		  {"cve":{"id":"CVE-2025-4","metrics":{}}},
		  {"cve":{"id":"CVE-2025-5","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
	}))
	defer srv.Close()
	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CVE != "CVE-2025-5" {
		t.Fatalf("emitted %+v, want only CVE-2025-5 - an unscored record must not "+
			"arrive as a rating with no vector, which would derive as none, not unknown", got)
	}
}

// v3.1, v4.0, v3.0 and v2 all appear in the feed. Every vector present is
// kept: severity.Highest picks among them at query time (D13), and dropping
// the ones this build does not score yet would bake today's scorer into the
// database.
func TestAnnotate_KeepsEveryVectorVersionPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-6","metrics":{
		  "cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
		  "cvssMetricV40":[{"cvssData":{"vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}],
		  "cvssMetricV2":[{"cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]}}}]}`)
	}))
	defer srv.Close()
	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	// Asserted against the exact three vectors, not just a length of 3: a
	// length-only check passes just as happily if one vector is appended
	// three times, or if a Score is mangled in transit - convert's own
	// field-append order (V2, V30, V31, V40) makes this order deterministic
	// regardless of the JSON's own key order.
	want := []advisory.Severity{
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
	}
	if !slices.Equal(got[0].Severity, want) {
		t.Errorf("Severity = %+v, want %+v (v2, v3.1, v4.0, all of them, so the "+
			"band is a query-time decision)", got[0].Severity, want)
	}
}

// An API key is sent as a header when set, and the request is unauthenticated
// when it is not. A provider that silently required a key would work for
// whoever wrote it and for nobody else.
func TestAnnotate_APIKeyIsOptionalAndSentAsAHeader(t *testing.T) {
	for _, tc := range []struct {
		name        string
		key         string
		wantHeader  string
		wantPresent bool
	}{
		{"without a key", "", "", false},
		{"with a key", "secret-key", "secret-key", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			var seenPresent bool
			var seenOK bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.Header.Get("apiKey")
				// r.Header.Get alone cannot tell "the header was never sent"
				// from "the header was sent with an empty value" - both read
				// back as "". Values() reports the header's presence
				// directly, which is the property "no key configured" is
				// actually supposed to have: not merely an empty value
				// travelling to NVD, but no apiKey line on the request at
				// all.
				seenPresent = len(r.Header.Values("apiKey")) > 0
				seenOK = true
				io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
			}))
			defer srv.Close()
			p := New(Options{BaseURL: srv.URL, APIKey: tc.key, PageSize: 100, Pause: durPtr(0)})
			if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if !seenOK {
				t.Fatal("the server was never called")
			}
			if seen != tc.wantHeader {
				t.Errorf("apiKey header = %q, want %q", seen, tc.wantHeader)
			}
			if seenPresent != tc.wantPresent {
				t.Errorf("apiKey header present = %v, want %v - an unconfigured key must "+
					"produce no header at all, not one carrying an empty value", seenPresent, tc.wantPresent)
			}
		})
	}
}

// An HTTP error is an error, not an empty feed. Returning nil here would build
// a database with no ratings that looks complete.
func TestAnnotate_AnHTTPErrorIsNotAnEmptyFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate returned nil on 503 - a failed sync must not read as " +
			"a feed with nothing in it")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error %q does not carry the status", err)
	}
}

// The context is honoured between pages, so ^C during a 20-minute sync stops
// promptly rather than at the next page boundary twenty minutes later.
func TestAnnotate_RespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1000000,"vulnerabilities":[{"cve":{"id":"CVE-2025-7","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	n := 0
	_, err := p.Annotate(ctx, func(advisory.Rating) error {
		n++
		if n == 3 {
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("Annotate ignored a cancelled context and would have run to a " +
			"million records")
	}
}

// A page that returns zero records while startIndex has not yet reached
// totalResults must not spin forever re-requesting the same startIndex:
// nothing else in Annotate advances startIndex, so a zero-length page is the
// one response shape that leaves the loop with no way to make progress. On
// a real ~187-page sync against a service that occasionally returns an
// empty page, that is a hang with no output and no error - the worst
// failure shape for something that already takes 20 minutes.
func TestAnnotate_AnEmptyPageBeforeTotalIsAnErrorNotAHang(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":5,"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate returned nil over a page that never advances past " +
			"startIndex 0 - this must be refused outright, not retried forever")
	}
}

// The status check on fetchPage applies to every page, not just the first:
// the first-page-only test above shares fetchPage with every later page, but
// sharing code is not the same as testing the shared path at every call
// site. A page-two failure must not let what NVD actually returned - a
// partial sync - report as a complete one.
func TestAnnotate_AnHTTPErrorOnALaterPageIsNotASilentPartialSync(t *testing.T) {
	var reqs int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&reqs, 1) == 1 {
			io.WriteString(w, `{"totalResults":3,"vulnerabilities":[
			  {"cve":{"id":"CVE-2025-10","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}},
			  {"cve":{"id":"CVE-2025-11","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}}]}}}]}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	var got []advisory.Rating
	_, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	})
	if err == nil {
		t.Fatalf("Annotate returned nil after page two failed (already emitted %d "+
			"ratings) - a partial sync must not read as a complete one", len(got))
	}
}

// Annotate paces requests through the sleep hook, not a bare sleepCtx call,
// specifically so this can be asserted without spending the real pause to
// prove it. Every other Annotate test in this file uses Pause: durPtr(0),
// and sleepCtx's own "d <= 0 returns immediately" fast path means deleting
// the pacing call from Annotate entirely breaks none of them: the 19.9s a
// full local run used to take, before Options.Pause became a
// *time.Duration, was the only evidence a pause ever happened, and nothing
// here replaced that once the tests stopped needing to sleep for real.
func TestAnnotate_PacesRequestsWithConfiguredPause(t *testing.T) {
	var calls []time.Duration
	orig := sleep
	sleep = func(_ context.Context, d time.Duration) error {
		calls = append(calls, d)
		return nil
	}
	defer func() { sleep = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("startIndex") {
		case "0":
			io.WriteString(w, `{"totalResults":2,"vulnerabilities":[
			  {"cve":{"id":"CVE-2025-12","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
		default:
			io.WriteString(w, `{"totalResults":2,"vulnerabilities":[
			  {"cve":{"id":"CVE-2025-13","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`)
		}
	}))
	defer srv.Close()

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(3 * time.Second)})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != 3*time.Second {
		t.Errorf("sleep calls = %v, want exactly one call of 3s - paced once, "+
			"between the two pages, using the configured Pause", calls)
	}
}

// sleepCtx must return promptly when cancelled mid-wait, not only when
// checked between Annotate's iterations - the "^C during a 20-minute sync
// stops promptly" property depends specifically on this, and nothing
// exercised sleepCtx in isolation to hold it: every Annotate test above uses
// a zero pause, which returns via the "d <= 0" fast path before the
// cancellation-aware select is ever reached.
func TestSleepCtx_ReturnsPromptlyWhenCancelledMidSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := sleepCtx(ctx, 10*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("sleepCtx returned nil after its context was cancelled mid-sleep")
	}
	if elapsed > 2*time.Second {
		t.Errorf("sleepCtx took %v to notice cancellation, want well under "+
			"the full 10s pause it was given", elapsed)
	}
}

// Since bounds the sync with NVD's lastModStartDate filter, which is what
// makes a daily run minutes rather than the seven hours a full pass costs.
func TestAnnotate_SinceBoundsTheWindow(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[],"timestamp":"2026-08-03T00:00:00.000"}`)
	}))
	defer srv.Close()

	// Both ends pinned, so the assertion is on the exact window rather than on
	// "a lastModStartDate appeared somewhere".
	restore := nowUTC
	nowUTC = func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }
	defer func() { nowUTC = restore }()

	p := New(Options{
		BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0),
		Since: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}
	q, err := url.ParseQuery(gotQuery)
	if err != nil {
		t.Fatal(err)
	}
	// Parsed rather than substring-matched: the raw query contains the same
	// date twice over in escaped form, so a Contains check could pass from
	// either bound while the other was wrong or missing.
	if got := q.Get("lastModStartDate"); got != "2026-07-01T00:00:00.000+00:00" {
		t.Errorf("lastModStartDate = %q, want the Since value", got)
	}
	if got := q.Get("lastModEndDate"); got != "2026-08-03T12:00:00.000+00:00" {
		t.Errorf("lastModEndDate = %q, want now - NVD rejects an open-ended "+
			"window rather than reading it as \"until now\"", got)
	}
}

// A record carrying metrics but no id is skipped rather than emitted. Stored,
// it would key as "\x00NVD": unreachable, since the matcher only asks
// RatingsFor about identifiers beginning "CVE-", but SetMeta derives its
// per-source counts by splitting stored keys, so `db status` would count it
// and claim a rating nothing can read (D20, over-claiming). Its URL would be
// a bare .../vuln/detail/ too.
func TestAnnotate_SkipsARecordWithMetricsButNoID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two records, identical but for the id, so the assertion rests on
		// the id alone rather than on the metrics being malformed.
		io.WriteString(w, `{"totalResults":2,"vulnerabilities":[`+
			`{"cve":{"id":"","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}},`+
			`{"cve":{"id":"CVE-2026-7","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}`+
			`],"timestamp":"2026-08-03T00:00:00.000"}`)
	}))
	defer srv.Close()

	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	prov, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CVE != "CVE-2026-7" {
		t.Errorf("emitted %+v, want only the record that has an id", got)
	}
	// Records must not count the skipped one either: the number db status
	// shows would otherwise disagree with what is actually in the bucket.
	if prov.Records != 1 {
		t.Errorf("Records = %d, want 1 - the skipped record must not be counted", prov.Records)
	}
}

// TestMain zeroes the retry schedule for the whole package.
//
// Adding retries made two pre-existing failure tests wait out the real
// schedule -- 62 seconds each, taking this package from 0.4s to 124s with
// nothing announcing it. That is the wall-clock-standing-in-for-an-assertion
// hazard CLAUDE.md records, arriving as a side effect rather than as a test
// anyone wrote.
//
// The slice keeps its LENGTH, so attempt counts are unchanged and every
// existing assertion still means what it meant. Only the sleeping goes.
// TestRetryWaits_ShippedScheduleActuallyWaits covers the real values, which
// this necessarily hides.
func TestMain(m *testing.M) {
	retryWaits = make([]time.Duration, len(defaultRetryWaits))
	os.Exit(m.Run())
}

// The shipped schedule really waits. TestMain zeroes the working copy for
// speed, so without this, changing every production value to 0 -- turning
// each retry into a hot loop against NVD, four requests with no pause --
// would pass the entire suite.
func TestRetryWaits_ShippedScheduleActuallyWaits(t *testing.T) {
	if len(defaultRetryWaits) == 0 {
		t.Fatal("no retry schedule at all")
	}
	var total time.Duration
	for i, w := range defaultRetryWaits {
		if w <= 0 {
			t.Errorf("defaultRetryWaits[%d] = %v, want a real pause", i, w)
		}
		total += w
	}
	// The BUDGET is the point, not merely that each value is non-zero.
	// The first schedule totalled 62s and threw away a run that had spent
	// 5h52m -- every individual value was non-zero and the policy was
	// still wrong. What has to hold is that the wait is proportionate to
	// what giving up costs.
	if min := 10 * time.Minute; total < min {
		t.Errorf("retry budget is %v, want at least %v -- a multi-hour sync must not be discarded over a brief outage", total, min)
	}
	// ...and still inside the daily workflow's 60-minute timeout, so a
	// genuine outage fails the build rather than hanging it.
	if max := 30 * time.Minute; total > max {
		t.Errorf("retry budget is %v, want at most %v", total, max)
	}
}

// The sync reports progress as it goes.
//
// Without this the loop printed nothing between "annotating with NVD" and
// its result -- seven hours of silence on a full pass. Through four
// bootstrap attempts the only way to tell a working sync from a hung one
// was watching the temporary database grow from outside the process.
func TestAnnotate_ReportsProgressPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two records total, one per page, so the loop runs twice.
		idx := r.URL.Query().Get("startIndex")
		id := "CVE-2026-1"
		if idx == "1" {
			id = "CVE-2026-2"
		}
		io.WriteString(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"`+id+`","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}],"timestamp":"2026-08-04T00:00:00.000"}`)
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0), Progress: &progress})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}

	lines := strings.Count(progress.String(), "nvd: ")
	if lines != 2 {
		t.Errorf("progress has %d line(s), want one per page (2):\n%s", lines, progress.String())
	}
	// The counts have to be real, not a bare heartbeat: a line that says
	// only "working" cannot distinguish progress from a loop re-reading
	// the same page.
	if want := "2/2 records"; !strings.Contains(progress.String(), want) {
		t.Errorf("progress does not report the final count %q:\n%s", want, progress.String())
	}
	if want := "1/2 records"; !strings.Contains(progress.String(), want) {
		t.Errorf("progress does not report intermediate position %q:\n%s", want, progress.String())
	}
}

// A single transient failure must not destroy a multi-hour sync. The first
// real 120-day bootstrap died at startIndex 42000 after 42 minutes on one
// 503 and lost every record, because Update installs the database only at
// the end -- there is no resume point to fall back to.
func TestAnnotate_RetriesATransientFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-9","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}],"timestamp":"2026-08-04T00:00:00.000"}`)
	}))
	defer srv.Close()

	restoreWaits := retryWaits
	retryWaits = []time.Duration{0, 0, 0, 0}
	defer func() { retryWaits = restoreWaits }()

	var progress bytes.Buffer
	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0), Progress: &progress})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("Annotate failed despite the failures being transient: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("emitted %d rating(s), want 1 -- the retry did not recover the page", len(got))
	}
	if calls != 3 {
		t.Errorf("made %d requests, want 3 (two failures then success)", calls)
	}
	// The wait is announced. A sync that pauses with no output is
	// indistinguishable from one that has hung.
	if !strings.Contains(progress.String(), "retrying in") {
		t.Errorf("progress = %q, want it to announce the retry", progress.String())
	}
}

// A failure that is NOT an HTTP status is retried too.
//
// This is the case the first retry implementation missed. It matched only
// httpStatusError, because a 503 was the failure that had just been seen --
// and the next bootstrap died at 116 minutes on an HTTP/2 stream error
// surfacing during body decode, with the retry never firing. A truncated
// body reproduces that shape: the request succeeds with 200, the decode
// fails.
func TestAnnotate_RetriesAFailureThatIsNotAnHTTPStatus(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// 200 with a body that stops mid-object: a decode error, not a
			// status error, which is exactly what the stream failure looked
			// like by the time it reached this code.
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":`)
			return
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-9","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}],"timestamp":"2026-08-04T00:00:00.000"}`)
	}))
	defer srv.Close()

	var got []advisory.Rating
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("Annotate failed on a retryable decode error: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d requests, want 2 -- a non-status failure must still be retried", calls)
	}
	if len(got) != 1 {
		t.Errorf("emitted %d rating(s), want 1", len(got))
	}
}

// A context cancelled MID-REQUEST must not be retried: ^C during a
// multi-hour sync has to stop, not wait out the whole schedule first.
//
// Cancelled mid-flight, deliberately. An already-cancelled context is
// caught by Annotate's own ctx.Err() check at the top of the loop, before
// fetchPage runs at all -- so a test using one passes whatever retryable
// decides, and proves nothing about it (verified: that version of this test
// survived the mutation).
//
// The assertion is on the retry NOTICE rather than the request count,
// because sleep() also honours the context: a mutated retryable would fail
// at the sleep instead and issue no extra request. The notice is the only
// externally visible difference.
func TestAnnotate_DoesNotRetryAContextCancelledMidRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0), Progress: &progress})
	if _, err := p.Annotate(ctx, func(advisory.Rating) error { return nil }); err == nil {
		t.Fatal("Annotate succeeded despite cancellation")
	}
	if strings.Contains(progress.String(), "retrying") {
		t.Errorf("progress = %q: a cancelled context was treated as retryable", progress.String())
	}
}

// ...and a PERMANENT failure is not retried. Retrying a 404 would have
// buried the window-too-wide bug behind four minutes of silent waiting
// before reporting the same error anyway.
func TestAnnotate_DoesNotRetryAPermanentFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	restoreWaits := retryWaits
	retryWaits = []time.Duration{0, 0, 0, 0}
	defer func() { retryWaits = restoreWaits }()

	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against a 404")
	}
	if calls != 1 {
		t.Errorf("made %d requests, want 1 -- a 404 is this code getting the request wrong, not NVD having a bad moment", calls)
	}
}

// Retries are bounded: a genuine outage fails the build rather than
// hanging it.
func TestAnnotate_GivesUpAfterTheRetryScheduleIsExhausted(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	restoreWaits := retryWaits
	retryWaits = []time.Duration{0, 0, 0}
	defer func() { retryWaits = restoreWaits }()

	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err == nil {
		t.Fatal("Annotate succeeded against a permanently failing registry")
	}
	// One initial attempt plus one per scheduled wait.
	if want := len(retryWaits) + 1; calls != want {
		t.Errorf("made %d requests, want %d (the schedule is the policy)", calls, want)
	}
}

// NVD_SINCE_DAYS=120 -- the documented maximum -- could never actually be
// used, and the API said so with a bare 404.
//
// The span is measured by NVD at REQUEST time. Since is computed when the
// options are read; until is read when Annotate starts; and in between,
// db update runs every advisory provider. The first real bootstrap spent
// 2m51s fetching OSV, so a 120-day window arrived as 120 days and 2m51s and
// was rejected outright.
//
// Clamping is safe rather than lossy because the narrowing is disclosed --
// Provenance.Window records the range actually requested and db status
// prints it -- so a clamped run cannot claim coverage it does not have.
func TestAnnotate_ClampsAWindowThatGrewPastNVDsMaximum(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[],"timestamp":"2026-08-04T00:00:00.000"}`)
	}))
	defer srv.Close()

	until := time.Date(2026, 8, 4, 3, 46, 10, 0, time.UTC)
	restore := nowUTC
	nowUTC = func() time.Time { return until }
	defer func() { nowUTC = restore }()

	// Exactly the shape that failed: Since chosen 120 days before the
	// moment the options were read, which was 2m50s before Annotate ran.
	since := until.Add(-maxWindow).Add(-2*time.Minute - 50*time.Second)
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0), Since: since})
	prov, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	q, err := url.ParseQuery(gotQuery)
	if err != nil {
		t.Fatal(err)
	}
	start, err := time.Parse("2006-01-02T15:04:05.000-07:00", q.Get("lastModStartDate"))
	if err != nil {
		t.Fatalf("lastModStartDate %q: %v", q.Get("lastModStartDate"), err)
	}
	end, err := time.Parse("2006-01-02T15:04:05.000-07:00", q.Get("lastModEndDate"))
	if err != nil {
		t.Fatalf("lastModEndDate %q: %v", q.Get("lastModEndDate"), err)
	}
	// Asserted on the SPAN, not on either bound: NVD rejects the range, so
	// the range is the thing that has to hold.
	if span := end.Sub(start); span > maxWindow {
		t.Errorf("requested span %v exceeds NVD's %v maximum; the API answers this with 404", span, maxWindow)
	}
	_ = prov
}

// ...and the clamp is disclosed, not silent.
//
// Split from the test above deliberately. There the overshoot is 2m50s --
// the real one -- which does not move the calendar day, so asserting the
// Window date there passes whether or not the clamp is reflected in it
// (verified by mutation: it survived). A large overshoot is what makes the
// disclosure observable.
func TestAnnotate_DisclosesTheClampedWindowNotTheRequestedOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[],"timestamp":"2026-08-04T00:00:00.000"}`)
	}))
	defer srv.Close()

	until := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	restore := nowUTC
	nowUTC = func() time.Time { return until }
	defer func() { nowUTC = restore }()

	// 200 days requested; 120 is the most NVD allows, so the reported start
	// must be the clamped 2026-04-06, not the requested 2026-01-16.
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0),
		Since: until.Add(-200 * 24 * time.Hour)})
	prov, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if want := "modified 2026-04-06"; !strings.Contains(prov.Window, want) {
		t.Errorf("Window = %q, want it to start at the clamped %q -- db status must not claim the 200 days that were asked for", prov.Window, want)
	}
	if strings.Contains(prov.Window, "2026-01-16") {
		t.Errorf("Window = %q reports the REQUESTED start, so a clamped run claims coverage it does not have", prov.Window)
	}
	// CoversSince carries the same fact in comparable form, and it must be
	// the CLAMPED value too. This is the field `db push`'s coverage guard
	// compares, so recording the unhonoured request would let a 120-day
	// artifact claim to be as broad as the 200 days it was invoked with --
	// and then overwrite a genuinely broader published one without tripping
	// the guard. Window being right while this is wrong is exactly the
	// split a display string and a machine value can drift into.
	if want := until.Add(-maxWindow); !prov.CoversSince.Equal(want) {
		t.Errorf("CoversSince = %v, want the clamped %v", prov.CoversSince, want)
	}
}

// A window comfortably inside the maximum is passed through untouched --
// the clamp must not quietly narrow every run.
func TestAnnotate_LeavesAWindowInsideTheMaximumAlone(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[],"timestamp":"2026-08-04T00:00:00.000"}`)
	}))
	defer srv.Close()

	until := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	restore := nowUTC
	nowUTC = func() time.Time { return until }
	defer func() { nowUTC = restore }()

	since := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC) // 30 days
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0), Since: since})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(gotQuery)
	if got := q.Get("lastModStartDate"); got != "2026-07-05T00:00:00.000+00:00" {
		t.Errorf("lastModStartDate = %q, want the Since value unchanged", got)
	}
}

// The window is read once and held for the whole sync, not recomputed per
// page. Pagination is by startIndex INTO the set the window defines, so
// moving the upper bound between requests moves that set while it is being
// walked: a CVE modified during the sync enters the window, shifts every
// later offset by one, and a record pushed past an offset already consumed is
// never emitted. That is a rating missing from the database and a finding
// left on a lower band -- silent, which is the failure mode that matters
// here. A real 30-day sync is ~11 pages over ~25 minutes, so this is not a
// narrow race.
//
// TestAnnotate_SinceBoundsTheWindow cannot catch it: it serves totalResults 0,
// so exactly one request is ever made and a per-page recomputation is
// invisible.
func TestAnnotate_TheWindowIsPinnedAcrossPages(t *testing.T) {
	var ends []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ends = append(ends, r.URL.Query().Get("lastModEndDate"))
		// Two pages of one record each: the first leaves startIndex short of
		// totalResults, so a second request is required.
		io.WriteString(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-1",`+
			`"metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}],`+
			`"timestamp":"2026-08-03T00:00:00.000"}`)
	}))
	defer srv.Close()

	// The clock ADVANCES between requests -- a day per call -- which is what
	// makes a per-page nowUTC() observable at all. Pinned to fixed values so
	// the assertion is on an exact string, not on "the two look similar".
	calls := 0
	restore := nowUTC
	nowUTC = func() time.Time {
		calls++
		return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC).AddDate(0, 0, calls-1)
	}
	defer func() { nowUTC = restore }()

	p := New(Options{
		BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0),
		Since: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}

	if len(ends) != 2 {
		t.Fatalf("made %d requests, want 2 - the fixture must actually paginate for this to test anything", len(ends))
	}
	if ends[0] != ends[1] {
		t.Errorf("lastModEndDate moved between pages: %q then %q - the window must be read once and held",
			ends[0], ends[1])
	}
	// And it is the value from BEFORE the first request, not some later
	// reading: equality alone would also hold if both pages recomputed and
	// the clock happened not to move.
	if want := "2026-08-03T12:00:00.000+00:00"; ends[0] != want {
		t.Errorf("lastModEndDate = %q, want %q - the window opens at the start of the sync", ends[0], want)
	}
}

// A bounded run must say so in its Provenance. Update rebuilds the database
// from empty every time, so a windowed sync's window IS that source's entire
// coverage rather than a delta on an earlier pass -- and without this a
// database holding one day of NVD is indistinguishable from one holding all
// of it (D20).
func TestAnnotate_ReportsWhatWindowItActuallyCovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[],"timestamp":"2026-08-03T00:00:00.000"}`)
	}))
	defer srv.Close()

	restore := nowUTC
	nowUTC = func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }
	defer func() { nowUTC = restore }()

	t.Run("bounded", func(t *testing.T) {
		p := New(Options{
			BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0),
			Since: time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC),
		})
		prov, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if want := "modified 2026-07-04..2026-08-03"; prov.Window != want {
			t.Errorf("Window = %q, want %q", prov.Window, want)
		}
	})

	// An unbounded run says so in words. An empty Window would be
	// indistinguishable from a database built before the field existed, and
	// "no limit" is the one reading it must not be given by default.
	t.Run("unbounded", func(t *testing.T) {
		p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
		prov, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if want := "the whole feed"; prov.Window != want {
			t.Errorf("Window = %q, want %q", prov.Window, want)
		}
	})
}

// ...and a zero Since asks for the whole feed, with neither bound present.
// Sending an empty lastModStartDate would be rejected by the API, so "not set"
// has to mean "omit", not "send empty".
func TestAnnotate_AZeroSinceSendsNoWindowAtAll(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `{"totalResults":0,"vulnerabilities":[],"timestamp":"2026-08-03T00:00:00.000"}`)
	}))
	defer srv.Close()
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0)})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(gotQuery)
	for _, k := range []string{"lastModStartDate", "lastModEndDate"} {
		if _, ok := q[k]; ok {
			t.Errorf("%s was sent for a full sync; NVD rejects an empty value "+
				"rather than treating it as no filter", k)
		}
	}
}

// A stalled page is retried. This is the second correction to retryable --
// the first turned an allow-list into a deny-list -- and the most expensive
// case it had left.
//
// net/http reports its OWN Client.Timeout as a deadline error: a
// timeoutError's Is(context.DeadlineExceeded) is true, for the
// response-header timeout and the body-read timeout alike (verified against
// Go 1.26). So the obvious spelling of "do not retry a cancellation" --
// errors.Is(err, context.DeadlineExceeded), which is what this file shipped
// -- also caught this provider's own ten-minute timeout, and classified it
// permanent. A 2,000-record page has taken 136 seconds and varies with NVD's
// load, so overrunning that timeout is an ordinary event; a full pass is
// about seven hours, and Update installs the database only at the end. One
// slow page therefore discarded the entire run with the retry never firing
// -- the exact failure the retry schedule was lengthened to twelve minutes
// to prevent.
//
// Only the CALLER's context can answer the question that exclusion is
// asking, so that is what is asked.
func TestRetryable_JudgesTheCallersContextNotTheError(t *testing.T) {
	// Shaped like what net/http hands back, without waiting out a real
	// timeout to produce one: what matters is that errors.Is finds
	// DeadlineExceeded inside it, which is exactly why the old test passed
	// while the policy was wrong.
	timeout := fmt.Errorf("Get %q: %w", "https://services.nvd.nist.gov", context.DeadlineExceeded)

	if !retryable(context.Background(), timeout) {
		t.Error("a client timeout was judged permanent -- a seven-hour sync must not be " +
			"discarded because one page was slow")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if retryable(cancelled, timeout) {
		t.Error("the caller's cancellation was retried; ^C must stop the sync, not restart it")
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if retryable(expired, timeout) {
		t.Error("an expired caller deadline was retried; the retry would outlive the deadline it was given")
	}
	// ...and the status rules are unchanged by the switch.
	for _, tc := range []struct {
		code int
		want bool
	}{
		{http.StatusNotFound, false},
		{http.StatusBadRequest, false},
		{http.StatusTooManyRequests, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusInternalServerError, true},
	} {
		if got := retryable(context.Background(), &httpStatusError{code: tc.code}); got != tc.want {
			t.Errorf("retryable(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

// ...and the same thing end to end, through a real net/http timeout rather
// than an error shaped like one, so this cannot pass on a wrong idea of what
// Client.Timeout actually produces.
func TestAnnotate_RetriesARealClientTimeout(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			// Never answers. The client's own Timeout ends the request; the
			// CALLER's context is untouched throughout, which is the whole
			// distinction being tested.
			<-r.Context().Done()
			return
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-11","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}],"timestamp":"2026-08-05T00:00:00.000"}`)
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: durPtr(0), Progress: &progress})
	// A tenth of a second, against a local server that answers in
	// microseconds. The margin is still three orders of magnitude, so this
	// bounds a hang rather than asserting a speed -- and redness comes from
	// the explicit assertions below, not from the clock, so a loaded runner
	// can only make this slower, never flip it.
	p.client.Timeout = 100 * time.Millisecond

	var got []advisory.Rating
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("Annotate failed on a client timeout, which is the most ordinary transient "+
			"failure this provider has: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("emitted %d rating(s), want 1 -- the retry did not recover the page", len(got))
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("made %d requests, want 2 (one stalled page, then success)", n)
	}
	if !strings.Contains(progress.String(), "retrying in") {
		t.Errorf("progress = %q, want the retry announced", progress.String())
	}
}
