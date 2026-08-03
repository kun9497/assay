package nvd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
