package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// gzipFixture gzip-compresses body, the shape FIRST.org actually serves
// (epss_scores-current.csv.gz, verified against a real download 2026-08-21).
func gzipFixture(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serveGzip(t *testing.T, body string) *httptest.Server {
	t.Helper()
	b := gzipFixture(t, body)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(b)
	}))
}

// realShapedFixture trims a handful of rows from the real feed sampled
// 2026-08-21 (epss_scores-current.csv.gz from
// epss.empiricalsecurity.com), keeping the header comment and column header
// exactly as measured.
const realShapedFixture = "#model_version:v2026.06.15,score_date:2026-08-20T12:03:07Z\n" +
	"cve,epss,percentile\n" +
	"CVE-1999-0001,0.03351,0.87734\n" +
	"CVE-1999-0002,0.27858,0.97942\n" +
	"CVE-1999-0006,0.119,0.95776\n" +
	"not-a-cve-row,0.5,0.5\n"

// TestAnnotate_EmitsTypedRatingsFromRealShapedFeed is the caller-first test:
// it drives Annotate itself against a fixture trimmed from the real feed,
// and checks every typed field the emitted advisory.Rating is supposed to
// carry (D86) -- not just that something was emitted. A helper that parsed
// CSV rows correctly but whose Annotate forgot to set, say, EPSSModel would
// leave a test of the parsing helper alone green; this is the test that
// would go red.
func TestAnnotate_EmitsTypedRatingsFromRealShapedFeed(t *testing.T) {
	srv := serveGzip(t, realShapedFixture)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	var got []advisory.Rating
	prov, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d rating(s), want 3 (one non-CVE row must be skipped): %+v", len(got), got)
	}

	byID := map[string]advisory.Rating{}
	for _, r := range got {
		byID[r.CVE] = r
	}
	want := advisory.Rating{
		CVE:            "CVE-1999-0002",
		Source:         "EPSS",
		EPSS:           0.27858,
		EPSSPercentile: 0.97942,
		EPSSModel:      "v2026.06.15",
		URL:            "https://api.first.org/data/v1/epss?cve=CVE-1999-0002",
	}
	got2, ok := byID["CVE-1999-0002"]
	if !ok {
		t.Fatalf("no rating emitted for CVE-1999-0002 among %+v", got)
	}
	// Field by field, not ==: advisory.Rating carries a []Severity, which
	// makes the struct non-comparable. Severity is asserted empty
	// separately, below.
	if got2.CVE != want.CVE || got2.Source != want.Source || got2.EPSS != want.EPSS ||
		got2.EPSSPercentile != want.EPSSPercentile || got2.EPSSModel != want.EPSSModel || got2.URL != want.URL {
		t.Errorf("rating = %+v, want %+v", got2, want)
	}
	if len(got2.Severity) != 0 {
		t.Errorf("rating.Severity = %v, want none -- EPSS expresses no severity opinion (D86)", got2.Severity)
	}

	// D12: DataAsOf is the score_date from the feed's own header comment,
	// never wall-clock fetch time.
	wantAsOf := time.Date(2026, 8, 20, 12, 3, 7, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("Provenance.DataAsOf = %v, want %v (the feed's score_date, not fetch time)", prov.DataAsOf, wantAsOf)
	}
	if prov.Records != 3 {
		t.Errorf("Provenance.Records = %d, want 3", prov.Records)
	}
}

// TestAnnotate_RefusesAFeedWithNoHeaderComment is the D12 refusal: without
// the "#model_version:...,score_date:..." line there is nowhere for DataAsOf
// to come from, and Annotate must fail rather than fall back to fetch time
// or leave DataAsOf zero.
func TestAnnotate_RefusesAFeedWithNoHeaderComment(t *testing.T) {
	body := "cve,epss,percentile\nCVE-1999-0001,0.03351,0.87734\n"
	srv := serveGzip(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against a feed with no header comment, want an error")
	}
}

// TestAnnotate_RefusesAnUnexpectedColumnHeader guards the second required
// line: a reshaped column order (or a column added/removed) must fail loudly
// rather than have emitRows silently misassign epss and percentile — the
// database would band a CVE by another CVE's percentile with no error at
// all.
func TestAnnotate_RefusesAnUnexpectedColumnHeader(t *testing.T) {
	body := "#model_version:v2026.06.15,score_date:2026-08-20T12:03:07Z\n" +
		"cve,epss,percentile,extra\n" +
		"CVE-1999-0001,0.03351,0.87734,x\n"
	srv := serveGzip(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against an unexpected column header, want an error")
	}
}

// TestAnnotate_SkipsNonCVERowsAndCountsThem drives the stats line, not just
// the emitted set: the house convention (CLAUDE.md) is that a skip is always
// counted, never folded silently into a success count.
func TestAnnotate_SkipsNonCVERowsAndCountsThem(t *testing.T) {
	body := "#model_version:v1,score_date:2026-08-20T12:03:07Z\n" +
		"cve,epss,percentile\n" +
		"CVE-1999-0001,0.1,0.5\n" +
		"GHSA-not-a-cve,0.2,0.6\n" +
		"CVE-1999-0002,0.3,0.7\n"
	srv := serveGzip(t, body)
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{URL: srv.URL, Progress: &progress})
	var got []advisory.Rating
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d rating(s), want 2 (the non-CVE row must be skipped, not emitted)", len(got))
	}
	if !strings.Contains(progress.String(), "1 non-CVE id(s) skipped") {
		t.Errorf("progress = %q, want it to count the skipped non-CVE row", progress.String())
	}
}

// TestAnnotate_StopsWhenEmitFails proves Annotate does not swallow the
// caller's own error and keep going.
func TestAnnotate_StopsWhenEmitFails(t *testing.T) {
	srv := serveGzip(t, realShapedFixture)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	n := 0
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error {
		n++
		return errStop
	})
	if err == nil {
		t.Fatal("Annotate succeeded despite emit always failing")
	}
	if n != 1 {
		t.Errorf("emit was called %d time(s) after failing, want exactly 1 (Annotate kept going)", n)
	}
}

var errStop = errStopType{}

type errStopType struct{}

func (errStopType) Error() string { return "stop" }

// TestAnnotate_AnHTTPErrorPropagatesAfterRetrying is the caller-first proof
// for the retry pattern: a server that never answers 200 must still fail the
// build after a bounded number of attempts, per this provider's retry
// pattern -- and it must actually retry more than once, not fail on the
// first transient response, which is what makes EPSS_ENABLE/KEV_ENABLE's
// default-on posture safe against a two-second blip.
func TestAnnotate_AnHTTPErrorPropagatesAfterRetrying(t *testing.T) {
	defer fetchBackoffForTest()()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against a server returning 503 on every attempt")
	}
	if calls != fetchAttempts {
		t.Errorf("server saw %d call(s), want exactly %d (the full retry schedule)", calls, fetchAttempts)
	}
}

// TestAnnotate_RetriesATransientFailureThenSucceeds is the other half:
// failing once (503) and succeeding on the next attempt must still emit the
// feed's ratings, proving attempt 2 is not merely counted but actually used.
func TestAnnotate_RetriesATransientFailureThenSucceeds(t *testing.T) {
	b := gzipFixture(t, realShapedFixture)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()

	orig := fetchBackoffForTest()
	defer orig()

	p := New(Options{URL: srv.URL})
	var got []advisory.Rating
	_, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if calls < 2 {
		t.Fatalf("server saw %d call(s), want at least 2 (a retry after the first failure)", calls)
	}
	if len(got) != 3 {
		t.Errorf("emitted %d rating(s) after the retry succeeded, want 3", len(got))
	}
}

// TestAnnotate_A4xxOtherThan429IsNotRetried proves the deny-list narrows in
// the direction it must: a request that is simply wrong must fail fast, not
// spend the whole retry schedule repeating a mistake.
func TestAnnotate_A4xxOtherThan429IsNotRetried(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against a 404")
	}
	if calls != 1 {
		t.Errorf("server saw %d call(s), want exactly 1 (a 404 is not retried)", calls)
	}
}

func TestAnnotate_RefusesAFeedThatEmitsNothing(t *testing.T) {
	body := "#model_version:v1,score_date:2026-08-20T12:03:07Z\ncve,epss,percentile\n"
	srv := serveGzip(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against a feed with a header but zero rows, want an error")
	}
}

func TestName_IsEPSS(t *testing.T) {
	if got := New(Options{}).Name(); got != "EPSS" {
		t.Errorf("Name() = %q, want %q", got, "EPSS")
	}
}

// fetchBackoffForTest shrinks the retry backoff to keep the retry tests fast,
// restoring the shipped schedule afterward so no other test observes a
// zeroed one -- the same split nvd.retryWaits/defaultRetryWaits keeps, for
// the identical reason (nvd.go's own doc comment): a test must not be able
// to silently zero the production backoff for every other test in the
// package.
func fetchBackoffForTest() func() {
	orig := fetchBackoff
	fetchBackoff = func(int) time.Duration { return time.Millisecond }
	return func() { fetchBackoff = orig }
}
