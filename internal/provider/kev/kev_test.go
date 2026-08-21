package kev

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

func serveJSON(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
}

// realShapedFixture is trimmed from the real catalog sampled 2026-08-21
// (known_exploited_vulnerabilities.json), keeping the field names and the
// dateReleased shape (four fractional-second digits) exactly as measured.
const realShapedFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.08.20",
  "dateReleased": "2026-08-20T17:00:27.8837Z",
  "count": 3,
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-72530",
      "vendorProject": "TrueConf",
      "product": "Server",
      "vulnerabilityName": "TrueConf Server Code Injection Vulnerability",
      "dateAdded": "2026-08-20",
      "shortDescription": "...",
      "requiredAction": "...",
      "dueDate": "2026-09-03",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": ""
    },
    {
      "cveID": "CVE-2021-45046",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "dateAdded": "2022-01-10",
      "dueDate": "2022-01-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    },
    {
      "cveID": "CVE-2024-37383",
      "vendorProject": "Roundcube",
      "product": "Webmail",
      "dateAdded": "2024-10-02",
      "dueDate": "2024-10-23",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": ""
    }
  ]
}`

// TestAnnotate_EmitsTypedRatingsFromRealShapedFeed is the caller-first test,
// on epss's own precedent: it drives Annotate against a fixture trimmed from
// the real catalog and checks every typed field the emitted advisory.Rating
// carries (D86), plus that dueDate never reaches it at all.
func TestAnnotate_EmitsTypedRatingsFromRealShapedFeed(t *testing.T) {
	srv := serveJSON(t, realShapedFixture)
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
		t.Fatalf("emitted %d rating(s), want 3: %+v", len(got), got)
	}

	byID := map[string]advisory.Rating{}
	for _, r := range got {
		byID[r.CVE] = r
	}
	log4j, ok := byID["CVE-2021-45046"]
	if !ok {
		t.Fatalf("no rating emitted for CVE-2021-45046 among %+v", got)
	}
	want := advisory.Rating{
		CVE:           "CVE-2021-45046",
		Source:        "KEV",
		KEV:           true,
		KEVDateAdded:  "2022-01-10",
		KEVRansomware: "Known",
		URL:           "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}
	if log4j.CVE != want.CVE || log4j.Source != want.Source || log4j.KEV != want.KEV ||
		log4j.KEVDateAdded != want.KEVDateAdded || log4j.KEVRansomware != want.KEVRansomware || log4j.URL != want.URL {
		t.Errorf("rating = %+v, want %+v", log4j, want)
	}
	if len(log4j.Severity) != 0 {
		t.Errorf("rating.Severity = %v, want none -- KEV expresses no severity opinion (D86)", log4j.Severity)
	}

	// D12: DataAsOf is dateReleased, never fetch time. Verifies Go's
	// time.RFC3339 layout actually accepts the feed's four-digit fractional
	// seconds -- the fact this whole test would silently rely on if it were
	// left unchecked.
	wantAsOf := time.Date(2026, 8, 20, 17, 0, 27, 883700000, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("Provenance.DataAsOf = %v, want %v (dateReleased, not fetch time)", prov.DataAsOf, wantAsOf)
	}
	if prov.Records != 3 {
		t.Errorf("Provenance.Records = %d, want 3", prov.Records)
	}
}

// TestAnnotate_RefusesACountMismatch is the integrity check: a catalog whose
// declared count disagrees with how many entries it actually carries is
// refused rather than trusted, because either number could be the wrong one
// and proceeding under-reports either way.
func TestAnnotate_RefusesACountMismatch(t *testing.T) {
	body := `{"dateReleased":"2026-08-20T17:00:27Z","count":5,"vulnerabilities":[
		{"cveID":"CVE-2026-1","dateAdded":"2026-08-20","knownRansomwareCampaignUse":"Unknown"}
	]}`
	srv := serveJSON(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded despite count=5 with only 1 entry present")
	}
}

func TestAnnotate_RansomwareVerbatimThirdValueIsStoredNotCoerced(t *testing.T) {
	body := `{"dateReleased":"2026-08-20T17:00:27Z","count":1,"vulnerabilities":[
		{"cveID":"CVE-2026-2","dateAdded":"2026-08-20","knownRansomwareCampaignUse":"Suspected"}
	]}`
	srv := serveJSON(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	var got []advisory.Rating
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if len(got) != 1 || got[0].KEVRansomware != "Suspected" {
		t.Errorf("got %+v, want a rating carrying KEVRansomware=%q verbatim", got, "Suspected")
	}
}

func TestAnnotate_CountsRansomwareKnownInProgress(t *testing.T) {
	var progress bytes.Buffer
	srv := serveJSON(t, realShapedFixture)
	defer srv.Close()

	p := New(Options{URL: srv.URL, Progress: &progress})
	if _, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil }); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if !strings.Contains(progress.String(), "1 ransomware-known") {
		t.Errorf("progress = %q, want it to count the one Known entry in the fixture", progress.String())
	}
}

func TestAnnotate_StopsWhenEmitFails(t *testing.T) {
	srv := serveJSON(t, realShapedFixture)
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
		t.Errorf("emit was called %d time(s), want exactly 1 (Annotate kept going after a failure)", n)
	}
}

var errStop = errStopType{}

type errStopType struct{}

func (errStopType) Error() string { return "stop" }

// TestAnnotate_AnHTTPErrorPropagatesAfterRetrying is the caller-first proof
// for the retry pattern, on epss's own precedent: a server that never
// answers 200 must fail the build only after the full retry schedule.
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

func TestAnnotate_RetriesATransientFailureThenSucceeds(t *testing.T) {
	defer fetchBackoffForTest()()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(realShapedFixture))
	}))
	defer srv.Close()

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
	body := `{"dateReleased":"2026-08-20T17:00:27Z","count":0,"vulnerabilities":[]}`
	srv := serveJSON(t, body)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Annotate(context.Background(), func(advisory.Rating) error { return nil })
	if err == nil {
		t.Fatal("Annotate succeeded against an empty catalog, want an error")
	}
}

func TestName_IsKEV(t *testing.T) {
	if got := New(Options{}).Name(); got != "KEV" {
		t.Errorf("Name() = %q, want %q", got, "KEV")
	}
}

// fetchBackoffForTest mirrors epss's own helper exactly, for the same
// reason: shrink the retry backoff for the duration of one test, restoring
// the shipped schedule afterward.
func fetchBackoffForTest() func() {
	orig := fetchBackoff
	fetchBackoff = func(int) time.Duration { return time.Millisecond }
	return func() { fetchBackoff = orig }
}
