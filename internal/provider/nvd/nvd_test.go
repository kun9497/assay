package nvd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

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
	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: 0})
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
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: 0})
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
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: 0})
	if _, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d, want 1", len(got))
	}
	if n := len(got[0].Severity); n != 3 {
		t.Errorf("kept %d vectors, want 3 (v3.1, v4.0, v2) - all of them, so the "+
			"band is a query-time decision: %+v", n, got[0].Severity)
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
			p := New(Options{BaseURL: srv.URL, APIKey: tc.key, PageSize: 100, Pause: 0})
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
	p := New(Options{BaseURL: srv.URL, PageSize: 100, Pause: 0})
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
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: 0})
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
