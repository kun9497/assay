package nvd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

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
	p := New(Options{BaseURL: srv.URL, Since: now.Add(-3 * 24 * time.Hour), Pause: durPtr(0)})
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
