package nvd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

type memoryTransport func(*http.Request) (*http.Response, error)

func (f memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The 2026-10-22 external review's #5, at the provider. A CVE the delta
// returns with no CVSS metrics -- Rejected, or reset to Awaiting Analysis --
// used to convert to nothing and be skipped, so a rating seeded from an
// earlier artifact survived NVD's own withdrawal of it. The provider now
// says so through the withdraw callback, and the matcher's verdict follows
// NVD's current word: no NVD rating, so the vendor's unrated entry is
// Unknown, not critical.
func TestAnnotateWithdrawing_ARecordWithoutMetricsWithdrawsTheSeededRating(t *testing.T) {
	for _, status := range []string{"Rejected", "Awaiting Analysis"} {
		t.Run(status, func(t *testing.T) {
			const cve = "CVE-2026-12345"
			path := filepath.Join(t.TempDir(), "review.db")
			w, err := store.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			old := advisory.Rating{CVE: cve, Source: SourceName, Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}
			if err := w.PutRating(old); err != nil {
				t.Fatal(err)
			}
			// Another authority's opinion about the same CVE is not NVD's to
			// withdraw.
			if err := w.PutRating(advisory.Rating{CVE: cve, Source: "KISA", Severity: old.Severity}); err != nil {
				t.Fatal(err)
			}
			if err := w.Put(advisory.Advisory{ID: "VENDOR-REVIEW", Database: "Vendor", Kind: advisory.KindVulnerability, Aliases: []string{cve}, Affected: []advisory.Affected{{Ecosystem: "npm", Name: "review-package", Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}}}); err != nil {
				t.Fatal(err)
			}
			zero := time.Duration(0)
			p := New(Options{BaseURL: "https://fixture.invalid/nvd", Pause: &zero, Since: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), Until: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)})
			var progress strings.Builder
			p.progress = &progress
			calls := 0
			p.client = &http.Client{Transport: memoryTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Query().Get("lastModStartDate") == "" {
					t.Fatal("expected an incremental request")
				}
				body := fmt.Sprintf(`{"totalResults":2,"timestamp":"2026-10-22T00:00:00.000","vulnerabilities":[{"cve":{"id":%q,"vulnStatus":%q,"metrics":{}}},{"cve":{"id":"CVE-2026-55555","vulnStatus":"Analyzed","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]}}}]}`, cve, status)
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			var withdrawn []string
			prov, err := p.AnnotateWithdrawing(context.Background(), w.PutRating, func(cve string) error {
				withdrawn = append(withdrawn, cve)
				_, err := w.WithdrawRating(cve, SourceName)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || prov.Records != 1 || !prov.CoversUntilKnown {
				t.Fatalf("unexpected delta: calls=%d prov=%+v", calls, prov)
			}
			if len(withdrawn) != 1 || withdrawn[0] != cve {
				t.Fatalf("withdrawn = %v, want exactly [%s]: the rated CVE on the same page must not be withdrawn", withdrawn, cve)
			}
			if !strings.Contains(progress.String(), "1 returned without a score (rating withdrawn)") {
				t.Errorf("progress does not say what was withdrawn:\n%s", progress.String())
			}
			rs, err := w.RatingsFor(cve)
			if err != nil {
				t.Fatal(err)
			}
			if len(rs) != 1 || rs[0].Source != "KISA" {
				t.Fatalf("RatingsFor(%s) = %+v, want only KISA's", cve, rs)
			}
			if err := w.SetMeta(store.Meta{BuiltAt: time.Now(), Providers: map[string]store.Provenance{"Vendor": {Ecosystems: []string{"npm"}}}, Ratings: map[string]store.Provenance{SourceName: prov}}); err != nil {
				t.Fatal(err)
			}
			res, err := matcher.New(w).Match(pkgmeta.Target{Packages: []pkgmeta.Package{{Ecosystem: "npm", Name: "review-package", Version: "1.0.0"}}})
			if err != nil {
				t.Fatal(err)
			}
			// KISA's opinion still rates it; what must be gone is NVD's.
			if len(res.Findings) != 1 {
				t.Fatalf("findings = %+v, want the vendor's one", res.Findings)
			}
			for _, r := range res.Findings[0].Ratings {
				if r.Database == SourceName {
					t.Errorf("the finding still carries an NVD rating: %+v", r)
				}
			}
			// KISA's identical vector keeps the band critical; the control
			// that the finding still exists is above. What this test pins is
			// NVD's absence from it.
			if res.Findings[0].Severity != severity.Critical {
				t.Errorf("severity = %v, want critical from KISA's remaining rating", res.Findings[0].Severity)
			}
		})
	}
}

// Annotate without a withdraw callback -- the shape every other annotator
// has -- keeps working and simply has no one to tell.
func TestAnnotate_WithoutAWithdrawCallbackStillRates(t *testing.T) {
	zero := time.Duration(0)
	p := New(Options{BaseURL: "https://fixture.invalid/nvd", Pause: &zero})
	p.client = &http.Client{Transport: memoryTransport(func(req *http.Request) (*http.Response, error) {
		body := `{"totalResults":2,"timestamp":"2026-10-22T00:00:00.000","vulnerabilities":[{"cve":{"id":"CVE-2026-1","vulnStatus":"Rejected","metrics":{}}},{"cve":{"id":"CVE-2026-2","metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]}}}]}`
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	var got []string
	prov, err := p.Annotate(context.Background(), func(r advisory.Rating) error {
		got = append(got, r.CVE)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if prov.Records != 1 || len(got) != 1 || got[0] != "CVE-2026-2" {
		t.Errorf("records=%d emitted=%v, want the one rated CVE", prov.Records, got)
	}
}
