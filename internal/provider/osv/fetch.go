package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// DefaultBaseURL is where OSV publishes one archive per ecosystem.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Ecosystems is what `assay db update` fetches. Distro coverage was briefly
// per-release-archive discovery (19 archives under "Alpine:vX.Y/", each a
// separate GCS prefix) before measurement against a real end-to-end scan
// showed those archives are a frozen 2024-10-09 export: the live, current
// data lives entirely under the single unversioned "Alpine/" prefix, which
// covers every release (v3.2 - v3.24 and growing) in one archive. The
// per-release archives are a superset of nothing current and are not
// fetched. "Alpine" is a fixed list entry like the language ecosystems
// because it is a fixed archive path — unlike a release list, it does not
// grow every six months; only the records inside it do. D6 still holds: the
// ecosystem KEYS the archive contains stay release-qualified
// ("Alpine:v3.19"), only the archive PATH is not. See familyMatches in
// record.go for how Convert reconciles a bare "Alpine" want against those
// release-qualified keys.
var Ecosystems = []string{"Go", "npm", "PyPI", "Alpine"}

type Provider struct {
	ecosystems []string
	baseURL    string
	client     *http.Client
}

func New(ecosystems []string, baseURL string) *Provider {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Provider{
		ecosystems: ecosystems,
		baseURL:    strings.TrimRight(baseURL, "/"),
		// A generous timeout: npm's archive alone is ~203 MB.
		client: &http.Client{Timeout: 30 * time.Minute},
	}
}

func (p *Provider) Name() string { return SourceName }

func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	prov := store.Provenance{Source: p.baseURL}
	var known int
	for _, eco := range p.ecosystems {
		u := fmt.Sprintf("%s/%s/all.zip", p.baseURL, url.PathEscape(eco))
		n, asOf, err := p.fetchOne(ctx, u, eco, emit)
		if err != nil {
			return store.Provenance{}, fmt.Errorf("fetch %s: %w", eco, err)
		}
		// There is no discovery step left to fail instead (release discovery
		// was removed once the per-release archives turned out to be a frozen
		// 2024-10-09 export): "Alpine" is now the sole source for every
		// release, so zero matching records here means Convert's family match
		// broke or the archive's shape changed, not that Alpine has no
		// advisories. Building a database that silently has none turns every
		// later Alpine scan into a clean report at exit 0 — the same failure
		// discovery's hard-fail existed to prevent, one layer further in.
		if eco == "Alpine" && n == 0 {
			return store.Provenance{}, fmt.Errorf("fetch %s: archive yielded no Alpine:* records", eco)
		}
		prov.Records += n
		if asOf.IsZero() {
			continue
		}
		known++
		// The oldest upstream timestamp wins: a database is only as fresh as
		// its stalest provider, and reporting the newest would hide that.
		if prov.DataAsOf.IsZero() || asOf.Before(prov.DataAsOf) {
			prov.DataAsOf = asOf
		}
	}
	// If any ecosystem gave no timestamp, the aggregate is unknown rather than
	// the minimum of the rest. Reporting min(known) would claim a floor on
	// staleness we cannot establish — the one we could not date may be the
	// oldest. `db status` renders the zero value as "unknown", which is the
	// honest answer.
	if known != len(p.ecosystems) {
		prov.DataAsOf = time.Time{}
	}
	return prov, nil
}

func (p *Provider) fetchOne(ctx context.Context, u, ecosystem string, emit func(advisory.Advisory) error) (int, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, time.Time{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, time.Time{}, fmt.Errorf("GET %s: %s", u, resp.Status)
	}

	// DataAsOf comes from the server, not from the local clock (D12): a mirror
	// serving a stale snapshot must not look fresh because we fetched it today.
	var asOf time.Time
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			asOf = t.UTC()
		}
	}

	// archive/zip needs a ReaderAt, so the archive is buffered. Records are
	// still streamed to emit one at a time.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, time.Time{}, err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("open zip: %w", err)
	}

	var kept int
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return kept, asOf, fmt.Errorf("open %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return kept, asOf, fmt.Errorf("read %s: %w", f.Name, err)
		}
		a, ok, err := Convert(data, ecosystem)
		if err != nil {
			return kept, asOf, fmt.Errorf("convert %s: %w", f.Name, err)
		}
		if !ok {
			continue
		}
		if err := emit(a); err != nil {
			return kept, asOf, err
		}
		kept++
	}
	return kept, asOf, nil
}
