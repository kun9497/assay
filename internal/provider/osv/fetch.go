package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// DefaultBaseURL is where OSV publishes one archive per ecosystem.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Ecosystems is the language-ecosystem scope. It is a fixed list because these
// keys never change. Distro ecosystems cannot be: they carry a release (D6)
// and Alpine publishes a new one every six months, so a hardcoded list would
// not fail — it would quietly stop covering new images.
var Ecosystems = []string{"Go", "npm", "PyPI"}

// AllEcosystems is what `assay db update` fetches: the fixed language list
// plus whatever Alpine releases the bucket currently publishes. Discovery is
// a network call, so callers on the scan path must never reach for this —
// only `db update` should.
func AllEcosystems(ctx context.Context) ([]string, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	alpine, err := AlpineEcosystems(ctx, c)
	if err != nil {
		// Do not fall back to the language list. Building a database that
		// silently contains no Alpine data, then scanning an Alpine image
		// against it, reports "no known vulnerabilities" — the exact failure
		// exit code 2 exists to prevent (D11).
		return nil, err
	}
	return append(slices.Clone(Ecosystems), alpine...), nil
}

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
