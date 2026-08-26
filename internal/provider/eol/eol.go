// Package eol converts endoflife.date's product catalog into
// store.EOLRelease rows: when a distro release stops being supported, the
// last grype-parity enrichment gap (D87). It enters through
// provider.EOLSource, a third source shape alongside Provider/Annotator/
// Enricher — see that interface's own doc comment for why none of the three
// existing ones fit.
package eol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Checked here, not just at the first caller: a method added to
// provider.EOLSource without a matching change here should fail this
// package's own build, not surface as a missing-method error somewhere else
// entirely (nvd.go's own doc comment gives the full reasoning).
var _ provider.EOLSource = (*Provider)(nil)

// SourceName identifies this source in `db status`'s EOL line and in the
// build's timing table.
const SourceName = "endoflife.date"

// DefaultURL is endoflife.date's v1 "full" product listing — one request,
// the whole catalog (~2.7 MB, 464 products measured 2026-08-21), rather than
// the per-product v0 endpoints or the lighter v1 index/summary endpoints:
// the summary omits labels.eol/labels.eoes prose (D87's own reason the
// isEol boolean is not trustworthy enough to store on its own), and one
// request for everything is cheaper to keep correct than 12 (one per distro
// this package keeps, D96 added Photon as the 12th) that could each fail
// independently.
const DefaultURL = "https://endoflife.date/api/v1/products/full"

// wantSlugs maps endoflife.date's own product slug to the os-release ID a
// scan's Target.Distro.ID actually carries. Mandatory, not derived from the
// v1 payload's own "aliases" list: aliases does not cover "amzn" or "ol" at
// all (verified against the live payload, 2026-08-21), so trusting it would
// leave Amazon Linux and Oracle Linux silently unlookupable despite their
// rows being stored under the wrong key.
var wantSlugs = map[string]string{
	"debian":       "debian",
	"ubuntu":       "ubuntu",
	"rhel":         "rhel",
	"alpine-linux": "alpine",
	"rocky-linux":  "rocky",
	"almalinux":    "almalinux",
	"amazon-linux": "amzn",
	"oracle-linux": "ol",
	"fedora":       "fedora",
	"sles":         "sles",
	"opensuse":     "opensuse-leap",
	// D96: endoflife.date's own slug IS "photon" (verified live 2026-08-26),
	// unlike amazon-linux/oracle-linux above -- an identity mapping, but
	// still a deliberate entry in this table rather than trusted from the
	// v1 payload's own "aliases" list, for the same reason every row here
	// is: aliases is not consulted at all (this table's own doc comment).
	"photon": "photon",
}

// Options configures New, on epss.Options'/kev.Options' own shape: a URL
// seam so a test can point at an httptest server without DefaultURL's live
// catalog ever being fetched from, and a Progress writer so a build that
// downloads and parses this file is not silent while it does.
type Options struct {
	URL      string
	Progress io.Writer
}

type Provider struct {
	url      string
	progress io.Writer
	client   *http.Client
}

func New(opts Options) *Provider {
	url := opts.URL
	if url == "" {
		url = DefaultURL
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		url:      url,
		progress: progress,
		// Generous but nowhere near NVD's ten minutes: the payload is ~2.7 MB,
		// measured 2026-08-21.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return SourceName }

// document is the v1 "full" response's top-level shape. Only what this
// package actually reads is modeled -- schema_version is neither read nor
// asserted, on the same "additive changes are fine, structural ones are
// caught by the integrity checks below" basis kev.feed already takes with
// catalogVersion.
type document struct {
	GeneratedAt string    `json:"generated_at"`
	Total       int       `json:"total"`
	Result      []product `json:"result"`
}

type product struct {
	Name     string    `json:"name"` // endoflife.date's own slug, e.g. "alpine-linux"
	Labels   labels    `json:"labels"`
	Releases []release `json:"releases"`
}

// labels carries the phase prose EOLRelease.EOLLabel/EOESLabel store. A
// pointer so a JSON null (every product's "discontinued" and "eoas", and
// most products' "eoes") decodes to a nil the strOrEmpty helper below turns
// into "", rather than the empty string silently meaning the same thing as
// "endoflife.date sent an empty label" (it never does, but the distinction
// is free to keep and matches how eolFrom/eoasFrom/eoesFrom on release are
// modeled a few lines down).
type labels struct {
	EOL  *string `json:"eol"`
	EOES *string `json:"eoes"`
}

// release is one entry in a product's releases array. isEoas and eoasFrom
// are read (into EOLRelease.EOASFrom) even though nothing in this package
// compares against them -- D13 stores what upstream publishes, not only
// what today's lookup needs.
type release struct {
	Name         string  `json:"name"`
	EOLFrom      *string `json:"eolFrom"`
	EOASFrom     *string `json:"eoasFrom"`
	EOESFrom     *string `json:"eoesFrom"`
	IsLTS        bool    `json:"isLts"`
	IsMaintained bool    `json:"isMaintained"`
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Fetch downloads the full product catalog, keeps only the 12 distro
// products wantSlugs names, and returns one store.EOLRelease per release
// those products publish.
func (p *Provider) Fetch(ctx context.Context) ([]store.EOLRelease, store.Provenance, error) {
	body, err := p.fetch(ctx)
	if err != nil {
		return nil, store.Provenance{}, err
	}
	defer body.Close()

	var doc document
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		return nil, store.Provenance{}, fmt.Errorf("eol: decode: %w", err)
	}

	// Integrity check, not a formality: total is endoflife.date's own claim
	// about how many products the file holds, so a mismatch means the
	// download was truncated or the array was reshaped, and either way
	// silently proceeding under-reports what is actually published -- the
	// same reasoning kev.Annotate's count check gives.
	if doc.Total != len(doc.Result) {
		return nil, store.Provenance{}, fmt.Errorf(
			"eol: catalog declares total=%d but carries %d product(s) -- refusing a feed that contradicts itself",
			doc.Total, len(doc.Result))
	}

	// D12: DataAsOf is the upstream data's own currency, never fetch time.
	asOf, err := time.Parse(time.RFC3339, doc.GeneratedAt)
	if err != nil {
		return nil, store.Provenance{}, fmt.Errorf("eol: parse generated_at %q: %w", doc.GeneratedAt, err)
	}

	var rows []store.EOLRelease
	matched := 0
	for _, prod := range doc.Result {
		distroID, ok := wantSlugs[prod.Name]
		if !ok {
			continue
		}
		matched++
		eolLabel := strOrEmpty(prod.Labels.EOL)
		eoesLabel := strOrEmpty(prod.Labels.EOES)
		for _, rel := range prod.Releases {
			rows = append(rows, store.EOLRelease{
				DistroID:     distroID,
				Release:      rel.Name,
				EOLFrom:      strOrEmpty(rel.EOLFrom),
				EOASFrom:     strOrEmpty(rel.EOASFrom),
				EOESFrom:     strOrEmpty(rel.EOESFrom),
				IsLTS:        rel.IsLTS,
				IsMaintained: rel.IsMaintained,
				EOLLabel:     eolLabel,
				EOESLabel:    eoesLabel,
			})
		}
	}

	fmt.Fprintf(p.progress, "eol: %d distro(s) matched (of %d wanted), %d release(s) emitted, generated %s\n",
		matched, len(wantSlugs), len(rows), asOf.Format("2006-01-02"))

	// D20/D78's coverage guard, one door over: a shape change upstream (a
	// renamed slug, a dropped product) must not ship a silently EOL-less
	// database that still passes every other check -- a scan that then asks
	// "is this image EOL" gets a confident "no" from a database that never
	// held the answer, indistinguishable from a genuinely current release.
	if len(rows) == 0 {
		return nil, store.Provenance{}, fmt.Errorf(
			"eol: matched 0 of %d wanted distro product(s) -- endoflife.date's shape may have changed", len(wantSlugs))
	}

	return rows, store.Provenance{
		Source:   p.url,
		DataAsOf: asOf,
		Records:  len(rows),
	}, nil
}

// fetchAttempts, fetchBackoff, retryable and sleepOrDone mirror
// internal/provider/epss's and internal/provider/kev's own copies exactly,
// on the same reasoning (epss.go's doc comments) -- a single whole-file GET,
// retried a few times against a transient failure. EOL_ENABLE defaults ON
// (cmd/assay/main.go) and this data feeds a gate (`--fail-on-eol`), so a
// build that fails after this bounded retry schedule rather than silently
// shipping without EOL data is the same trade EPSS/KEV already made.
const fetchAttempts = 3

// A package variable, not a plain function, so a test can shrink it -- see
// epss.fetchBackoff's own doc comment for the full reasoning.
var fetchBackoff = func(attempt int) time.Duration {
	return time.Duration(uint(1)<<uint(attempt-1)) * 500 * time.Millisecond
}

func retryable(ctx context.Context, status int) bool {
	if ctx.Err() != nil {
		return false
	}
	// 429 and every 5xx are the server saying "try later" -- checked FIRST,
	// because 503 is itself >= 400 and would otherwise fall into the next
	// check and be refused.
	if status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	// Any other 4xx is this code asking for the wrong thing, which asking
	// again will not fix.
	if status >= 400 {
		return false
	}
	// status == 0: a transport failure, transient by nature.
	return true
}

func sleepOrDone(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Provider) fetch(ctx context.Context) (io.ReadCloser, error) {
	var lastErr error
	for attempt := 1; attempt <= fetchAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 1 {
			if err := sleepOrDone(ctx, fetchBackoff(attempt-1)); err != nil {
				return nil, err
			}
			fmt.Fprintf(p.progress, "eol: fetch failed (%v); retrying (attempt %d of %d)\n",
				lastErr, attempt, fetchAttempts)
		}
		body, status, err := p.get(ctx)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable(ctx, status) {
			return nil, fmt.Errorf("eol: fetch %s: %w", p.url, err)
		}
	}
	return nil, fmt.Errorf("eol: fetch %s: %d attempts: %w", p.url, fetchAttempts, lastErr)
}

func (p *Provider) get(ctx context.Context) (io.ReadCloser, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, resp.StatusCode, fmt.Errorf("%s", resp.Status)
	}
	return resp.Body, resp.StatusCode, nil
}
