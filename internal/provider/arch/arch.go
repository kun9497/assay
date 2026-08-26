// Package arch converts Arch Linux's own security tracker feed
// (security.archlinux.org) into the internal advisory shape (D1). This is
// the last of D97's three pieces: a NEW provider (this package), a NEW
// pacman cataloger (internal/cataloger/pacmandb), and routing under the
// release-less sentinel key "Arch:rolling" (pkgmeta.Distro.Ecosystem's
// "arch" case), vunnel's and syft's own shared convention for a distro with
// no release axis at all.
//
// The feed: https://security.archlinux.org/json redirects (308) to
// https://security.archlinux.org/issues/all.json -- one bare JSON array of
// AVG (Arch Vulnerability Group) records, no wrapper object (measured
// 2026-08-26: 2,444 records, ~878 KB). See feed.go's row and buildAdvisories
// doc comments for the field inventory, the status vocabulary and its
// distribution, and the severity-word decision.
//
// Freshness (D12). Checked live 2026-08-26: neither
// security.archlinux.org/json NOR /issues/all.json sends a Last-Modified
// header (curl -I against both), and no record in the payload itself
// carries a date field of any kind (row's own doc comment -- the closest
// thing, `advisories`, names ASA bulletin ids, not dates; recovering a date
// from them would mean a second HTTP request per advisory, which
// vunnel's own parser does and this provider deliberately does not, since
// the brief asks only to use "the best available" signal, and there is no
// per-request date signal available at all here, unlike photon's Last-
// Modified header, found present on all three of ITS files). fetchAll
// reads a Last-Modified header defensively anyway (the same generic read
// photon.fetchMajor performs), so if Arch's server ever starts sending one
// this provider picks it up with no code change -- but DataAsOf is
// time.Now() on every run measured so far, unlike photon.fetchMajor's
// "defensive branch, not observed to actually fire" wording: here it is
// observed to ALWAYS fire.
//
// Zero-record guard: D20's ordinary shape -- a feed that yields no
// advisories at all means the schema changed or every status word this
// build recognizes stopped matching, not that Arch shipped zero fixed or
// vulnerable packages (2,236 of 2,444 measured 2026-08-26 carry a Fixed,
// Testing or Vulnerable status).
package arch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// SourceName identifies records this provider supplied.
const SourceName = "arch"

// Ecosystem is the one key every Affected entry this provider writes uses
// (D6, satisfied vacuously the way D88's Wolfi/Chainguard and D92's
// MinimOS/Echo already are: Arch has no release axis, so there is nothing
// for the key to lose by being release-less). pkgmeta.Distro.Ecosystem's
// "arch" case must write the identical literal string, and
// internal/version's registry entry must key on it too -- not cross-checked
// against those two by a test in THIS package (importing pkgmeta/version
// here would be a cycle risk neither needs), but each is pinned on its own
// side: pkgmeta.TestDistroEcosystem_Arch, version.TestFor_ArchRollingResolvesPacman
// and version.TestNoUnbackedDistroComparer's exact-key-set guard, and
// scancmd.TestCatalogFromImage_PacmanPackagesAreKeyed, which drives a real
// image through pkgmeta's routing and asserts the literal "Arch:rolling"
// string reaches a cataloged package.
const Ecosystem = "Arch:rolling"

// DefaultURL is the endpoint this provider fetches (verified live
// 2026-08-26: security.archlinux.org/json 308-redirects here). Fetching the
// redirect target directly rather than following the redirect saves
// nothing measurable but documents which URL is actually read.
const DefaultURL = "https://security.archlinux.org/issues/all.json"

type Options struct {
	// URL defaults to DefaultURL. A test seam, the same role
	// photon.Options.BaseURL and redhat.Options.BaseURL play: it lets a
	// test point at an httptest server without the live host ever being
	// reached.
	URL string
	// Progress is where the drop-count summary goes, or nil for io.Discard.
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
		// One file, ~878 KB measured 2026-08-26 -- nowhere near Red Hat's
		// 262 MB archive or NVD's seven hours, but a generous bound rather
		// than http.Client's own unbounded default.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Arch Linux Security Tracker" }

// Fetch downloads the AVG feed, converts every group into zero or one
// advisory (buildAdvisories, feed.go), and emits each one.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	rows, when, haveHeader, err := p.fetchAll(ctx)
	if err != nil {
		return store.Provenance{}, fmt.Errorf("arch: %w", err)
	}
	if !haveHeader {
		fmt.Fprintf(p.progress, "arch: %s carries no Last-Modified header; "+
			"using the local clock instead, so this run's freshness reading may overstate "+
			"how current the data is (verified absent on both /json and /issues/all.json, 2026-08-26)\n",
			p.url)
	}

	advisories, st := buildAdvisories(rows)
	// D20's guard: a feed that yields zero advisories means the shape
	// changed or the status filters no longer match, not that Arch shipped
	// nothing fixed or vulnerable (2,236 of 2,444 measured 2026-08-26).
	if len(advisories) == 0 {
		return store.Provenance{}, fmt.Errorf(
			"arch: %d record(s) yielded no advisories; the feed's shape may have changed "+
				"or the status filters no longer match", st.Records)
	}
	for _, adv := range advisories {
		if err := emit(adv); err != nil {
			return store.Provenance{}, err
		}
	}

	fmt.Fprintln(p.progress, "arch: "+st.String())

	return store.Provenance{
		Source:     p.url,
		DataAsOf:   when,
		Records:    len(advisories),
		Ecosystems: []string{Ecosystem},
	}, nil
}

// fetchAll downloads and decodes the feed, returning its rows and the
// upstream freshness time (D12).
//
// haveHeader is false, and when falls back to time.Now(), whenever the
// response carries no Last-Modified -- which is every response measured
// live against this feed, 2026-08-26 (unlike photon.fetchMajor's identical
// fallback, kept there only as an unobserved defensive branch, this one is
// the ordinary path here).
func (p *Provider) fetchAll(ctx context.Context) (rows []row, when time.Time, haveHeader bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("fetch %s: %w", p.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, false, fmt.Errorf("fetch %s: %s", p.url, resp.Status)
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, perr := http.ParseTime(lm); perr == nil {
			when, haveHeader = t.UTC(), true
		}
	}
	if !haveHeader {
		when = time.Now().UTC()
	}

	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("decode %s: %w", p.url, err)
	}
	return rows, when, haveHeader, nil
}
