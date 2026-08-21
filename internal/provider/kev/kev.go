// Package kev converts CISA's Known Exploited Vulnerabilities catalog into
// advisory.Rating: a statement that a CVE IS being exploited, independent of
// which package is affected -- the same D27 shape provider/epss and
// provider/nvd use. It enters through provider.Annotator for the identical
// reason: the catalog never says a package is affected, only that a CVE
// itself is on the list (D86).
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Checked here, not just at the first caller: a method added to
// provider.Annotator without a matching change here should fail this
// package's own build (nvd.go's own doc comment gives the full reasoning).
var _ provider.Annotator = (*Provider)(nil)

// SourceName identifies ratings this provider supplied.
const SourceName = "KEV"

// DefaultURL is CISA's own JSON catalog -- the whole list in one file,
// unauthenticated, regenerated as entries are added.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Options configures New, on epss.Options' own shape: a URL seam for tests,
// a Progress writer so a build that downloads and parses this file is not
// silent while it does.
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
		// The catalog is ~1.6 MB (measured 2026-08-21) -- generous, but
		// nowhere near NVD's ten minutes.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return SourceName }

// feed is CISA's top-level document shape. Only what this provider actually
// uses is modeled; catalogVersion and title are echoed in the progress line
// but not stored, and dueDate is deliberately absent from entry below (see
// its own comment).
type feed struct {
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Count           int     `json:"count"`
	Vulnerabilities []entry `json:"vulnerabilities"`
}

type entry struct {
	CveID     string `json:"cveID"`
	DateAdded string `json:"dateAdded"`
	// KnownRansomwareCampaignUse is CISA's own "Known"/"Unknown" verbatim
	// (both values measured 2026-08-21). Stored as-is on advisory.Rating
	// rather than parsed into a bool, so a third value CISA ever publishes
	// arrives as data a reader can see, not a silent parse failure or a
	// forced false.
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	// dueDate is deliberately NOT modeled here. advisory.Rating.KEVDateAdded's
	// own doc comment explains why: it is a US federal compliance deadline
	// (BOD 22-01), not a technical fact about the vulnerability, and
	// surfacing it unlabelled in a Rating would misread as remediation
	// advice this project has no basis to give a non-federal reader.
}

// Annotate downloads the catalog, checks it against its own declared count
// (refusing a feed that contradicts itself rather than trusting whichever
// number is wrong), and emits one Rating per entry.
func (p *Provider) Annotate(ctx context.Context, emit func(advisory.Rating) error) (store.Provenance, error) {
	body, err := p.fetch(ctx)
	if err != nil {
		return store.Provenance{}, err
	}
	defer body.Close()

	var f feed
	if err := json.NewDecoder(body).Decode(&f); err != nil {
		return store.Provenance{}, fmt.Errorf("kev: decode: %w", err)
	}

	// Integrity check, not a formality: count is CISA's own claim about how
	// many entries the file holds, so a mismatch means the download was
	// truncated or the array was reshaped, and either way silently
	// proceeding on a partial list under-reports what is actually known
	// exploited.
	if f.Count != len(f.Vulnerabilities) {
		return store.Provenance{}, fmt.Errorf(
			"kev: catalog declares count=%d but carries %d entries -- refusing a feed that contradicts itself",
			f.Count, len(f.Vulnerabilities))
	}

	// D12: DataAsOf is the upstream data's own currency, never fetch time.
	// dateReleased carries fractional seconds of varying length in the live
	// feed ("2026-08-20T17:00:27.8837Z", four digits, measured 2026-08-21);
	// time.Parse(time.RFC3339, ...) accepts a fractional-second field of any
	// length even though the layout constant only spells three digits (the
	// stdlib's own documented leniency for parsing, verified against Go
	// 1.26), so no separate layout is needed the way nvd's parseTimestamp
	// needs several.
	asOf, err := time.Parse(time.RFC3339, f.DateReleased)
	if err != nil {
		return store.Provenance{}, fmt.Errorf("kev: parse dateReleased %q: %w", f.DateReleased, err)
	}

	var records, ransomwareKnown int
	for _, v := range f.Vulnerabilities {
		// Mirrors nvd.convert's own "no id" skip: an entry with no cveID
		// would otherwise store under the key "\x00KEV", unreachable by
		// RatingsFor (which only ever asks about "CVE-" identifiers) but
		// still counted by SetMeta's per-source split -- over-claiming
		// coverage for an entry nothing can read back. None measured in the
		// live catalog (0 of 1,673, 2026-08-21).
		if v.CveID == "" {
			continue
		}
		if v.KnownRansomwareCampaignUse == "Known" {
			ransomwareKnown++
		}
		if err := emit(advisory.Rating{
			CVE:           v.CveID,
			Source:        SourceName,
			KEV:           true,
			KEVDateAdded:  v.DateAdded,
			KEVRansomware: v.KnownRansomwareCampaignUse,
			URL:           "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		}); err != nil {
			return store.Provenance{}, err
		}
		records++
	}

	fmt.Fprintf(p.progress, "kev: %d entries emitted, %d ransomware-known, catalog %s, released %s\n",
		records, ransomwareKnown, f.CatalogVersion, asOf.Format("2006-01-02"))

	// D20's coverage guard, the same shape every other provider's Fetch/
	// Annotate ends on: a parse that passed the count check but somehow
	// emitted nothing must fail the build rather than write a database
	// that answers every KEV lookup with silence.
	if records == 0 {
		return store.Provenance{}, fmt.Errorf(
			"kev: catalog declared %d entries but none carried a usable cveID", f.Count)
	}

	return store.Provenance{
		Source:   p.url,
		DataAsOf: asOf,
		Records:  records,
		// The whole catalog, every build -- epss.Annotate's own Window
		// comment gives the identical reasoning: there is no partial-window
		// concept here, so this is recorded as unbounded (broadest) rather
		// than left unrecorded.
		Window:           "the whole feed",
		CoversSinceKnown: true,
		CoversUntilKnown: true,
	}, nil
}

// fetchAttempts, fetchBackoff, retryable and sleepOrDone mirror
// internal/provider/epss's own copies exactly, on the same reasoning
// (epss.go's doc comments) -- a single whole-file GET, retried a few times
// against a transient failure, on a deny-list classification keyed on the
// caller's own context rather than an enumerated allow-list of transient
// error shapes.
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
			fmt.Fprintf(p.progress, "kev: fetch failed (%v); retrying (attempt %d of %d)\n",
				lastErr, attempt, fetchAttempts)
		}
		body, status, err := p.get(ctx)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable(ctx, status) {
			return nil, fmt.Errorf("kev: fetch %s: %w", p.url, err)
		}
	}
	return nil, fmt.Errorf("kev: fetch %s: %d attempts: %w", p.url, fetchAttempts, lastErr)
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
