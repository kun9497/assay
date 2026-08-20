// Package fedora converts Fedora's Bodhi security updates into the internal
// advisory shape (D1) -- the last of the buildable RPM-family distros
// (D75), following Amazon Linux (D73) and Oracle Linux (D74) as assay's
// third non-OSV *advisory* provider.
//
// There is no OSV shortcut here at all, unlike Rocky and AlmaLinux: measured
// 2026-08-19, osv-vulnerabilities.storage.googleapis.com/Fedora/all.zip is a
// bare 404, the bucket lists nothing under a "Fedora" prefix, and
// api.osv.dev/v1/query rejects both "Fedora" and "Fedora:43" as an invalid
// ecosystem. ossf/osv-schema simply has no Fedora ecosystem. So this
// provider reads Bodhi's own updates REST API -- the same feed grype/vunnel
// use -- and normalizes it into OSV shape itself, the same move D74 made for
// Oracle's OVAL archive.
//
// Three hazards ship with this slice, counted and disclosed rather than
// hidden:
//
//  1. EPEL fold-in. EPEL-9's release.version field is literally "9" -- keying
//     on version digits alone would fold RHEL-9 add-on advisories into
//     "Fedora:9". This provider filters on release.id_prefix == "FEDORA"
//     defensively (dropAndCount, see convertUpdate), on top of querying each
//     release by its own Bodhi name ("F43", not a bare "43").
//  2. CVE extraction is regex-over-prose, not structured. Bodhi's REST API
//     carries no dedicated CVE reference field at all (measured 2026-08-19:
//     even updateinfo.xml, the rejected alternative, has zero structured
//     reference type="cve" entries) -- vunnel's title-only method reaches
//     62.7% of updates, and scanning the notes field too raises that to a
//     measured ceiling of 81.7%. The remaining 18.3% is not silently
//     dropped: every update with no extractable CVE anywhere in title+notes
//     still becomes a finding, reachable by its own FEDORA-* id, and is
//     counted in stats.NoExtractableCVE so the miss is loud rather than a
//     number nobody sees.
//  3. Feeds freeze at EOL. A Fedora release is supported for about 13
//     months; F42 archived 2026-05-27 and its Bodhi data is now a
//     permanently frozen lower bound. Fetch prints which releases it asked
//     for and names this hazard explicitly (eolDisclosure below) -- the scan
//     side has no way to know a release went EOL, so the disclosure has to
//     live at build time.
//
// No CVSS vector exists anywhere in Bodhi's data (measured 2026-08-19: 0%).
// Severity is Bodhi's own five-word ladder -- urgent/high/medium/low/
// unspecified -- stored losslessly as a VENDOR_WORD entry (D13, D71
// decision 2) rather than renamed onto RHSA's Critical/Important/Moderate/
// Low vocabulary; the NVD join carries the rest via the CVE this provider
// places in Related.
package fedora

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// SourceName identifies records this provider supplied.
const SourceName = "fedora"

// DefaultBaseURL is Bodhi's updates REST endpoint.
const DefaultBaseURL = "https://bodhi.fedoraproject.org/updates/"

// pageSize is Bodhi's own documented maximum rows per page (measured
// 2026-08-19).
const pageSize = 100

// Release names one Bodhi release to fetch: the Bodhi release NAME the
// releases= query parameter takes ("F43", never a bare "43" -- release
// names are what tells Fedora and EPEL apart before id_prefix is even
// read) and the release-qualified ecosystem key it populates (D6).
type Release struct {
	Name      string
	Ecosystem string
}

// DefaultReleases is Bodhi's current stable Fedora releases, measured
// 2026-08-19 against https://bodhi.fedoraproject.org/releases/?rows_per_page=100:
// F43 and F44 (F42 archived 2026-05-27; F45/F46 pending). Fedora's ~6-month
// cadence and ~13-month support window mean this pair changes roughly twice
// a year -- keeping it current is a docs/deferred-decisions.md maintenance
// item, not a code change, because EOL freezes what is already stored
// rather than requiring one.
var DefaultReleases = []Release{
	{Name: "F43", Ecosystem: "Fedora:43"},
	{Name: "F44", Ecosystem: "Fedora:44"},
}

// pageRequestTimeout bounds ONE page fetch. Measured 2026-08-19: ~18s/100
// rows, heavier than a typical REST page because Bodhi embeds full comment
// threads. Generous margin over that, the same reasoning nvd.Provider's own
// client.Timeout doc comment gives for NVD's page latency: a page that is
// still running after this has hung rather than being slow.
const pageRequestTimeout = 2 * time.Minute

// maxPageBytes caps one page response. Bodhi's heaviest measured slice (3
// full releases, comment threads and all) was 30MB across ~32 pages, so a
// single page is ordinarily a few MB; this is a defensive ceiling against a
// misrouted response (an HTML error page, a redirect target) being read as
// an unbounded stream, not a bound expected to bind in practice.
const maxPageBytes = 64 << 20

// userAgent is descriptive rather than a browser string on purpose. Bodhi is
// fronted by the Anubis anti-bot proxy, and the research this slice shipped
// from measured a browser User-Agent getting "Access Denied" while plain
// curl/urllib passed -- Go's own default transport already looks nothing
// like a browser, and naming this build explicitly is the polite version of
// that same fact rather than an attempt to look like something else.
const userAgent = "assay-db-build/1.0 (+https://github.com/kun9497/assay)"

// eolDisclosure names which releases were fetched and the EOL-freeze hazard
// (#3 in the package doc comment): a scan of an EOL'd Fedora image has no
// in-band way to know its data stopped moving, so the warning has to live
// here, at build time, and in FEDORA_ENABLE's usage text -- mirroring how
// amazon.extrasDisclosure's own doc comment justifies printing a coverage
// gap rather than leaving it to a comment nobody reads.
func eolDisclosure(releases []Release) string {
	names := make([]string, len(releases))
	for i, r := range releases {
		names[i] = r.Name
	}
	return fmt.Sprintf(
		"fedora: fetching %s only (Bodhi's current stable releases) -- Fedora's ~13-month "+
			"support window means an EOL'd release (F42 archived 2026-05-27) gets NO new "+
			"advisories from this feed ever again; a scan of an EOL'd Fedora image is a frozen "+
			"lower bound with no in-band signal that it stopped moving (docs/deferred-decisions.md)",
		strings.Join(names, ", "))
}

type Options struct {
	// Releases defaults to DefaultReleases. A test seam, the same role
	// amazon.Options.Repos and oracle.Options.URL play: it lets a test point
	// at an httptest server without DefaultReleases' live Bodhi endpoint
	// ever being reached.
	Releases []Release
	// BaseURL defaults to DefaultBaseURL. A test seam for the same reason.
	BaseURL string
	// Progress is where the EOL disclosure, per-page lines and the fetch
	// summary go, or nil for io.Discard.
	Progress io.Writer
}

type Provider struct {
	releases []Release
	baseURL  string
	progress io.Writer
	client   *http.Client
}

func New(opts Options) *Provider {
	releases := opts.Releases
	if len(releases) == 0 {
		releases = DefaultReleases
	}
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		releases: releases,
		baseURL:  baseURL,
		progress: progress,
		client:   &http.Client{Timeout: pageRequestTimeout},
	}
}

func (p *Provider) Name() string { return "Fedora Bodhi Updates" }

// Fetch pages Bodhi's updates REST API for every configured release and
// emits one advisory per FEDORA-* update.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	fmt.Fprintln(p.progress, eolDisclosure(p.releases))

	var st stats
	var sources []string
	covered := map[string]bool{}
	var asOf time.Time
	haveAsOf := true
	total := 0

	for _, r := range p.releases {
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		kept, relAsOf, err := p.fetchRelease(ctx, r, emit, &st)
		if err != nil {
			return store.Provenance{}, fmt.Errorf("fedora: %s: %w", r.Ecosystem, err)
		}
		// D20's guard, the same shape amazon.Fetch and oracle.Fetch both end
		// on: a release yielding zero advisories means the security-type
		// filter broke, the id_prefix guard ate everything, or the feed's
		// shape changed -- not that Bodhi published no security update for a
		// current release. A database that silently holds none turns every
		// later scan of that release into a clean report at exit 0.
		if kept == 0 {
			return store.Provenance{}, fmt.Errorf(
				"fedora: %s yielded no advisories out of %d updates; "+
					"the feed's shape may have changed or the security-type/id_prefix filter no longer matches",
				r.Ecosystem, st.Updates)
		}
		total += kept
		covered[r.Ecosystem] = true
		sources = append(sources, p.pageURL(r.Name, 1))
		if relAsOf.IsZero() {
			haveAsOf = false
			continue
		}
		// The stalest release wins (amazon.Fetch's own reasoning, applied
		// here across two releases instead of two repos): a database is
		// only as fresh as its least current source.
		if asOf.IsZero() || relAsOf.Before(asOf) {
			asOf = relAsOf
		}
	}
	if !haveAsOf {
		// If any release gave no timestamp at all, the aggregate is unknown
		// rather than the other release's date: reporting a floor we cannot
		// establish is the over-claim D12 exists to prevent.
		asOf = time.Time{}
	}

	fmt.Fprintln(p.progress, "fedora: "+st.String())

	ecos := make([]string, 0, len(covered))
	for e := range covered {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)

	return store.Provenance{
		Source:     strings.Join(sources, ", "),
		DataAsOf:   asOf,
		Records:    total,
		Ecosystems: ecos,
	}, nil
}

// progressEveryPages gates the per-page line. 1, not a larger stride:
// mirroring nvd.Provider.Annotate's own reasoning verbatim -- a page here is
// ~18s measured, so a full current-releases sync is on the order of twenty
// pages, and the line doubles as the pacing signal (nvd's own doc comment:
// "lines that stop arriving mean stalled, not slow"). A named constant
// rather than a bare "print every time" so a future release count that made
// per-page output too noisy has one place to widen the stride.
const progressEveryPages = 1

// fetchRelease pages through one release's security updates and emits every
// advisory it converts. asOf is the LATEST date_stable seen among this
// release's updates, computed even for one that is later skipped (D12).
func (p *Provider) fetchRelease(ctx context.Context, r Release, emit func(advisory.Advisory) error, st *stats) (int, time.Time, error) {
	var asOf time.Time
	kept := 0
	page := 1
	for {
		if err := ctx.Err(); err != nil {
			return kept, asOf, err
		}
		resp, err := p.fetchPageRetrying(ctx, r.Name, page, st)
		if err != nil {
			return kept, asOf, err
		}
		for _, u := range resp.Updates {
			st.Updates++
			// Defense in depth against the EPEL fold-in hazard (#1 in the
			// package doc comment): releases= already scopes the query to
			// "F43"/"F44", which EPEL's own release names ("EPEL-9") never
			// collide with, but a server-side change to that filter must
			// not silently start folding EPEL-9 advisories (whose
			// release.version is literally "9") into a Fedora key.
			if !strings.EqualFold(u.Release.IDPrefix, "FEDORA") {
				st.SkippedWrongPrefix++
				continue
			}
			adv, when, ok := convertUpdate(u, r.Ecosystem, st)
			if when.After(asOf) {
				asOf = when
			}
			if !ok {
				continue
			}
			if err := emit(adv); err != nil {
				return kept, asOf, err
			}
			st.Advisories++
			kept++
		}
		if page%progressEveryPages == 0 || page >= resp.Pages {
			fmt.Fprintf(p.progress, nlFmt("fedora: %s page %d/%d, %d updates -> %d advisories so far"),
				r.Name, page, resp.Pages, st.Updates, st.Advisories)
		}
		if resp.Pages <= 0 || page >= resp.Pages {
			break
		}
		page++
	}
	return kept, asOf, nil
}

// nlFmt appends a newline to a format string. Assembled rather than typed,
// per CLAUDE.md's "never type an escape sequence as a literal": one helper
// is cheaper than remembering that at every call site (nvd.nlFmt's own
// doc comment gives the identical reasoning).
func nlFmt(s string) string { return s + string(rune(10)) }

// pageURL builds one page's request URL.
func (p *Provider) pageURL(release string, page int) string {
	v := url.Values{}
	v.Set("status", "stable")
	v.Set("type", "security")
	v.Set("releases", release)
	v.Set("rows_per_page", strconv.Itoa(pageSize))
	v.Set("page", strconv.Itoa(page))
	return p.baseURL + "?" + v.Encode()
}

// fetchPageOnce is one attempt at one page. It returns the HTTP status
// alongside the error so the caller can classify without parsing a message;
// status is 0 when the request never produced a response.
func (p *Provider) fetchPageOnce(ctx context.Context, release string, page int) (bodhiPage, int, error) {
	u := p.pageURL(release, page)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return bodhiPage{}, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return bodhiPage{}, 0, fmt.Errorf("fedora: fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return bodhiPage{}, resp.StatusCode, fmt.Errorf("fedora: fetch %s: %s", u, resp.Status)
	}
	var page_ bodhiPage
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPageBytes)).Decode(&page_); err != nil {
		return bodhiPage{}, resp.StatusCode, fmt.Errorf("fedora: decode %s: %w", u, err)
	}
	return page_, resp.StatusCode, nil
}

// fetchPageRetrying retries one page through a transient failure (D58's
// shape, narrowed per this package's own retryable -- see retry.go).
func (p *Provider) fetchPageRetrying(ctx context.Context, release string, page int, st *stats) (bodhiPage, error) {
	var lastErr error
	for attempt := 1; attempt <= pageAttempts; attempt++ {
		if attempt > 1 {
			if err := sleepOrDone(ctx, pageBackoff(attempt-1)); err != nil {
				return bodhiPage{}, err
			}
			st.Retried++
		}
		resp, status, err := p.fetchPageOnce(ctx, release, page)
		if err == nil {
			// Counted only when a retry is what produced the answer, the
			// same split redhat.document keeps between "retried" (extra
			// work) and "rescued" (builds saved).
			if attempt > 1 {
				st.Rescued++
			}
			return resp, nil
		}
		lastErr = err
		if !retryable(err, status) {
			return bodhiPage{}, err
		}
	}
	return bodhiPage{}, fmt.Errorf("fedora: %d attempts fetching %s page %d: %w",
		pageAttempts, release, page, lastErr)
}

// stats accumulates what a sync discarded, for Options.Progress -- the same
// discipline amazon.stats and oracle.stats exist for.
type stats struct {
	Updates              int
	Advisories           int
	Packages             int
	SkippedNonSecurity   int
	SkippedWrongPrefix   int
	SkippedNoID          int
	SkippedNoPackages    int
	SkippedBadNVR        int
	SkippedNonRPMBuild   int
	UnrecognizedSeverity int
	// NoExtractableCVE is hazard #2's own counter (package doc comment): an
	// update whose title+notes carried no regex-matchable CVE anywhere.
	// Still emitted -- reachable by its own FEDORA-* id -- but counted so
	// the measured 18.3% ceiling is loud rather than invisible.
	NoExtractableCVE int
	Retried          int
	Rescued          int
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d updates -> %d advisories, %d package builds; skipped %d non-security, "+
			"%d wrong id_prefix (EPEL guard), %d with no id, %d with no packages, "+
			"%d unparseable NVRs, %d non-rpm builds; %d advisories carried no recognized "+
			"severity word; %d updates carried no extractable CVE; %d page fetch(es) retried, "+
			"%d rescued by retry",
		s.Updates, s.Advisories, s.Packages,
		s.SkippedNonSecurity, s.SkippedWrongPrefix, s.SkippedNoID, s.SkippedNoPackages,
		s.SkippedBadNVR, s.SkippedNonRPMBuild, s.UnrecognizedSeverity, s.NoExtractableCVE,
		s.Retried, s.Rescued)
}
