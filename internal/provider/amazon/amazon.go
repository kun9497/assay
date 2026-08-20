// Package amazon converts Amazon Linux's ALAS security advisories into the
// internal advisory shape (D1). It is assay's first non-OSV *advisory*
// provider besides Red Hat's CSAF VEX feed (D47-D51): Amazon publishes no
// OSV archive at all (measured 2026-08-19 against
// osv-vulnerabilities.storage.googleapis.com/ecosystems.txt), so there is no
// zip to download and filter the way internal/provider/osv does for every
// other distro.
//
// The feed instead is the same "yum updateinfo" XML every RPM-based repo
// tool publishes: a repomd.xml pointer to a gzip-compressed updateinfo.xml
// carrying one <update> per ALAS. Getting there from a fixed URL takes two
// indirections, both load-bearing and neither hardcodable — see resolveMirror
// and updateinfoHref.
//
// No modularity. Amazon Linux ships no module streams the way RHEL/Rocky/
// AlmaLinux's `module+el`/`module_el` platform tags mark (D46, D71
// decision 3) — every release string measured across both core feeds is an
// ordinary "N.amznM[.P]" suffix. matcher.rpmModuleBuild's own pattern simply
// never matches one, so internal/matcher's existing module-build guard
// (shared by every RPM-family ecosystem, gated on the comparer rather than a
// hardcoded ecosystem list) is inert here by construction, not by a new
// special case — which is also why this package adds no module-build test of
// its own: there is no guard behaviour unique to Amazon Linux to prove.
package amazon

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// SourceName identifies records this provider supplied.
const SourceName = "amazon"

// Repo names one ALAS feed to fetch: the release-qualified ecosystem key it
// populates (D6) and the mirror.list URL that is the feed's only fixed
// entry point.
type Repo struct {
	Ecosystem     string
	MirrorListURL string
}

// DefaultRepos is AL2 and AL2023's CORE repos — the scope this slice covers,
// measured 2026-08-19: 2,320 AL2 advisories and 2,010 AL2023 advisories, both
// 100% type=security/status=final, 100% severity-banded, 98%+ CVE-referenced.
//
// Deliberately NOT the full picture. AL2 alone has 73 more "extras" repos
// (docker, ecs, livepatch, nitro-enclaves, firefox and 29 namespaces in all,
// ~964 advisories none of which appear in core) and AL2023 keeps its NVIDIA
// and livepatch advisories outside core the same way. Fetch's own disclosure
// line and the AMAZON_ENABLE usage text both name this gap — see
// extrasDisclosure below — rather than let a core-only database read as a
// complete one.
var DefaultRepos = []Repo{
	{Ecosystem: "Amazon Linux:2", MirrorListURL: "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"},
	{Ecosystem: "Amazon Linux:2023", MirrorListURL: "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"},
}

// extrasDisclosure is printed once per Fetch, mirroring dbcmd.Update's own
// seed-disclosure line: a build that silently narrows its own coverage looks
// exactly like one that is broken, and the KISA/Red Hat providers already
// treat "print the gap on stderr" as the fix rather than a comment nobody
// reads (see redhat.Options.Progress's own doc comment for the same
// reasoning applied to its container/module skips).
const extrasDisclosure = "amazon: fetching CORE repositories only -- AL2's 73 extras repos " +
	"(~964 advisories across docker, ecs, livepatch, nitro-enclaves, firefox and more) and " +
	"AL2023's NVIDIA/livepatch repos are NOT fetched; a package installed from one of those " +
	"is evaluated only against core data (docs/deferred-decisions.md)"

type Options struct {
	// Repos defaults to DefaultRepos. A test seam, the same role
	// redhat.Options.BaseURL plays: it lets a test point at an httptest
	// server without DefaultRepos' live CDN ever being reached.
	Repos []Repo
	// Progress is where the disclosure line and the fetch summary go, or nil
	// for io.Discard.
	Progress io.Writer
}

type Provider struct {
	repos    []Repo
	progress io.Writer
	client   *http.Client
}

func New(opts Options) *Provider {
	repos := opts.Repos
	if len(repos) == 0 {
		repos = DefaultRepos
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		repos:    repos,
		progress: progress,
		// Generous but bounded: two repos, ~1.5 MB gzip each measured
		// 2026-08-19, nowhere near Red Hat's 262 MB archive.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Amazon Linux ALAS" }

// Fetch resolves each configured repo's mirror.list -> repomd.xml ->
// updateinfo.xml.gz chain and emits one advisory per ALAS.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	fmt.Fprintln(p.progress, extrasDisclosure)

	var st stats
	var sources []string
	covered := map[string]bool{}
	var asOf time.Time
	haveAsOf := true
	total := 0

	for _, r := range p.repos {
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		kept, repoAsOf, err := p.fetchRepo(ctx, r, emit, &st)
		if err != nil {
			return store.Provenance{}, fmt.Errorf("amazon: %s: %w", r.Ecosystem, err)
		}
		// D20's guard, one repo at a time, mirroring
		// osv.Provider.Fetch's own per-ecosystem guard: a repo yielding
		// zero advisories means the security-type filter broke or the
		// feed's shape changed, not that Amazon published no ALAS for
		// it -- every core repo measured 2026-08-19 carries thousands.
		// A database that silently holds none turns every later scan of
		// that release into a clean report at exit 0.
		if kept == 0 {
			return store.Provenance{}, fmt.Errorf(
				"amazon: %s yielded no advisories out of %d updates; "+
					"the feed's shape may have changed or the security-type filter no longer matches",
				r.Ecosystem, st.Updates)
		}
		total += kept
		covered[r.Ecosystem] = true
		sources = append(sources, r.MirrorListURL)
		if repoAsOf.IsZero() {
			haveAsOf = false
			continue
		}
		// The stalest repo wins (osv.Provider.Fetch's own reasoning,
		// applied here across two repos instead of many ecosystems): a
		// database is only as fresh as its least current source, and
		// reporting the newest would hide that.
		if asOf.IsZero() || repoAsOf.Before(asOf) {
			asOf = repoAsOf
		}
	}
	if !haveAsOf {
		// If either repo gave no timestamp at all, the aggregate is unknown
		// rather than the other repo's date: reporting a floor we cannot
		// establish is the over-claim D12 exists to prevent.
		asOf = time.Time{}
	}

	fmt.Fprintln(p.progress, "amazon: "+st.String())

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

// fetchRepo resolves one repo's mirror.list -> repomd.xml -> updateinfo
// chain and emits every advisory it converts. asOf is the LATEST issued/
// updated date seen among this repo's updates, computed even for one that
// is later skipped (a bugfix-type entry still says how current the feed
// snapshot is) -- see the hazard docs/deferred-decisions.md/the research
// this slice shipped from recorded: repomd's own <revision> lagged the
// updateinfo content by days on the very feed this measured, so freshness
// must be read from the advisories themselves (D12).
func (p *Provider) fetchRepo(ctx context.Context, r Repo, emit func(advisory.Advisory) error, st *stats) (int, time.Time, error) {
	mirror, err := p.resolveMirror(ctx, r.MirrorListURL)
	if err != nil {
		return 0, time.Time{}, err
	}
	href, err := p.updateinfoHref(ctx, mirror)
	if err != nil {
		return 0, time.Time{}, err
	}
	body, err := p.get(ctx, mirror+href)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer body.Close()
	gz, err := gzip.NewReader(body)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("open %s as gzip: %w", href, err)
	}
	defer gz.Close()

	var doc xmlUpdates
	if err := xml.NewDecoder(gz).Decode(&doc); err != nil {
		return 0, time.Time{}, fmt.Errorf("decode updateinfo: %w", err)
	}

	var asOf time.Time
	kept := 0
	for _, u := range doc.Updates {
		if err := ctx.Err(); err != nil {
			return kept, asOf, err
		}
		st.Updates++
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
	return kept, asOf, nil
}

// resolveMirror reads mirror.list and returns the first mirror URL it names,
// with a trailing slash. It must be followed rather than hardcoded: the
// resolved path carries a rotating GUID or content hash
// ("2/core/2.0/x86_64/81f0ad94.../", "al2023/core/guids/e56f3d93.../") that
// changes whenever Amazon republishes the repo, so caching or guessing it
// would eventually 404 or silently serve a frozen snapshot forever -- exactly
// the stale-mirror case D12 warns about.
func (p *Provider) resolveMirror(ctx context.Context, mirrorListURL string) (string, error) {
	body, err := p.get(ctx, mirrorListURL)
	if err != nil {
		return "", err
	}
	defer body.Close()
	// A mirror list is one short URL per line. The cap is what stops a
	// misrouted response -- an HTML error page, a redirect to a login -- from
	// being read as a URL and then requested, the same reasoning redhat.
	// archiveName's cap gives for its pointer file.
	b, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return "", fmt.Errorf("read mirror list %s: %w", mirrorListURL, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasSuffix(line, "/") {
			line += "/"
		}
		return line, nil
	}
	return "", fmt.Errorf("mirror list %s named no mirror", mirrorListURL)
}

// updateinfoHref reads repomd.xml and returns the updateinfo entry's
// location href, relative to mirror. Read rather than assumed to be
// "repodata/updateinfo.xml.gz": repomd.xml is the repo's own table of
// contents, and reading it is what makes this resilient to Amazon changing
// the checksum-qualified path the way it already does for every other entry
// in the file (primary.xml.gz, filelists.xml.gz, ...).
func (p *Provider) updateinfoHref(ctx context.Context, mirror string) (string, error) {
	body, err := p.get(ctx, mirror+"repodata/repomd.xml")
	if err != nil {
		return "", err
	}
	defer body.Close()
	var doc repomdXML
	if err := xml.NewDecoder(body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode repomd.xml at %s: %w", mirror, err)
	}
	for _, d := range doc.Data {
		if d.Type != "updateinfo" {
			continue
		}
		if d.Location.Href == "" {
			return "", fmt.Errorf("repomd.xml at %s names an updateinfo entry with no location", mirror)
		}
		return d.Location.Href, nil
	}
	return "", fmt.Errorf("repomd.xml at %s names no updateinfo entry", mirror)
}

func (p *Provider) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// stats accumulates what a sync discarded, for Options.Progress -- the same
// discipline redhat.stats exists for: a provider that quietly drops part of
// its input looks exactly like one that is broken.
type stats struct {
	Updates              int
	Advisories           int
	Packages             int
	SkippedNonSecurity   int
	SkippedNoID          int
	SkippedNoPackages    int
	UnrecognizedSeverity int
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d updates -> %d advisories, %d package entries; skipped %d non-security, "+
			"%d with no id, %d with no packages; %d advisories carried no recognized severity word",
		s.Updates, s.Advisories, s.Packages,
		s.SkippedNonSecurity, s.SkippedNoID, s.SkippedNoPackages, s.UnrecognizedSeverity)
}
