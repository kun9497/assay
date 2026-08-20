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
//
// No livepatch name-collision guard, for the same "measured, not assumed"
// reason (D78). ALAS2LIVEPATCH is the same hazard family as Oracle's ksplice
// lineage (internal/provider/oracle/oracle.go's own doc comment) — a package
// name an installed-livepatch advisory could accidentally also match against
// an ordinary mainline install. Measured live 2026-08-20 against the real
// feed: 297 ALAS2LIVEPATCH advisories name 277 distinct package names, and
// EVERY one is qualified "kernel-livepatch-<kernel-version>-<patch-version>"
// or that name plus "-debuginfo" — none is a bare mainline name ("kernel",
// "glibc", ...). 73 of those 277 names also appear in AL2 CORE's own
// updateinfo (a core kernel CVE that also affects the livepatch build for
// it), which is not the hazard either: the package name itself is still
// livepatch-qualified, so it can only ever match an actually-installed
// livepatch package. So this is the Repo.Extras' "distinct names" branch,
// not the "colliding names" one — ingested normally, with no drop-and-count
// guard, because measurement found nothing to drop. If a future measurement
// ever finds an ALAS2LIVEPATCH entry naming a bare mainline package, that is
// the trigger to add the guard, mirroring oracle's cross-definition
// dropAmbiguous (D74) rather than Ubuntu's report-as-not-evaluated (D53) —
// this feed can tell a livepatch package from a mainline one by name alone,
// which Ubuntu's +esmN/+FipsN suffix convention cannot.
package amazon

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
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
	// Extras marks a repo discovered through AL2's extras catalog (D78)
	// rather than named directly in DefaultRepos. It scopes the zero-advisory
	// guard in Fetch: a CORE repo yielding zero advisories is a
	// build-breaking anomaly (every core repo carries thousands, measured
	// 2026-08-19), but most extras topics legitimately carry none — 28 of 73
	// measured 2026-08-20 — so for an Extras repo a zero is counted, not an
	// error. Also what lets fetchRepo treat "repomd.xml names no updateinfo
	// entry at all" (errNoUpdateinfo) as the same kind of legitimate zero,
	// which 14 of those 28 topics take.
	Extras bool
}

// DefaultRepos is AL2 and AL2023's CORE repos, unchanged since D73: 2,320 AL2
// advisories and 2,010 AL2023 advisories measured 2026-08-19, both 100%
// type=security/status=final, 100% severity-banded, 98%+ CVE-referenced.
//
// AL2's 73 "extras" topic repos (docker, ecs, livepatch, nitro-enclaves,
// firefox and more) are deliberately NOT in this list — Fetch enumerates and
// fetches them separately, from AL2's own extras catalog (D78; see
// fetchExtrasTopics in extras.go), because that list is neither fixed nor
// small enough to hardcode the way these two entries are. Extras topics carry
// the same Ecosystem key as core, "Amazon Linux:2": a package installed from
// extras runs on the same OS core does, not a different release.
//
// AL2023 keeps its own extras-shaped gap open, and D78 does not close it:
// NVIDIA and livepatch repos live outside AL2023 core the way AL2's used to
// before D78, but AL2023 uses a different (DNF-module) repo layout that this
// slice's research did not extend the catalog-enumeration approach to.
// Fetch's own disclosure line names this — see extrasDisclosure below —
// rather than let a core-plus-AL2-extras database read as covering AL2023
// completely too.
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
//
// D78 closed the AL2 half of the gap D73 disclosed here: AL2's 73 extras
// topics are now enumerated and fetched alongside core. What remains is
// AL2023's own — NVIDIA (306 advisories) and livepatch (286 advisories) live
// outside AL2023 core, in a different DNF-module repo layout this slice did
// not extend to, so a package installed from either is still evaluated only
// against AL2023 core data.
const extrasDisclosure = "amazon: fetching AL2 core + all extras topics, and AL2023 core -- " +
	"AL2023's NVIDIA (306 advisories) and livepatch (286 advisories) repos are NOT fetched; " +
	"a package installed from either is evaluated only against AL2023 core data (D78)"

type Options struct {
	// Repos defaults to DefaultRepos. A test seam, the same role
	// redhat.Options.BaseURL plays: it lets a test point at an httptest
	// server without DefaultRepos' live CDN ever being reached.
	Repos []Repo
	// ExtrasBaseURL defaults to DefaultExtrasBaseURL. The same seam as Repos,
	// covering the piece Repos cannot: it lets a test point AL2's extras
	// catalog AND every topic it names at an httptest server, without
	// DefaultExtrasBaseURL's live CDN ever being reached.
	ExtrasBaseURL string
	// Progress is where the disclosure line and the fetch summary go, or nil
	// for io.Discard.
	Progress io.Writer
}

type Provider struct {
	repos         []Repo
	extrasBaseURL string
	progress      io.Writer
	client        *http.Client
}

func New(opts Options) *Provider {
	repos := opts.Repos
	if len(repos) == 0 {
		repos = DefaultRepos
	}
	extrasBaseURL := opts.ExtrasBaseURL
	if extrasBaseURL == "" {
		extrasBaseURL = DefaultExtrasBaseURL
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		repos:         repos,
		extrasBaseURL: extrasBaseURL,
		progress:      progress,
		// Generous but bounded: two core repos, ~1.5 MB gzip each measured
		// 2026-08-19, and up to 73 extras topics whose combined updateinfo is
		// smaller still (most carry zero advisories) — this is a per-request
		// timeout (http.Client's own semantics), so the count of requests
		// does not shrink it, and it is nowhere near Red Hat's 262 MB
		// archive.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Amazon Linux ALAS" }

// Fetch resolves each configured repo's mirror.list -> repomd.xml ->
// updateinfo.xml.gz chain and emits one advisory per ALAS.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	fmt.Fprintln(p.progress, extrasDisclosure)

	// D78: enumerated before any repo is fetched, so a broken catalog fails
	// the whole build the same way a broken core mirror.list already does,
	// rather than silently shipping a core-only database again.
	topics, err := p.fetchExtrasTopics(ctx)
	if err != nil {
		return store.Provenance{}, fmt.Errorf("amazon: extras catalog: %w", err)
	}
	// D20's guard again, one level up: a catalog that parses but names zero
	// topics means the document's shape changed (a renamed "n" field decodes
	// cleanly to nothing), not that Amazon deleted extras — the live catalog
	// carried 73 topics measured 2026-08-20. Without this, such a change
	// ships a silently core-only database: the exact regression D78 exists
	// to close, reported only as "extras: 0 topics" in a build log nobody
	// rereads.

	if len(topics) == 0 {
		return store.Provenance{}, fmt.Errorf(
			"amazon: extras catalog at %s%s parsed but named zero topics; "+
				"the catalog's shape may have changed", p.extrasBaseURL, extrasCatalogPath)
	}

	repos := make([]Repo, 0, len(p.repos)+len(topics))
	repos = append(repos, p.repos...)
	for _, topic := range topics {
		repos = append(repos, Repo{
			Ecosystem:     "Amazon Linux:2",
			MirrorListURL: p.extrasMirrorListURL(topic),
			Extras:        true,
		})
	}

	var st stats
	st.ExtrasTopics = len(topics)
	var sources []string
	covered := map[string]bool{}
	var asOf time.Time
	haveAsOf := true
	total := 0

	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		// This repo's own share of st.Updates, not the running total: with
		// up to 45 extras repos now sharing one stats accumulator, the error
		// below would otherwise report every update seen so far across every
		// repo, not this one's.
		updatesBefore := st.Updates
		kept, repoAsOf, err := p.fetchRepo(ctx, r, emit, &st)
		if err != nil {
			if r.Extras {
				return store.Provenance{}, fmt.Errorf("amazon: extras %s: %w", r.MirrorListURL, err)
			}
			return store.Provenance{}, fmt.Errorf("amazon: %s: %w", r.Ecosystem, err)
		}
		// D20's guard, one repo at a time, mirroring osv.Provider.Fetch's own
		// per-ecosystem guard: a CORE repo yielding zero advisories means the
		// security-type filter broke or the feed's shape changed, not that
		// Amazon published no ALAS for it -- every core repo measured
		// 2026-08-19 carries thousands. A database that silently holds none
		// turns every later scan of that release into a clean report at exit
		// 0.
		//
		// An extras topic is different (Repo.Extras' own doc comment): most
		// legitimately carry nothing, so a zero there is counted, not fatal.
		if kept == 0 {
			if !r.Extras {
				return store.Provenance{}, fmt.Errorf(
					"amazon: %s yielded no advisories out of %d updates; "+
						"the feed's shape may have changed or the security-type filter no longer matches",
					r.Ecosystem, st.Updates-updatesBefore)
			}
			st.ExtrasZeroAdvisoryTopics++
			continue
		}
		total += kept
		if r.Extras {
			st.ExtrasAdvisories += kept
		} else {
			sources = append(sources, r.MirrorListURL)
		}
		covered[r.Ecosystem] = true
		if repoAsOf.IsZero() {
			haveAsOf = false
			continue
		}
		// The stalest repo wins (osv.Provider.Fetch's own reasoning, applied
		// here across dozens of repos instead of many ecosystems): a
		// database is only as fresh as its least current source, and
		// reporting the newest would hide that.
		if asOf.IsZero() || repoAsOf.Before(asOf) {
			asOf = repoAsOf
		}
	}
	if !haveAsOf {
		// If any repo gave no timestamp at all, the aggregate is unknown
		// rather than another repo's date: reporting a floor we cannot
		// establish is the over-claim D12 exists to prevent.
		asOf = time.Time{}
	}
	// One entry for the whole extras catalog rather than up to 45 per-topic
	// mirror.list URLs: Source is meant to say WHERE the data came from, and
	// the catalog URL is the single entry point that determines every extras
	// URL fetched, the same role DefaultURL plays for oracle.Provider's
	// one-file archive. Unconditional because the zero-topics guard above
	// already refused any Fetch that read no topics.
	sources = append(sources, p.extrasBaseURL+extrasCatalogPath)

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
		if r.Extras && errors.Is(err, errNoUpdateinfo) {
			// See errNoUpdateinfo's own doc comment: a topic that never
			// published a security update at all is as legitimate a zero as
			// one whose updateinfo.xml.gz decodes to no <update> elements,
			// and the caller (Fetch) counts both the same way for an extras
			// repo. A core repo never reaches this branch — it returns the
			// error below unconditionally.
			return 0, time.Time{}, nil
		}
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
	return "", fmt.Errorf("repomd.xml at %s: %w", mirror, errNoUpdateinfo)
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
	// D78: AL2's extras catalog, layered on top of the two CORE repos above.
	// ExtrasAdvisories is a SUBSET of Advisories (every extras advisory is
	// also counted there), broken out so the summary line can say how much
	// of the total came from extras rather than leaving that folded in.
	ExtrasTopics             int
	ExtrasZeroAdvisoryTopics int
	ExtrasAdvisories         int
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d updates -> %d advisories, %d package entries; skipped %d non-security, "+
			"%d with no id, %d with no packages; %d advisories carried no recognized severity word; "+
			"extras: %d topics enumerated, %d with zero advisories, %d advisories ingested",
		s.Updates, s.Advisories, s.Packages,
		s.SkippedNonSecurity, s.SkippedNoID, s.SkippedNoPackages, s.UnrecognizedSeverity,
		s.ExtrasTopics, s.ExtrasZeroAdvisoryTopics, s.ExtrasAdvisories)
}
