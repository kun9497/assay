// Package photon converts VMware/Broadcom Photon OS's own CVE metadata feed
// into the internal advisory shape (D1). Photon publishes no OSV archive at
// all (verified absent from
// osv-vulnerabilities.storage.googleapis.com/ecosystems.txt, 2026-08-26) --
// assay's fourth non-OSV *advisory* provider after Amazon Linux (D73),
// Oracle Linux (D74) and Fedora (D75), and the first RPM-family one whose
// feed is a flat JSON array rather than XML (yum updateinfo) or a paginated
// REST API.
//
// The feed. Three files, one per supported major --
// https://packages.broadcom.com/photon/photon_cve_metadata/cve_data_photon{3.0,4.0,5.0}.json
// -- each a bare JSON array of {cve_id, pkg, cve_score, aff_ver, res_ver,
// status} rows with no wrapper object and no nesting (measured 2026-08-26:
// 8,689 / 76,984 / 103,695 records, 189,368 combined, ~31.6 MB). A fourth
// file, photon_versions.json, names every branch VMware has ever shipped
// ({"branches": ["1.0", "2.0", "3.0", "4.0", "5.0"]} at measurement time) --
// deliberately NOT read here. See DefaultMajors' own doc comment for why the
// three supported majors are hardcoded rather than derived from it.
//
// Status is a two-value enum on every row measured: "Fixed" (a real
// res_ver, always a bare Version-Release with a ".phN" distro tag baked in,
// e.g. "1.20.2-10.ph5" -- 0 epochs across 165,850 Fixed rows, 2 rows in the
// 4.0 feed with no ".phN" suffix at all, ordinary data rather than a shape
// needing special handling) or "Not Affected" (aff_ver and res_ver both the
// literal "NA" on 100% of Not-Affected rows measured). There is no third
// state: Photon's schema has no way to say "affected, no fix yet" at all --
// unlike Red Hat's or SUSE's CSAF VEX, which carry an explicit
// known_affected/no-fix-available state (D52/D77), a Photon Not-Affected row
// means "this CVE never applied to this package", full stop, and produces
// no advisory.Range whatsoever (see feed.go's majorResult doc comment).
//
// Three data hazards, each with a user-decided fixed policy (see feed.go's
// processMajor and idClass for where each is applied and counted):
//
//  1. Fixed wins. 1,019 (cve, pkg, major) keys measured 2026-08-26 (0 in the
//     3.0 feed, 11 in 4.0's, 1,008 -- 1.22% of that feed's keys -- in 5.0's)
//     carry BOTH a Fixed row and a Not-Affected row for the same key. The
//     Fixed row wins and the Not-Affected row for that key is dropped,
//     counted but not otherwise surfaced -- the same choice vunnel's own
//     Photon feed reader makes, and the safer of the two: leaning
//     Not-Affected would silently drop a real, verifiable fix.
//  2. BDSA-* records (783 measured: 207 in the 4.0 feed, 576 in 5.0's) name
//     no CVE anywhere in the row -- dropped and counted (idBDSA, feed.go).
//  3. Sentinel/garbled ids ("Re", "UNK-1", "UNK-2"; 17 records measured, all
//     status=Not Affected -- so also dropped by rule 1's absence of a Fixed
//     counterpart, and by this classification independently) -- dropped and
//     counted (idSentinel, feed.go).
//
// Advisory shape and the D90 collision this provider avoids internally: see
// buildAdvisories' own doc comment in feed.go for why every major and every
// package sharing one CVE merge into ONE "PHOTON-"+cve advisory rather than
// one per major or per (cve, pkg) -- the short version is that Photon reuses
// one bare cve_id across all three per-major feed files with no
// release-specific advisory id anywhere in its own schema, unlike ALAS or
// FEDORA-*, so anything less than a global merge before emission would
// silently clobber records in the store's last-writer-wins by-id bucket
// (D90) for the 5,865 of 14,341 CVEs (measured) that are fixed in more than
// one Photon major.
//
// Freshness (D12). No date field exists anywhere in either JSON payload, so
// Provenance.DataAsOf is read from each file's own HTTP Last-Modified header
// instead -- verified live 2026-08-26 against all three
// cve_data_photon*.json endpoints (a JFrog Artifactory-fronted static file
// listing): every one carried the header. fetchMajor falls back to
// time.Now() when a response carries none, with a progress line naming the
// gap -- see that function's own doc comment for why the harder failure
// suse.archiveLastModified makes for a missing header is not taken here: the
// live measurement found no case of it actually happening, so refusing the
// whole build over a hazard that has not been observed once would trade a
// working default-on provider for a hypothetical.
package photon

import (
	"context"
	"encoding/json"
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
const SourceName = "photon"

// Major names one Photon OS release to fetch: the feed file's own version
// suffix and the release-qualified ecosystem key it populates (D6). The
// Ecosystem spelling ("Photon OS:3") is what pkgmeta.Distro.Ecosystem's
// "photon" case must also produce for a scanned image's packages to be
// keyed against this data at all -- see that case's own doc comment for why
// the key truncates VERSION_ID to the bare major rather than keeping it
// verbatim.
type Major struct {
	Version   string // "3.0", "4.0", "5.0" -- the feed file's own suffix
	Ecosystem string // "Photon OS:3", "Photon OS:4", "Photon OS:5"
}

// DefaultMajors is the three Photon OS majors this slice verified end to
// end (D96) against real images (mirror.gcr.io/library/photon:{3.0,4.0,5.0})
// and their real feed files: 189,368 records measured 2026-08-26 combined.
//
// Photon publishes its own manifest of every branch it has ever shipped at
// https://packages.broadcom.com/photon/photon_cve_metadata/photon_versions.json
// ({"branches": ["1.0", "2.0", "3.0", "4.0", "5.0"]} at measurement time) --
// deliberately NOT read here to derive this list. Two reasons: 1.0 and 2.0
// are both already past their own endoflife.date EOLFrom (verified live,
// 2026-08-26: 1.0 EOL 2022-02-28, 2.0 EOL 2022-12-01), and neither this
// list's feed files nor a real 1.0/2.0 image were fetched or verified this
// slice, so trusting the manifest would ingest data (and claim ecosystem
// coverage, D20) for two releases nothing here has confirmed the shape of.
// Hardcoding the majors this slice actually measured is the same "measured,
// not assumed" discipline amazon.DefaultRepos and fedora.DefaultReleases
// already follow for their own fixed lists. Add "6.0" here -- with its own
// Major.Ecosystem, a pkgmeta.Distro.Ecosystem test row, and a real image to
// verify os-release/rpmdb-backend against -- once VMware publishes it;
// photon_versions.json above is where to check first.
var DefaultMajors = []Major{
	{Version: "3.0", Ecosystem: "Photon OS:3"},
	{Version: "4.0", Ecosystem: "Photon OS:4"},
	{Version: "5.0", Ecosystem: "Photon OS:5"},
}

// DefaultBaseURL is Broadcom's own JFrog Artifactory listing of Photon's CVE
// metadata (verified live 2026-08-26). Each major's file is DefaultBaseURL +
// "cve_data_photon" + Major.Version + ".json".
const DefaultBaseURL = "https://packages.broadcom.com/photon/photon_cve_metadata/"

type Options struct {
	// Majors defaults to DefaultMajors. A test seam, the same role
	// amazon.Options.Repos and fedora.Options.Releases play: it lets a test
	// point at an httptest server without DefaultBaseURL's live host ever
	// being reached.
	Majors []Major
	// BaseURL defaults to DefaultBaseURL. A test seam for the same reason.
	BaseURL string
	// Progress is where the per-major Last-Modified warning (if any) and the
	// fetch summary go, or nil for io.Discard.
	Progress io.Writer
}

type Provider struct {
	majors   []Major
	baseURL  string
	progress io.Writer
	client   *http.Client
}

func New(opts Options) *Provider {
	majors := opts.Majors
	if len(majors) == 0 {
		majors = DefaultMajors
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
		majors:   majors,
		baseURL:  baseURL,
		progress: progress,
		// Generous but bounded: three files, ~31.6 MB combined measured
		// 2026-08-26 -- a per-request timeout (http.Client's own semantics),
		// nowhere near Red Hat's 262 MB archive or NVD's seven hours.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Photon OS CVE metadata" }

// Fetch downloads every configured major's feed file, merges them into one
// advisory per CVE (buildAdvisories, feed.go), and emits each one.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	var st stats
	byMajor := make([]majorResult, len(p.majors))
	majorEco := make([]string, len(p.majors))
	sources := make([]string, 0, len(p.majors))
	var asOf time.Time

	for i, maj := range p.majors {
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		url := p.baseURL + "cve_data_photon" + maj.Version + ".json"
		rows, when, haveHeader, err := p.fetchMajor(ctx, url)
		if err != nil {
			return store.Provenance{}, fmt.Errorf("photon: %s: %w", maj.Ecosystem, err)
		}
		if !haveHeader {
			fmt.Fprintf(p.progress, "photon: %s carries no Last-Modified header; "+
				"using the local clock instead, so this run's freshness reading may overstate "+
				"how current the data is (not observed against the live feed as of 2026-08-26)\n", url)
		}
		byMajor[i] = processMajor(rows, &st)
		majorEco[i] = maj.Ecosystem
		sources = append(sources, url)
		// The stalest file wins (amazon.Fetch/fedora.Fetch's own reasoning
		// applied across three files instead of many repos/releases): a
		// database is only as fresh as its least current source.
		if asOf.IsZero() || when.Before(asOf) {
			asOf = when
		}
	}

	advisories := buildAdvisories(byMajor, majorEco)
	// D20's guard, the same shape amazon/oracle/fedora all end their own
	// Fetch on: three files that together yield zero advisories means the
	// feed's shape changed or the id/status filters no longer match, not
	// that Photon shipped no fixed CVE for any of its three majors combined
	// (14,341 measured 2026-08-26).
	if len(advisories) == 0 {
		return store.Provenance{}, fmt.Errorf(
			"photon: %d record(s) across %d major(s) yielded no advisories; "+
				"the feed's shape may have changed or the status/id filters no longer match",
			st.Records, len(p.majors))
	}
	for _, adv := range advisories {
		if err := emit(adv); err != nil {
			return store.Provenance{}, err
		}
	}
	st.Advisories = len(advisories)

	fmt.Fprintln(p.progress, "photon: "+st.String())

	ecos := make([]string, len(majorEco))
	copy(ecos, majorEco)
	sort.Strings(ecos)

	return store.Provenance{
		Source:     strings.Join(sources, ", "),
		DataAsOf:   asOf,
		Records:    st.Advisories,
		Ecosystems: ecos,
	}, nil
}

// fetchMajor downloads and decodes one major's cve_data_photon<N>.json,
// returning its rows and the upstream freshness time (D12).
//
// The Last-Modified header is read off the SAME GET response that delivers
// the body (osv.fetchOne's own convention) rather than a separate HEAD the
// way suse.archiveLastModified makes -- there is only one response to pay
// for either way here, so a second round trip would buy nothing.
//
// haveHeader is false, and when falls back to time.Now(), only when the
// response carries no Last-Modified at all or it fails to parse. This is a
// SOFTER failure than suse.archiveLastModified's, which refuses the whole
// build over a missing header: that choice fits SUSE's bulk archive, where
// no other freshness signal exists anywhere close by. Here the same
// question was asked directly of the live server (2026-08-26, all three
// endpoints) and every response carried the header, so this branch is
// defensive against a hazard that has not actually been observed -- see the
// package doc comment's own note on why time.Now() (which OVERSTATES
// freshness for a mirror serving a stale snapshot, the exact over-claim D12
// exists to prevent) is accepted here rather than failing the build the way
// SUSE's provider does for a hazard that measurement found to be real there.
func (p *Provider) fetchMajor(ctx context.Context, url string) (rows []row, when time.Time, haveHeader bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, false, fmt.Errorf("fetch %s: %s", url, resp.Status)
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
		return nil, time.Time{}, false, fmt.Errorf("decode %s: %w", url, err)
	}
	return rows, when, haveHeader, nil
}
