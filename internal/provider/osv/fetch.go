package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
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
//
// "Debian" joins them on the same terms and for the same reason: one archive
// path, release-qualified keys inside it ("Debian:12"). It is the largest of
// the five — 62,318 records against Alpine's 4,405 — and unlike Alpine its
// per-release archives are current, but a single fetch is still fewer requests
// and one freshness timestamp instead of four.
// "Ubuntu" joins on the same terms (D53) and is by far the largest: 601 MB
// compressed and 6.03 GB unpacked, against Debian's 70 MB and 254 MB. The
// driver is not record count — 62,751 against Debian's 62,465, near enough
// identical — but 38.9 affected entries per record against 3.4, because each
// record lists one entry per (lineage x release x binary package). Convert
// drops the lineage entries as it goes (ubuntuLineage), so what is stored is
// mainline only and the stream is never held whole.
// RubyGems, Packagist, NuGet and Maven join the language ecosystems on the
// same terms as crates.io: a plain archive path, a plain (unversioned)
// ecosystem key (D6 does not apply to them, only to distros).
//
// "Rocky Linux" joins on the same terms (D71): one archive
// ("Rocky%20Linux/all.zip" — the family name has a space, and url.PathEscape
// in fetchOne's URL build is what turns it into the %20 a real GET needs),
// release-qualified keys inside it ("Rocky Linux:9"). Measured 2026-08-19:
// 3,941 records, 3,915 of them RLSA, 84.1% carrying a CVSS v3 vector, and CVE
// linkage via `upstream` at 99.3% — D3 already reads that field, so nothing
// there had to change.
//
// "AlmaLinux" joins on the same terms (D72): one archive path (no space, so
// url.PathEscape is a no-op here — unlike "Rocky Linux"), release-qualified
// keys inside it ("AlmaLinux:8/9/10"). Measured 2026-08-19: 5,606 records —
// 4,405 ALSA (security), 979 ALBA (bugfix), 222 ALEA (enhancement), the
// latter two dropped at Convert because they name no vulnerability — 0% CVSS
// anywhere, and the CVE lives ONLY in `related` (aliases and upstream are
// empty on every record), which is what made D71 decision 1 (`related`
// joins the CVE read, scoped to distro-authored records) and decision 2
// (vendor severity words, stored losslessly) load-bearing rather than
// optional for this feed specifically.
//
// "Chainguard" is D88's entry, and it is deliberately alone: "one feed, two
// keys". Chainguard/all.zip is a measured STRICT superset of Wolfi/all.zip
// (23,961 of Wolfi's own 23,961 records are byte-identical members of
// Chainguard's 43,650 — 0 wolfi-only records, measured 2026-08-22), so
// Wolfi/all.zip is never fetched at all. familyMatches' own Chainguard/Wolfi
// clause (record.go) is what makes the one fetch mark BOTH "Chainguard" and
// "Wolfi" covered (D20) — omitting "Wolfi" from this list is not lost
// coverage, it is the whole point: fetching it too would be a second,
// redundant network request for data this build already has. Release-less
// keys, both of them — the first ecosystems this project keys with no
// release axis at all (see pkgmeta.Distro.Ecosystem's "wolfi"/"chainguard"
// cases for why that satisfies D6 rather than violating it). Live yield is
// small relative to the raw archive: 76.9% of Chainguard's 43,650 records
// are withdrawn and D16 drops them at ingestion, leaving ~10,085 live.
//
// "MinimOS" is D92's clone of that same shape: one archive path, no release
// axis on either side (pkgmeta.Distro.Ecosystem's "minimos" case), fetched
// directly rather than through a Wolfi/Chainguard-style "one feed, two keys"
// arrangement -- no cross-feed duplication was measured, so it needs no
// familyMatches special case. Measured 2026-08-26: 129,979 records, MINI-*
// ids, every affected entry ecosystem the bare string "MinimOS".
//
// "Echo" joins on the same terms -- deb-based rather than apk, but still one
// archive path with no release axis (pkgmeta.Distro.Ecosystem's "echo"
// case). Measured 2026-08-26: 8,136 records, ECHO-* ids. Most affected
// entries carry the bare "Echo" key (7,957); a minority carry a
// language-qualified one -- "Echo:PyPi" (495), "Echo:Maven" (34), "Echo:npm"
// (16) -- which the generic familyMatches prefix rule (below) auto-ingests
// alongside the bare ones. Those qualified keys are stored but UNREACHABLE:
// a real Python/npm/Java package catalogs as PyPI/npm/Maven, never as
// "Echo:PyPi" etc., since its own purl is a plain pkg:pypi/... one, not a
// deb purl. Harmless dead entries, not special-cased out.
var Ecosystems = []string{
	"Go", "npm", "PyPI", "crates.io", "RubyGems", "Packagist", "NuGet", "Maven",
	"Alpine", "Debian", "Ubuntu", "Rocky Linux", "AlmaLinux", "Chainguard",
	"MinimOS", "Echo",
}

type Provider struct {
	ecosystems []string
	baseURL    string
	client     *http.Client
	// progress is where D82's module-stream counts are printed, or
	// io.Discard by default. Not a New(...) parameter -- the dozen existing
	// two-argument New(...) call sites across this package's tests would all
	// have to change for a diagnostic nobody there asserts on. WithProgress
	// is the opt-in, the same shape redhat/oracle/amazon/fedora/suse.Options
	// .Progress serves for their own providers, just set after construction
	// instead of at it.
	progress io.Writer
	// ubuntuTrackerEnabled, ubuntuTrackerURL and ubuntuSpoolDir are D85's
	// fields. See WithUbuntuTracker's own comment (ubuntu_spool.go) for why
	// the enabled flag defaults false here rather than true, and ubuntuSpool
	// / ubuntuURL for the other two's defaults -- both are test-only
	// overrides, set directly rather than through an exported setter because
	// every test that needs them lives in this package.
	ubuntuTrackerEnabled bool
	ubuntuTrackerURL     string
	ubuntuSpoolDir       string
}

func New(ecosystems []string, baseURL string) *Provider {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Provider{
		ecosystems: ecosystems,
		baseURL:    strings.TrimRight(baseURL, "/"),
		// A generous timeout: npm's archive alone is ~203 MB.
		client:   &http.Client{Timeout: 30 * time.Minute},
		progress: io.Discard,
	}
}

// WithProgress sets where this provider's own diagnostics go (D82's
// module-stream counts today) and returns p for chaining at the call site.
// A nil writer is ignored rather than replacing the io.Discard default --
// there is no reason to silence a caller that already opted in.
func (p *Provider) WithProgress(w io.Writer) *Provider {
	if w != nil {
		p.progress = w
	}
	return p
}

func (p *Provider) Name() string { return SourceName }

func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	prov := store.Provenance{Source: p.baseURL}
	allCovered := map[string]struct{}{}
	var known int
	// D82: one counter across every ecosystem this Fetch covers, not one per
	// archive -- Rocky Linux and AlmaLinux are two of p.ecosystems' entries
	// among many, and a build that runs with only one of the two enabled
	// still gets an honest (zero-for-the-other) line rather than one line per
	// archive most of which would read "0, 0, 0".
	var st stats

	// D85: built once, up front, so it is available to fetchOne/convert
	// regardless of where "Ubuntu" falls in p.ecosystems -- not per-eco,
	// which would either re-sync the tracker once per archive for no reason
	// or require tracking "have we already done this" state that a
	// once-before-the-loop call makes unnecessary. Skipped entirely (no git,
	// no network) when this build is not fetching Ubuntu at all, so every
	// existing test that constructs a Provider without "Ubuntu" in its
	// ecosystems is unaffected.
	var tracker *ubuntuTracker
	if slices.Contains(p.ecosystems, "Ubuntu") {
		if p.ubuntuTrackerEnabled {
			t, err := p.loadUbuntuTracker(ctx, &st)
			if err != nil {
				return store.Provenance{}, fmt.Errorf("ubuntu tracker: %w", err)
			}
			tracker = t
		} else {
			fmt.Fprintln(p.progress, ubuntuTrackerDisabledDisclosure)
		}
	}

	for _, eco := range p.ecosystems {
		u := fmt.Sprintf("%s/%s/all.zip", p.baseURL, url.PathEscape(eco))
		n, asOf, covered, err := p.fetchOne(ctx, u, eco, emit, &st, tracker)
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
		// The same guard for every distro archive, Rocky Linux and AlmaLinux
		// included (D71, D72). Zero matching records means the family match
		// broke or the archive's shape changed, not that the distro has no
		// advisories — and a database that silently has none turns every
		// later scan of that distro into a clean report at exit 0.
		if (eco == "Alpine" || eco == "Debian" || eco == "Ubuntu" || eco == "Rocky Linux" ||
			eco == "AlmaLinux" || eco == "Chainguard" || eco == "Wolfi" ||
			eco == "MinimOS" || eco == "Echo") && n == 0 {
			return store.Provenance{}, fmt.Errorf("fetch %s: archive yielded no %s:* records", eco, eco)
		}
		// "Wolfi" above is not dead weight even though nothing in
		// Ecosystems ever fetches under that literal name (D88's "one
		// feed, two keys" -- Ecosystems' own comment explains why only
		// "Chainguard" is fetched). QA on this slice constructed a
		// Provider directly with p.ecosystems = []string{"Wolfi"} and
		// found this guard silently did not apply to it, because eco is
		// only ever compared against the names listed and "Wolfi" was
		// never one of them. Listing it costs nothing today and closes
		// that gap for any caller that hands Fetch an ecosystems list
		// this package's own default does not build.
		prov.Records += n
		for e := range covered {
			allCovered[e] = struct{}{}
		}
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
	prov.Ecosystems = slices.Sorted(maps.Keys(allCovered))
	// Printed unconditionally, the same discipline redhat/oracle's own stats
	// lines follow: a build that ran with neither Rocky Linux nor AlmaLinux
	// enabled prints an honest all-zero line rather than staying silent,
	// which is indistinguishable from "this counter does not exist".
	fmt.Fprintln(p.progress, "osv: "+st.String())
	return prov, nil
}

// fetchOne returns the records kept, the upstream timestamp, and the ecosystem
// keys this archive actually covered. The third is not the same as `ecosystem`:
// the Alpine archive is fetched as "Alpine" and covers Alpine:v3.2 through
// Alpine:v3.24 (D20).
func (p *Provider) fetchOne(ctx context.Context, u, ecosystem string, emit func(advisory.Advisory) error, st *stats, tracker *ubuntuTracker) (int, time.Time, map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, time.Time{}, nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, time.Time{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, time.Time{}, nil, fmt.Errorf("GET %s: %s", u, resp.Status)
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
		return 0, time.Time{}, nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return 0, time.Time{}, nil, fmt.Errorf("open zip: %w", err)
	}

	var kept int
	covered := map[string]struct{}{}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return kept, asOf, covered, fmt.Errorf("open %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return kept, asOf, covered, fmt.Errorf("read %s: %w", f.Name, err)
		}
		a, ok, err := convert(data, ecosystem, st, tracker)
		if err != nil {
			return kept, asOf, covered, fmt.Errorf("convert %s: %w", f.Name, err)
		}
		if !ok {
			continue
		}
		if err := emit(a); err != nil {
			return kept, asOf, covered, err
		}
		// Coverage is the keys this archive is authoritative for, which is NOT
		// every ecosystem the record names: a Go advisory that also carries npm
		// entries does not make the npm archive fetched. The same predicate
		// Convert filters on decides it (D20).
		for _, aff := range a.Affected {
			if familyMatches(aff.Ecosystem, ecosystem) {
				covered[aff.Ecosystem] = struct{}{}
			}
		}
		kept++
	}
	return kept, asOf, covered, nil
}
