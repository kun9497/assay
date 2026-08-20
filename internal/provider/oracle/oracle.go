// Package oracle ingests Oracle Linux's ELSA/ELBA security errata from
// Oracle's own OVAL feed (D74) -- assay's first OVAL provider, and its first
// non-JSON one besides Red Hat's tar-of-CSAF-documents (which is still one
// JSON document per file). There is no OSV shortcut the way Ubuntu, Rocky and
// AlmaLinux have: measured 2026-08-19 against
// osv-vulnerabilities.storage.googleapis.com/ecosystems.txt, Oracle Linux
// names no ecosystem there at all, so this provider is the one that has to
// normalize Oracle's own shape into OSV's (D1) rather than reformat an
// archive someone else already normalized.
//
// The feed itself is cheap: one 12 MB bzip2-compressed file (measured
// 2026-08-19), unauthenticated, regenerated daily, covering Oracle Linux 5
// through 10 in one download. What makes the provider non-trivial is that
// the archive is OVAL, not a flat advisory list -- a definition's fixed
// version is not a field, it is the answer to walking an AND/OR criteria
// tree and joining three more pools by id (oval.go) -- and that Oracle's
// kernel-uek lineage genuinely fixes the same CVE at two or more unrelated
// version trains in parallel (the UEK guard in oval.go's dropAmbiguous).
//
// Ksplice-lineage and FIPS-lineage fixed EVRs (Oracle's analogues of RHEL's
// live-patch and Ubuntu's FIPS builds, D53) are filtered at ingestion (D79,
// oval.go's oracleLineageMarker): the criteria walk drops any fixed EVR
// carrying `.ksplice<N>.` or an end-anchored `_fips` before it ever reaches
// perMajor, which is also before dropAmbiguous groups it. Left in, a lineage
// EVR collides with the mainline fix for the same (CVE, major, package), and
// D74's cross-definition guard drops BOTH -- measured 2026-08-20 by
// reproducing dropAmbiguous against the full live archive: excluding
// lineage EVRs recovers 10,502 of the 43,123 dropped affected entries
// (24.4%; 169,585 ambiguous groups fall to 158,119), and openssl's entire
// ambiguity among them disappears. A package actually installed from one of
// these lineages still has nothing sound to be judged against once its
// lineage fix is gone -- mainline bounds do not order against a Ksplice or
// FIPS release in either direction -- so the matcher half of D79
// (oracleLineageOf/oracleLineageMarker in internal/matcher/matcher.go, a
// deliberate duplicate of the regexp here for the same reason csaf.go's
// isModule and matcher's rpmModuleBuild are duplicated) reports such an
// installed package not-evaluated rather than matched.
package oracle

import (
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// SourceName identifies records this provider supplied.
const SourceName = "oracle"

// DefaultURL is Oracle's consolidated OVAL archive: every ELSA/ELBA, every
// release, in one file. The per-release and per-year archives at the same
// index (com.oracle.elsa-ol{6,7,8,9,10}.xml.bz2, com.oracle.elsa-YYYY.xml.bz2)
// are not used -- they carry the identical multi-platform criteria-tree shape
// (measured 2026-08-19: a per-release archive still needs the same guard
// walk, since Oracle does not split multi-platform definitions across the
// per-release files it also publishes), so splitting the fetch would add
// requests without removing any of the parsing this provider already has to
// do, for a corpus that is 12 MB whole.
const DefaultURL = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"

// olamsaGuard is not a filter this provider applies -- com.oracle.elsa-all.xml.bz2
// never contains OL Automation Manager (OLAM) definitions, which live at a
// SEPARATE index entry (com.oracle.olamsa-*.xml.bz2, D74 research). It is
// named here only so a future change to DefaultURL toward a glob is written
// against this comment rather than rediscovering the exclusion the hard way:
// an OLAM definition ingested under an Oracle Linux key would judge an
// entirely different product's fixes against OL package versions.
const olamsaGuard = "com.oracle.olamsa-* is a different product and must never be globbed in alongside this URL"

type Options struct {
	// URL defaults to DefaultURL. A test seam, the same role
	// redhat.Options.BaseURL and amazon.Options.Repos play: it lets a test
	// point at an httptest server without DefaultURL's live archive ever
	// being fetched.
	URL string
	// Progress is where the fetch summary goes, or nil for io.Discard.
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
		// Generous but nowhere near Red Hat's hour: the archive is 12 MB
		// compressed, measured 2026-08-19.
		client: &http.Client{Timeout: 10 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Oracle Linux OVAL" }

// Fetch downloads the OVAL archive, spooled to a temporary file before
// anything decompresses or parses it (D64): the archive is two orders of
// magnitude smaller than Red Hat's 261 MB, but the reason D64 exists does not
// scale with size -- streaming decompression and parsing while the HTTP
// response body is still open holds the connection for the whole of both,
// where spooling first closes it as soon as the bytes are down.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	f, err := p.spool(ctx, p.url)
	if err != nil {
		return store.Provenance{}, err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	var st stats
	defs, asOf, err := parseOVAL(bzip2.NewReader(f), &st)
	if err != nil {
		return store.Provenance{}, fmt.Errorf("oracle: %w", err)
	}

	advs := normalize(defs, &st)
	fmt.Fprintln(p.progress, "oracle: "+st.String())

	// D20's coverage guard, the same shape redhat.Fetch and amazon.Fetch
	// both end on: a parse that read real definitions but somehow emitted no
	// advisories at all must fail the build rather than write a database
	// that answers every Oracle Linux scan with "no advisories for this
	// ecosystem" -- indistinguishable from a clean image.
	if len(advs) == 0 {
		return store.Provenance{}, fmt.Errorf(
			"oracle: %d definitions yielded no advisories; the archive's shape may have "+
				"changed or the criteria-walk no longer resolves it", st.Definitions)
	}

	covered := map[string]bool{}
	for _, a := range advs {
		for _, aff := range a.Affected {
			covered[aff.Ecosystem] = true
		}
		if err := emit(a); err != nil {
			return store.Provenance{}, err
		}
	}

	ecos := make([]string, 0, len(covered))
	for e := range covered {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)

	return store.Provenance{
		Source:     p.url,
		DataAsOf:   asOf,
		Records:    st.Advisories,
		Ecosystems: ecos,
	}, nil
}

func (p *Provider) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oracle: fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("oracle: fetch %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}
