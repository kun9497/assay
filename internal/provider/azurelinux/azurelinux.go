// Package azurelinux ingests Azure Linux / CBL-Mariner security data from
// Microsoft's own two OVAL feeds (D106) -- assay's second OVAL provider,
// following internal/provider/oracle's shape (D74).
//
// This replaces the "Azure Linux" family that used to be fetched through
// internal/provider/osv (D94, "Azure%20Linux/all.zip" on
// osv-vulnerabilities.storage.googleapis.com). That path is gone, not
// narrowed: OSV.dev's own converter for this ecosystem is measured stalled --
// investigating a first attempt at this slice (a plan to consume Microsoft's
// osv/ directory in github.com/microsoft/AzureLinuxVulnerabilityData, which
// looked like a live drop-in OSV source) found that directory has exactly ONE
// commit (2026-03-10) and is itself an abandoned one-time snapshot, OLDER
// than what OSV.dev already serves -- OSV.dev's importer reads that very
// directory via its own source.yaml, and the importer is healthy; the SOURCE
// it reads is dead. Consuming it would have made assay's data WORSE.
//
// The living source, verified 2026-08-28, is the two OVAL files this
// provider fetches directly -- the same ones grype and trivy consume, and the
// same shape Oracle Linux's own feed already taught this codebase how to
// read: a definition's fixed version is not a field, it is the answer to
// joining <criterion> against the <tests>/<objects>/<states> pools by id. Two
// files, not one, because Microsoft ships CBL-Mariner 2.0 and Azure Linux 3.0
// (the mid-2024 rename, D94's own pkgmeta.Distro.Ecosystem routing already
// handles both os-release IDs) as separate OVAL documents, each pre-scoped to
// its own release -- unlike Oracle's single multi-release archive, neither
// file needs a platform-major criterion walk at all, because there is only
// ever one release per file.
//
// Measured 2026-08-28 against both live files:
//   - azurelinux-3.0-oval.xml: 7,268 <definition> elements, generator
//     timestamp current to the day fetched (2026-08-27 when measured).
//     Criteria trees are flat: every definition's <criteria operator="AND">
//     holds exactly one or two direct <criterion> children, 0 nested
//     <criteria>, 0 operator="OR" anywhere. One criterion is the fixed bound
//     (operation "less than"); a second, when present (66 of 7,268), is a
//     real introduced bound (operation "greater than", value "0:X.Y.Z.azl3"
//     -- "0:0.0.0.azl3" on 53 of those 66 is the "no real lower bound"
//     sentinel, kept as-is rather than special-cased to bare "0": the RPM{}
//     comparer already orders any real installed version above it). Every
//     definition carries exactly one CVE reference. Severity is a plain word
//     -- Critical/High/Medium/Low, no CVSS vector anywhere in the file --
//     and all four words already exist in severity.vendorSeverityWords
//     (Critical from RHSA's own convention, Medium from Amazon's D73 entry,
//     High from Fedora's D75 entry, Low from the base RHSA set), so this
//     provider needs no new severity mapping at all, only a membership check
//     to catch a future fifth word rather than storing it silently unrated.
//   - cbl-mariner-2.0-oval.xml: 5,406 definitions, the identical flat-criteria
//     shape, plus one operation azurelinux-3.0-oval.xml never uses: "less
//     than or equal" (230 occurrences), OSV's `last_affected` (inclusive)
//     rather than `fixed` (exclusive) -- always the SOLE criterion in its
//     definition, never paired with an introduced bound. 106 of those 230
//     pair with <patchable>false</patchable> ("No patch is available
//     currently" in the definition's own description) -- genuine,
//     currently-unfixed vulnerabilities, stamped FixState = NotFixed (D52)
//     because the vendor's own patchable flag is the positive evidence D52
//     requires. The other 124, plus 14 "less than"-shaped ones, pair with
//     <patchable>Not Applicable</patchable> ("This CVE either no longer is or
//     was never applicable") -- dropped at ingestion (D16's discipline
//     applied to a vendor's own retraction signal, the same as OSV's
//     `withdrawn` field), not stored as a live finding.
//
// Fixed/introduced/last-affected bounds are stored verbatim, epoch and
// ".azl3"/".cm2" dist tag included ("0:1.8.11-1.azl3"), never stripped: unlike
// OSV.dev's old export (D94's own comment in internal/version/version.go,
// which stripped both before storing), this provider controls its own
// output and an unstripped bound compares MORE precisely against a real
// installed EVR -- ordinary rpmvercmp epoch and trailing-segment handling
// covers it either way, so nothing downstream needed to change to accept it.
//
// A single CVE can appear in more than one <definition> in the SAME file --
// measured 325 CVEs in azurelinux-3.0-oval.xml, 364 in cbl-mariner-2.0-oval.xml,
// most commonly because a package that ships two supported build tracks in
// parallel (golang 1.25.x vs 1.26.x, rust 1.75 vs 1.90) gets a separate
// definition per track. This is NOT Oracle's kernel-uek hazard (two
// definitions asserting two DIFFERENT, mutually exclusive facts that must
// pick one or drop both, D74's dropAmbiguous) -- every measured pair shares
// the same implicit introduced bound ("0") and differs only in fixed
// version, so the two definitions' ranges NEST rather than conflict: any
// version below the lower fixed bound is caught by both, any version between
// the two bounds is caught by the higher one, nothing is lost by keeping
// both as separate, independent Advisory records rather than merging or
// picking one. This provider therefore mints a UNIQUE id per definition
// (its own <advisory_id>, prefixed) rather than per CVE, and needs no
// ambiguity-dropping pass at all: D25's own grouping (matcher.identifiers,
// which reads ID + Aliases) is what recombines every definition sharing one
// CVE into a single finding at match time, the same mechanism that already
// joins two independent vendors' records for one CVE.
package azurelinux

import (
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
const SourceName = "azurelinux"

// DefaultAZL3URL and DefaultMariner2URL are Microsoft's own raw OVAL files,
// regenerated daily (D106) -- the source-of-truth grype and trivy both read,
// not the abandoned osv/ snapshot in the same repository (see the package
// doc comment).
const (
	DefaultAZL3URL     = "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml"
	DefaultMariner2URL = "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/cbl-mariner-2.0-oval.xml"
)

// family pairs one OVAL file with the D94 ecosystem key it feeds (D6: the
// release is part of the key, and both files are release-qualified rather
// than reading a platform criterion the way Oracle's single multi-release
// archive must, because each file only ever names one release).
type family struct {
	url     string
	release string // "3" or "2" -- becomes "Azure Linux:"+release
}

type Options struct {
	// AZL3URL and Mariner2URL default to DefaultAZL3URL/DefaultMariner2URL.
	// Test seams, the same role oracle.Options.URL plays: they let a test
	// point at an httptest server without either live file ever being
	// fetched.
	AZL3URL     string
	Mariner2URL string
	// Progress is where the fetch summary goes, or nil for io.Discard.
	Progress io.Writer
}

type Provider struct {
	families []family
	progress io.Writer
	client   *http.Client
}

func New(opts Options) *Provider {
	azl3 := opts.AZL3URL
	if azl3 == "" {
		azl3 = DefaultAZL3URL
	}
	mariner2 := opts.Mariner2URL
	if mariner2 == "" {
		mariner2 = DefaultMariner2URL
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		families: []family{
			{url: azl3, release: "3"},
			{url: mariner2, release: "2"},
		},
		progress: progress,
		// Generous but nowhere near Red Hat's hour: both files together are
		// under 25 MB uncompressed (measured 2026-08-28).
		client: &http.Client{Timeout: 10 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Azure Linux OVAL" }

// Fetch downloads both OVAL files, one at a time, each spooled to a
// temporary file before anything parses it (D64, following oracle.spool's
// own reasoning -- see spool.go).
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	var st stats
	var asOf time.Time
	haveAsOf := false
	covered := map[string]bool{}
	sources := make([]string, 0, len(p.families))

	for _, fam := range p.families {
		sources = append(sources, fam.url)
		f, err := p.spool(ctx, fam.url)
		if err != nil {
			return store.Provenance{}, fmt.Errorf("azurelinux: %w", err)
		}
		advs, fileAsOf, err := parseOVAL(fam.release, f, &st)
		f.Close()
		os.Remove(f.Name())
		if err != nil {
			return store.Provenance{}, fmt.Errorf("azurelinux: %w", err)
		}
		// The same D20 guard every other distro provider in this codebase
		// ends its own fetch loop on: a file that parsed real <definition>
		// elements but yielded zero advisories after filtering means the
		// feed's shape changed, not that this release has no advisories.
		// Silently building a database with no Azure Linux:N coverage would
		// answer every later scan of that release "clean", indistinguishable
		// from actually clean.
		if len(advs) == 0 {
			return store.Provenance{}, fmt.Errorf(
				"azurelinux: Azure Linux:%s OVAL (%s) yielded no advisories; "+
					"the feed's shape may have changed", fam.release, fam.url)
		}
		for _, a := range advs {
			for _, aff := range a.Affected {
				covered[aff.Ecosystem] = true
			}
			if err := emit(a); err != nil {
				return store.Provenance{}, err
			}
		}
		// D12: the OLDEST of the two generator timestamps wins, the same
		// aggregate rule osv.Provider.Fetch already applies across its own
		// multi-archive loop -- a database is only as fresh as its stalest
		// input, and reporting the newer file's timestamp would hide that
		// the other one is behind it.
		if !fileAsOf.IsZero() && (!haveAsOf || fileAsOf.Before(asOf)) {
			asOf = fileAsOf
			haveAsOf = true
		}
	}

	fmt.Fprintln(p.progress, "azurelinux: "+st.String())

	ecos := make([]string, 0, len(covered))
	for e := range covered {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)

	return store.Provenance{
		Source:     sources[0] + ", " + sources[1],
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
		return nil, fmt.Errorf("azurelinux: fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("azurelinux: fetch %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}
