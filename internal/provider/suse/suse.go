// Package suse ingests SUSE's CSAF VEX feed for SLES and openSUSE Leap
// (D77), closing the RPM family D71-D76 built out (Rocky, AlmaLinux, Amazon
// Linux, Oracle Linux, Fedora, then the ndb rpmdb backend that made a SLES or
// openSUSE image catalogable at all). It is the second provider, after Red
// Hat's, that can say "affected, will not fix" rather than only "affected,
// fixed in X" -- SUSE's own OSV export is errata-only in exactly the shape
// D47-D49 measured for Red Hat's: every one of its affected entries carries a
// fixed version, so a scanner built on it alone reports every unfixed SUSE
// CVE as clean. This provider exists so --fail-on-unfixable works on SUSE for
// the first time, reusing D52's FixState machinery unchanged -- an OSV range
// with an introduced event and no fixed one is still what an "affected, no
// fix" statement is, on any feed.
//
// The feed itself, verified live 2026-08-20 against
// https://ftp.suse.com/pub/projects/security/: unlike Red Hat, whose CSAF VEX
// distribution point carries only a dated tar.zst pointed to by
// archive_latest.txt, SUSE additionally publishes a bulk archive under a
// SINGLE, undated name -- csaf-vex.tar.bz2, 445 MB, rebuilt in place -- one
// directory above the per-document tree (csaf-vex/, ~63,808 individual
// documents plus .asc/.sha256 siblings, changes.csv and index.txt). D64's
// spooling and the bulk-archive preference the D77 design named both apply:
// this provider downloads the one archive rather than 63,808 individual
// files, then closes the gap between the archive's build time and now with a
// delta pass over changes.csv, the same two-phase shape redhat.go uses.
//
// Two real differences from Red Hat's shape, both load-bearing:
//
//   - No dated archive name. SUSE rebuilds csaf-vex.tar.bz2 in place, so
//     there is no filename to read a build date out of the way
//     redhat.archiveDate does. D12 still has to be honoured -- freshness
//     measured from upstream data, not from the machine running the sync --
//     so this provider reads the archive's own HTTP Last-Modified header
//     instead (archiveLastModified). A response with no such header, or one
//     that will not parse, fails the build rather than falling back to
//     time.Now(), for the identical reason archiveDate's failure is fatal.
//   - changes.csv sorts OLDEST FIRST, not newest first (verified live: the
//     file's first rows are from 2023, its last from the day it was
//     generated). redhat.changedSince's early exit on the first old row
//     depends on newest-first order and would return NOTHING on this file;
//     changedSince here reads it start to finish instead, which costs
//     nothing an early exit would have saved at 63,784 rows and a few
//     megabytes.
//
// The key SUSE's own product tree needs that Red Hat's never did: one SLES
// release's mainline fixes are spread across roughly twenty per-module
// product names ("SUSE Linux Enterprise Module for Basesystem 15 SP6", "...
// Module for Python 3 15 SP6", and so on) rather than living under one
// mainline product the way Red Hat's "Red Hat Enterprise Linux 9" does.
// csaf.go's foldKey collapses all of them, plus the bare "SUSE Linux
// Enterprise Server 15 SP6" product itself, into ONE release-qualified key
// ("SLES:15.SP6") -- the union D47's own precedent describes for a family
// spread across several CPEs, with an anchored fold pattern so the SAP, HPC,
// Micro, Manager, Storage, Teradata, Real Time Module and Liberty Linux
// product lines that share the "SUSE Linux Enterprise" namespace stay out,
// the same discipline D47's mainlineCPE anchors against JBoss and OpenStack.
// openSUSE Leap needs no fold at all -- its product names ("openSUSE Leap
// 15.6") already match the key 1:1 -- and Tumbleweed is refused by name: a
// rolling release with no stable axis to key on.
package suse

import (
	"archive/tar"
	"compress/bzip2"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// SourceName is what every advisory from this provider records as its
// origin.
const SourceName = "suse"

// DefaultBaseURL is SUSE's own security-data distribution point. Both the
// bulk archive (archiveName, directly under this path) and the per-document
// delta feed (changes.csv and individual documents, one level below under
// "csaf-vex/") live beneath it.
const DefaultBaseURL = "https://ftp.suse.com/pub/projects/security"

// archiveName is the bulk CSAF VEX archive. Unlike Red Hat's, it carries no
// date -- SUSE rebuilds it in place -- so there is no pointer file to read
// the way redhat.pointerFile is; this constant IS the whole of "which file".
const archiveName = "csaf-vex.tar.bz2"

// maxDocument bounds one CSAF document, matching redhat.maxDocument's
// generous headroom for the identical reason: it exists to stop a corrupt
// tar header from asking for an unbounded allocation, not to filter real
// input. The largest document sampled from the live 2026-08-19 archive is
// under 1 MB.
const maxDocument = 512 << 20

type Options struct {
	// BaseURL defaults from its zero value, matching redhat.Options.BaseURL's
	// convention.
	BaseURL string
	// Progress is where the discard counts go, or nil for io.Discard. Matters
	// here for the identical reason it matters on redhat.Options: this
	// provider discards the large majority of what it reads (SAP, HPC,
	// Micro, Manager, Storage and every other non-SLES/Leap product sharing
	// the namespace), and a provider that quietly drops most of its input
	// looks exactly like one that is broken.
	Progress io.Writer
}

type Provider struct {
	baseURL  string
	progress io.Writer
	client   *http.Client
	// Retry counters (D58), identical in role to redhat.Provider's.
	retried atomic.Int64
	rescued atomic.Int64
}

func New(opts Options) *Provider {
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		baseURL:  strings.TrimRight(baseURL, "/"),
		progress: progress,
		// The archive is 445 MB compressed; a generous timeout matching
		// redhat.Provider's for the same reason -- the whole of it is
		// streamed through in one request during spool.
		client: &http.Client{Timeout: 60 * time.Minute},
	}
}

func (p *Provider) Name() string { return "SUSE CSAF VEX" }

// Fetch downloads the bulk archive, converts every document in it, then
// closes the gap between the archive's build time and now with a delta pass.
// Nothing is written to disk beyond the spooled archive itself, and no
// converted document is held after it is emitted.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	archiveURL := p.baseURL + "/" + archiveName
	// D12: read BEFORE spooling, so a HEAD failure fails fast rather than
	// after downloading 445 MB.
	asOf, err := p.archiveLastModified(ctx, archiveURL)
	if err != nil {
		return store.Provenance{}, err
	}

	// Spooled to disk first, then decompressed from there -- D64, the same
	// trade redhat.spool documents: a 445 MB transfer held open while every
	// record it produces is written to bbolt is the exact shape that lost a
	// day's build on 2026-08-13 for Red Hat's archive.
	body, err := p.spool(ctx, archiveURL)
	if err != nil {
		return store.Provenance{}, err
	}
	defer func() {
		body.Close()
		os.Remove(body.Name())
	}()

	var st stats
	// covered accumulates the release-qualified keys actually seen, not the
	// ones this provider hopes for -- identical reasoning to redhat.covered:
	// SUSE adds and retires SLES/Leap releases on its own schedule.
	covered := map[string]bool{}
	tr := tar.NewReader(bzip2.NewReader(body))
	for {
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return store.Provenance{}, fmt.Errorf("suse: read %s: %w", archiveName, err)
		}
		// The archive's entries are "csaf-vex/cve-YYYY-NNNNN.json" alongside
		// "*.json.asc" and "*.json.sha256" siblings and directory entries
		// (verified live); the .json suffix check alone excludes both
		// siblings, since neither ends in ".json".
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		if h.Size > maxDocument {
			return store.Provenance{}, fmt.Errorf(
				"suse: %s in %s is %d bytes, past the %d-byte cap", h.Name, archiveName, h.Size, maxDocument)
		}
		var d document
		if err := json.NewDecoder(tr).Decode(&d); err != nil {
			// One unreadable document is not a broken feed -- counted and
			// reported rather than failing the build, mirroring
			// redhat.Fetch's identical choice.
			st.SkippedBadDoc++
			continue
		}
		adv, ok := convert(&d, &st)
		if !ok {
			continue
		}
		for _, a := range adv.Affected {
			covered[a.Ecosystem] = true
		}
		if err := emit(adv); err != nil {
			return store.Provenance{}, err
		}
	}

	// The archive is a snapshot; documents changed since its own
	// Last-Modified are fetched individually and emitted on top, exactly
	// mirroring redhat.Fetch's deltaSince call.
	if err := p.deltaSince(ctx, asOf, emit, &st, covered); err != nil {
		return store.Provenance{}, err
	}

	// D20's coverage guard, identical in shape to redhat.Fetch's: a build
	// that produced no SLES or openSUSE Leap records must fail rather than
	// write a database that answers every SLES/Leap scan with "no advisories
	// for this ecosystem" -- indistinguishable from a clean image.
	if len(covered) == 0 {
		return store.Provenance{}, fmt.Errorf(
			"suse: %s yielded no SLES or openSUSE Leap records out of %d documents; "+
				"the archive's shape has changed or the key fold no longer matches", archiveName, st.Documents)
	}
	st.DeltaRetried = int(p.retried.Load())
	st.DeltaRescued = int(p.rescued.Load())
	fmt.Fprintln(p.progress, "suse: "+st.String())
	return store.Provenance{
		Source:     archiveURL,
		DataAsOf:   asOf,
		Records:    st.Advisories,
		Ecosystems: sortedKeys(covered),
	}, nil
}

// archiveLastModified reads the archive's own HTTP Last-Modified header
// (D12). Unlike Red Hat's dated archive_latest.txt, SUSE's bulk archive
// keeps ONE filename forever (verified live: csaf-vex.tar.bz2, rebuilt in
// place), so the header on the response is the only statement upstream makes
// about when it was built. A HEAD request costs nothing extra fetched, and a
// missing or unparseable header is fatal rather than falling back to
// time.Now() -- a mirror serving a stale snapshot fetched today must not
// report as fresh, the identical rule redhat.archiveDate's fatal failure
// enforces for a name with no date in it.
func (p *Provider) archiveLastModified(ctx context.Context, url string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("suse: HEAD %s: %w", url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("suse: HEAD %s: %s", url, resp.Status)
	}
	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return time.Time{}, fmt.Errorf(
			"suse: %s carries no Last-Modified header, so how current the data is cannot be recorded", url)
	}
	t, err := http.ParseTime(lm)
	if err != nil {
		return time.Time{}, fmt.Errorf("suse: %s has an unreadable Last-Modified header %q: %w", url, lm, err)
	}
	return t.UTC(), nil
}

func (p *Provider) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("suse: fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("suse: fetch %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// String renders what a sync discarded, for Options.Progress. Every count is
// here for the reason redhat.stats.String's is: a provider that quietly
// drops most of its input looks identical to one that is broken.
func (s stats) String() string {
	return fmt.Sprintf(
		"%d documents -> %d advisories, %d affected entries (%d with no fix available: "+
			"%d will not be fixed, %d not fixed yet, %d with no reason given, %d tagged both ways); "+
			"platforms seen: %d not matching the SLES/Leap key fold, %d Tumbleweed (refused, rolling); "+
			"skipped %d entries with no colon, %d with an empty component, %d referencing Tumbleweed "+
			"directly, %d naming an undeclared platform, %d naming a platform the key fold does not "+
			"cover, %d naming a package with no readable purl, %d documents with no CVE id, "+
			"%d unreadable documents; delta: %d changed since the archive, %d fetched, %d already "+
			"withdrawn, %d yielded a record, %d retried, %d rescued by a retry",
		s.Documents, s.Advisories, s.Affected, s.Unfixable,
		s.UnfixableWontFix, s.UnfixableNotFixed, s.UnfixableUnstated, s.UnfixableBothReasons,
		s.PlatformsUnfoldable, s.PlatformsTumbleweed,
		s.SkippedNoColon, s.SkippedEmptyComponent, s.SkippedTumbleweedRef,
		s.SkippedUnknownPlatform, s.SkippedUnfoldablePlatform, s.SkippedUnknownPackage,
		s.SkippedNoCVE, s.SkippedBadDoc,
		s.DeltaListed, s.DeltaFetched, s.DeltaGone, s.DeltaAdvisories,
		s.DeltaRetried, s.DeltaRescued)
}
