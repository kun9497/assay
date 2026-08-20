package redhat

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// SourceName is what every advisory from this provider records as its origin.
const SourceName = "redhat"

// DefaultBaseURL is Red Hat's CSAF VEX distribution point. The feed is
// TLP:WHITE on all 67,261 documents, so redistributing what is built from it
// carries no restriction — unlike the KISA prose D29 has to strip before
// `db push`.
const DefaultBaseURL = "https://security.access.redhat.com/data/csaf/v2/vex"

// pointerFile names the current full archive. It is read rather than the
// archive name being constructed from today's date: the archive is rebuilt on
// Red Hat's schedule, not ours, and guessing a filename yields a 404 that is
// indistinguishable from a feed that has gone away.
const pointerFile = "archive_latest.txt"

// maxDocument bounds one CSAF document. The largest in the archive is 94 MB
// (2026/cve-2026-33186.json), so the cap is generous — it exists to stop a
// corrupt tar header from asking for an unbounded allocation, not to filter
// real input.
const maxDocument = 512 << 20

type Options struct {
	// BaseURL defaults from its zero value, which is an unambiguous "not set"
	// -- nobody wants an empty URL.
	BaseURL string
	// Progress is where the discard counts go, or nil for io.Discard.
	//
	// An option rather than a parameter for knvd's reason: provider.Provider's
	// signature is Fetch(ctx, emit) and must stay that way, and threading a
	// writer through the interface to serve one implementation's diagnostics
	// is the wrong trade.
	//
	// It matters more here than for any other provider. This one discards the
	// large majority of what it reads -- container images, non-mainline
	// products, module builds -- and a provider that quietly drops two thirds
	// of its input looks exactly like one that is broken.
	Progress io.Writer
}

type Provider struct {
	baseURL  string
	progress io.Writer
	client   *http.Client
	// Retry counters (D58). Atomic because the delta fetches eight
	// documents at once, and on the Provider rather than threaded through
	// eachDocument because they are diagnostics: nothing branches on them,
	// so the alternative is changing a signature for a number that only
	// ever gets printed.
	//
	// Counted because the first build after D58 could not tell whether a
	// retry had saved it or no transient failure had occurred — the same
	// run had died at document 2,448 the day before, and "it worked" is not
	// evidence that the fix is what made it work.
	retried atomic.Int64 // extra attempts made, across all documents
	rescued atomic.Int64 // documents that succeeded only after a retry
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
		// The archive is 262 MB compressed and 17.1 GB decompressed, and the
		// whole of it is streamed through in one request.
		client: &http.Client{Timeout: 60 * time.Minute},
	}
}

func (p *Provider) Name() string { return "Red Hat CSAF VEX" }

// Fetch streams the archive and emits one advisory per CVE.
//
// Nothing is written to disk and no document is held after it is converted.
// That matters more here than for any other provider: 17.1 GB decompressed is
// two orders of magnitude past the OSV archives, and a design that
// accumulated even the converted records before emitting would need several
// gigabytes of its own.
func (p *Provider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	name, err := p.archiveName(ctx)
	if err != nil {
		return store.Provenance{}, err
	}
	// D12: freshness is measured from the upstream data, not from this run.
	// The archive names the day Red Hat built it, which is the only statement
	// available about when the data was current — a mirror serving a stale
	// snapshot fetched today must not report as fresh.
	asOf, err := archiveDate(name)
	if err != nil {
		return store.Provenance{}, err
	}

	// Spooled to disk first, then decompressed from there. Streaming the
	// archive while storing what it produced held one connection open for the
	// whole build (D64) - the transfer takes two minutes and the store takes
	// eight, and on 2026-08-13 the far end reset it in between, losing the day.
	url := p.baseURL + "/" + name
	body, err := p.spool(ctx, url, name)
	if err != nil {
		return store.Provenance{}, err
	}
	defer func() {
		body.Close()
		os.Remove(body.Name())
	}()

	zr, err := zstd.NewReader(body)
	if err != nil {
		return store.Provenance{}, fmt.Errorf("redhat: open %s as zstd: %w", name, err)
	}
	defer zr.Close()

	var st stats
	// covered accumulates the release-qualified keys actually seen, not the
	// ones this provider hopes for. Red Hat publishes for RHEL 3 through 10
	// and the set changes as releases are added and retired, so a hardcoded
	// list would claim coverage of a release the archive stopped carrying.
	covered := map[string]bool{}
	tr := tar.NewReader(zr)
	for {
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return store.Provenance{}, fmt.Errorf("redhat: read %s: %w", name, err)
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		if h.Size > maxDocument {
			return store.Provenance{}, fmt.Errorf(
				"redhat: %s in %s is %d bytes, past the %d-byte cap", h.Name, name, h.Size, maxDocument)
		}
		var d document
		// Decoded straight off the tar reader rather than through
		// io.ReadAll: the largest document is 94 MB and reading it whole
		// before parsing doubles the peak for no gain.
		if err := json.NewDecoder(tr).Decode(&d); err != nil {
			// One unreadable document is not a broken feed. It is counted and
			// reported rather than failing the build, for the reason every
			// skip in this project is counted: a number somebody can see beats
			// both a silent drop and a sync that will not finish.
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

	// The archive is a snapshot; documents written since it was built are
	// fetched individually and emitted on top. See deltaSince — this is the
	// only thing that separated assay from grype on either differential run.
	if err := p.deltaSince(ctx, asOf, emit, &st, covered); err != nil {
		return store.Provenance{}, err
	}

	// D20's coverage set, and the guard beside it. A build that produced no
	// Red Hat records must fail rather than write a database that answers
	// every RHEL scan with "no advisories for this ecosystem" -- which is
	// indistinguishable from a clean image and is the exact failure D20 exists
	// to close, one archive further in.
	if len(covered) == 0 {
		return store.Provenance{}, fmt.Errorf(
			"redhat: %s yielded no mainline Red Hat records out of %d documents; "+
				"the archive's shape has changed or the CPE filter no longer matches", name, st.Documents)
	}
	st.DeltaRetried = int(p.retried.Load())
	st.DeltaRescued = int(p.rescued.Load())
	fmt.Fprintln(p.progress, "redhat: "+st.String())
	return store.Provenance{
		Source:     url,
		DataAsOf:   asOf,
		Records:    st.Advisories,
		Ecosystems: sortedKeys(covered),
	}, nil
}

// archiveName reads archive_latest.txt.
func (p *Provider) archiveName(ctx context.Context) (string, error) {
	body, err := p.get(ctx, p.baseURL+"/"+pointerFile)
	if err != nil {
		return "", err
	}
	// Drained for the delta pass's reason: an undrained body costs the
	// connection, and every request after it pays for a new one.
	defer func() {
		io.Copy(io.Discard, io.LimitReader(body, 1<<20))
		body.Close()
	}()
	// The pointer file holds one short filename. The cap is what stops a
	// misrouted response — an HTML error page, a redirect to a login — from
	// being read as a name and then requested.
	b, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return "", fmt.Errorf("redhat: read %s: %w", pointerFile, err)
	}
	name := strings.TrimSpace(string(b))
	if name == "" || strings.ContainsAny(name, "/\\") || !strings.HasSuffix(name, ".tar.zst") {
		return "", fmt.Errorf("redhat: %s named %q, which is not an archive filename", pointerFile, name)
	}
	return name, nil
}

// archiveDate reads the day out of "csaf_vex_2026-08-05.tar.zst".
//
// A failure here is fatal rather than falling back to time.Now(): D12 exists
// so a stale mirror cannot report as fresh, and substituting the fetch time
// for the data time is precisely the substitution it forbids.
func archiveDate(name string) (time.Time, error) {
	s := strings.TrimSuffix(name, ".tar.zst")
	if i := strings.LastIndexByte(s, '_'); i >= 0 {
		s = s[i+1:]
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"redhat: cannot read a date out of the archive name %q, so how current the data is "+
				"cannot be recorded: %w", name, err)
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
		return nil, fmt.Errorf("redhat: fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("redhat: fetch %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// String renders what a sync discarded, for Options.Progress. Every count
// is here because the alternative is a provider that quietly drops most of its
// input and looks identical to one that is broken.
//
// D80 moved module-scoped entries out of "skipped" and into "kept": they used
// to be an unconditional discard (a "::" context meant the scan could not
// know which stream was enabled) and are now stored, streamed, because the
// context turned out to carry the very stream name the release string was
// missing.
func (s stats) String() string {
	return fmt.Sprintf(
		"%d documents -> %d advisories, %d affected entries (%d module-scoped across %d streams, "+
			"%d with no fix available: %d will not be fixed, %d not fixed yet, %d with no reason given, "+
			"%d tagged both ways, %d remediations naming a product group); "+
			"skipped %d module builds with no readable stream, %d flatpak-scoped entries, "+
			"%d module contexts that did not parse as name:stream, "+
			"%d non-mainline products, %d container images, "+
			"%d products with no CPE, %d whole-product entries naming no package, "+
			"%d unreadable products, %d documents with no CVE id, "+
			"%d unreadable documents; delta: %d changed since the archive, "+
			"%d fetched, %d already withdrawn, %d yielded a record, "+
			"%d retried, %d rescued by a retry",
		s.Documents, s.Advisories, s.Affected, s.ModuleKept, len(s.moduleStreams),
		s.Unfixable, s.UnfixableWontFix, s.UnfixableNotFixed, s.UnfixableUnstated,
		s.UnfixableBothReasons, s.RemediationGrouped,
		s.SkippedModule, s.SkippedFlatpak, s.SkippedModuleContext,
		s.SkippedNonRHEL, s.SkippedImage,
		s.SkippedNoCPE, s.SkippedWholeProduct, s.SkippedBadProduct, s.SkippedNoCVE, s.SkippedBadDoc,
		s.DeltaListed, s.DeltaFetched, s.DeltaGone, s.DeltaAdvisories,
		s.DeltaRetried, s.DeltaRescued)
}
