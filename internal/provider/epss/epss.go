// Package epss converts FIRST.org's Exploit Prediction Scoring System feed
// into advisory.Rating: an opinion about how likely a CVE is to see exploit
// activity in the next 30 days, independent of which package is affected --
// the identical D27 shape provider/nvd uses for CVSS. It enters through
// provider.Annotator for the same reason nvd does: EPSS never says a package
// is affected, only what a CVE is worth (D86).
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Checked here, not just at the first caller: a method added to
// provider.Annotator without a matching change here should fail this
// package's own build, not surface as a missing-method error somewhere else
// entirely (nvd.go's own doc comment gives the same reasoning).
var _ provider.Annotator = (*Provider)(nil)

// SourceName identifies ratings this provider supplied.
const SourceName = "EPSS"

// DefaultURL is FIRST.org's daily-scored, gzip-compressed CSV -- the whole
// corpus in one file, regenerated once a day.
//
// NOT epss.cyentia.com/epss_scores-current.csv.gz. That is EPSS's older
// hostname and it still works, but it answers with a 301 to this one
// (measured 2026-08-21): following the redirect costs an extra round trip on
// every build and depends on Cyentia keeping the alias alive, where fetching
// the destination directly costs neither.
const DefaultURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// Options configures New. Mirrors oracle.Options and fedora.Options: a URL
// seam so a test can point at an httptest server without DefaultURL's live
// feed ever being fetched from, and a Progress writer for the same reason
// every other provider in this project has one -- a build that prints
// nothing while it downloads and parses a file is indistinguishable from one
// that has hung.
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
		// Generous but nowhere near NVD's ten minutes: the compressed feed is
		// ~2.5 MB, measured 2026-08-21.
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (p *Provider) Name() string { return SourceName }

// columnHeader is the second of the two lines EPSS's CSV is documented to
// start with (the first is the header comment parseHeaderComment reads).
// Both are REQUIRED, not merely expected: the first line is the only place
// the model version and the scoring date live (D12 -- DataAsOf must be the
// upstream data's own currency, never fetch time), so a feed that has
// dropped or reshaped either is refused outright rather than annotated with
// a guessed or absent date.
const columnHeader = "cve,epss,percentile"

// Annotate downloads the EPSS feed, gunzips it while streaming (the
// uncompressed CSV is ~11 MB, measured 2026-08-21 -- small enough that
// buffering it whole would not be wrong, but there is no reason to when a
// single streaming pass already suffices), and emits one Rating per CVE row.
//
// Every row is emitted, unfiltered against anything already in the database
// (362,881 measured 2026-08-21): narrowing to CVEs a build already knows
// about would silently drop scores for advisories that land in tomorrow's
// OSV or NVD sync, which then join a CVE with no EPSS opinion until the next
// full EPSS rebuild caught up on its own.
func (p *Provider) Annotate(ctx context.Context, emit func(advisory.Rating) error) (store.Provenance, error) {
	body, err := p.fetch(ctx)
	if err != nil {
		return store.Provenance{}, err
	}
	defer body.Close()

	gz, err := gzip.NewReader(body)
	if err != nil {
		return store.Provenance{}, fmt.Errorf("epss: gunzip: %w", err)
	}
	defer gz.Close()

	br := bufio.NewReader(gz)
	headerLine, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return store.Provenance{}, fmt.Errorf("epss: read header comment: %w", err)
	}
	model, asOf, err := parseHeaderComment(headerLine)
	if err != nil {
		return store.Provenance{}, err
	}

	colLine, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return store.Provenance{}, fmt.Errorf("epss: read column header: %w", err)
	}
	if got := strings.TrimRight(colLine, "\r\n"); got != columnHeader {
		return store.Provenance{}, fmt.Errorf(
			"epss: column header is %q, want %q -- the feed's shape may have changed", got, columnHeader)
	}

	records, skipped, err := emitRows(br, model, emit)
	if err != nil {
		return store.Provenance{}, err
	}

	fmt.Fprintf(p.progress,
		"epss: %d row(s) emitted, %d non-CVE id(s) skipped, model %s, score date %s\n",
		records, skipped, model, asOf.Format("2006-01-02"))

	// D20's coverage guard, the same shape every other provider's Fetch
	// ends on: a parse that read a real header but somehow emitted no rows
	// at all must fail the build rather than write a database that answers
	// every EPSS lookup with silence, indistinguishable from a clean scan.
	if records == 0 {
		return store.Provenance{}, fmt.Errorf(
			"epss: parsed the header but emitted zero rows -- the feed's shape may have changed")
	}

	return store.Provenance{
		Source:   p.url,
		DataAsOf: asOf,
		Records:  records,
		// The whole feed, every build -- there is no partial-window concept
		// here the way NVD_SINCE_DAYS bounds a sync (D65). CoversSinceKnown
		// true with a zero CoversSince is "unbounded", exactly as an
		// unwindowed nvd.Annotate run records it (nvd.go's Annotate), so a
		// coverage comparison elsewhere sorts this as the broadest possible
		// claim rather than as "not recorded" (store.Provenance.CoversSince's
		// own doc comment).
		Window:           "the whole feed",
		CoversSinceKnown: true,
		CoversUntilKnown: true,
	}, nil
}

// parseHeaderComment requires line to be exactly
// "#model_version:<v>,score_date:<RFC3339>" and returns the two halves. Any
// other shape -- no leading "#", a missing field, a reordered one, an
// unparseable date -- is refused rather than tolerated, because DataAsOf
// depends entirely on this line (D12) and a best-effort parse that silently
// fell back to "unknown" would make a stale mirror look current.
func parseHeaderComment(line string) (model string, asOf time.Time, err error) {
	line = strings.TrimRight(line, "\r\n")
	rest, ok := strings.CutPrefix(line, "#")
	if !ok {
		return "", time.Time{}, fmt.Errorf(
			"epss: first line %q is not the #model_version/score_date header comment -- refusing a feed with no declared currency", line)
	}
	mvField, sdField, ok := strings.Cut(rest, ",")
	if !ok {
		return "", time.Time{}, fmt.Errorf("epss: malformed header comment %q", line)
	}
	mv, ok1 := strings.CutPrefix(mvField, "model_version:")
	sd, ok2 := strings.CutPrefix(sdField, "score_date:")
	if !ok1 || !ok2 || mv == "" || sd == "" {
		return "", time.Time{}, fmt.Errorf("epss: malformed header comment %q", line)
	}
	asOf, err = time.Parse(time.RFC3339, sd)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("epss: parse score_date %q: %w", sd, err)
	}
	return mv, asOf, nil
}

// emitRows reads the CSV body (everything after the two header lines
// Annotate already consumed) and emits one Rating per CVE-prefixed row.
//
// A row whose id does not start with "CVE-" is counted and skipped rather
// than emitted: the store keys ratings on CVE (RatingsFor's own contract),
// and FIRST.org's own docs reserve the column for non-CVE identifiers in
// principle even though none were measured in the live feed (0 of 362,881,
// 2026-08-21) -- counted anyway, per the house convention of never folding a
// skip silently into a success count.
func emitRows(r io.Reader, model string, emit func(advisory.Rating) error) (records, skipped int, err error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	for {
		row, err := cr.Read()
		if err == io.EOF {
			return records, skipped, nil
		}
		if err != nil {
			return records, skipped, fmt.Errorf("epss: parse row %d: %w", records+skipped+1, err)
		}
		id := row[0]
		if !strings.HasPrefix(id, "CVE-") {
			skipped++
			continue
		}
		// Scores are trimmed-precision text ("0.01", "0.87734") -- parsed as
		// a float, never treated as a fixed-width or substring value (the
		// CLAUDE.md hazard: a substring read here would silently truncate a
		// score like a comparer misreading a version).
		score, serr := strconv.ParseFloat(row[1], 64)
		if serr != nil {
			return records, skipped, fmt.Errorf("epss: %s: parse score %q: %w", id, row[1], serr)
		}
		pct, perr := strconv.ParseFloat(row[2], 64)
		if perr != nil {
			return records, skipped, fmt.Errorf("epss: %s: parse percentile %q: %w", id, row[2], perr)
		}
		if err := emit(advisory.Rating{
			CVE:            id,
			Source:         SourceName,
			EPSS:           score,
			EPSSPercentile: pct,
			EPSSModel:      model,
			URL:            "https://api.first.org/data/v1/epss?cve=" + id,
		}); err != nil {
			return records, skipped, err
		}
		records++
	}
}

// fetchAttempts governs how many times the single feed GET is tried before
// the build fails outright -- the same shape redhat.deltaAttempts and
// suse.deltaAttempts give a per-document fetch (D58), narrowed to a single
// whole-file download since that is all this provider ever makes. EPSS is
// DEFAULT ON (unlike NVD's opt-in): the feed is one small file, so a build
// that fails after a short retry schedule rather than silently narrowing is
// the right trade -- there is no seven-hour cost here to be careful about,
// and a scheduled nightly build should not go red over a two-second network
// blip.
const fetchAttempts = 3

// fetchBackoff is the pause before attempt n (1-indexed): 0.5s then 1s,
// matching redhat.deltaBackoff -- short on purpose, because this is one
// client talking to a feed that is either up or genuinely not, not a service
// under load that waiting politely would help.
//
// A package variable, not a plain function, so a test can shrink it (the
// same shape nvd.sleep and its defaultRetryWaits/retryWaits split use, for
// the identical reason nvd.go's doc comment gives): asserting a retry
// actually happened must not cost the real backoff's wall-clock time.
var fetchBackoff = func(attempt int) time.Duration {
	return time.Duration(uint(1)<<uint(attempt-1)) * 500 * time.Millisecond
}

// retryable decides whether the single feed fetch is worth another attempt,
// on nvd.retryable's own reasoning (nvd.go's doc comment): a deny-list, not
// an allow-list, because enumerating every transient shape means the next
// unenumerated one costs a build failure instead of a retry. Only the
// caller's own cancellation and a non-429 4xx (this code asking for the
// wrong thing, which asking again will not fix) are excluded; a 5xx, a
// timeout, a reset, or any other transport failure all count as the network
// or the feed having a bad moment.
//
// The caller's ctx, not an inspection of err, answers "was I told to stop" --
// nvd.retryable's own doc comment explains why asking the error instead
// (errors.Is(err, context.DeadlineExceeded)) also matches this code's own
// client timeout, which is not a cancellation at all.
func retryable(ctx context.Context, status int) bool {
	if ctx.Err() != nil {
		return false
	}
	// 429 and every 5xx are the server (or a proxy in front of it) saying
	// "try later" -- checked FIRST, because 503 is itself >= 400 and would
	// otherwise fall into the next check and be refused.
	if status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	// Any other 4xx is this code asking for the wrong thing, which asking
	// again will not fix.
	if status >= 400 {
		return false
	}
	// status == 0: no response at all reached this point (a transport
	// failure -- reset, timeout, DNS blip), which is transient by nature.
	return true
}

// sleepOrDone waits for d, or returns the context's error if it ends first --
// the same shape redhat.sleepOrDone and suse.sleepOrDone give, so a
// cancelled build does not spend the rest of the retry schedule's backoff
// before noticing.
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

// fetch retries the single GET up to fetchAttempts times before giving up.
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
			fmt.Fprintf(p.progress, "epss: fetch failed (%v); retrying (attempt %d of %d)\n",
				lastErr, attempt, fetchAttempts)
		}
		body, status, err := p.get(ctx)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable(ctx, status) {
			return nil, fmt.Errorf("epss: fetch %s: %w", p.url, err)
		}
	}
	return nil, fmt.Errorf("epss: fetch %s: %d attempts: %w", p.url, fetchAttempts, lastErr)
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
