package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Checked here, not just at the first caller: a method added to
// provider.Annotator without a matching change here should fail this
// package's own build, not surface as a missing-method error somewhere else
// entirely.
var _ provider.Annotator = (*Provider)(nil)

// DefaultBaseURL is NVD's CVE 2.0 API.
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// defaultPageSize is the measured shape of a full sync: 2,000 records per
// request is ~4.3 MB and ~33 s, and 187 requests cover the whole feed.
const defaultPageSize = 2000

// defaultPause and defaultPauseWithKey space sequential requests to stay
// under NVD's published rate limit: 5 requests per rolling 30 s without a
// key, 50 with one. The limit is per source IP, so this is a spacing between
// requests, never a budget for concurrency.
const (
	defaultPause        = 6500 * time.Millisecond
	defaultPauseWithKey = 650 * time.Millisecond
)

// Options configures New. Most callers set only APIKey and BaseURL; PageSize
// and Pause exist so tests can shrink a page and remove the real rate-limit
// delay without changing the production defaults.
type Options struct {
	APIKey  string
	BaseURL string
	// PageSize and BaseURL default from their zero value (0 and "") because
	// neither is ever a meaningful request on its own - nobody wants a
	// literal zero-record page or an empty URL, so the zero value is a safe,
	// unambiguous "not set" sentinel.
	PageSize int
	// Pause is the delay between requests, or nil to use the rate-limit
	// default (6.5s, or 0.65s with an API key).
	//
	// A *time.Duration, not a bare time.Duration, for the same reason
	// scancmd.Options.FailOn is a *severity.Band rather than a bare Band
	// (internal/scancmd/scancmd.go): zero is a real, requestable value - "no
	// pause at all", which a test or a caller pointed at a local mirror
	// might genuinely want - and Duration's zero value, so it cannot also
	// mean "not set" without colliding with that explicit request. Unlike
	// PageSize and BaseURL above, 0 is not a safe sentinel here.
	Pause *time.Duration
	// Since bounds the sync to CVEs modified on or after this instant, using
	// NVD's lastModStartDate filter. Zero means the whole feed.
	//
	// It exists because the whole feed is not a 20-minute job. Measured
	// 2026-08-03: a 2,000-record page takes 114-136 seconds regardless of
	// page size or compression, because NVD generates the response rather
	// than serving a file - 500 records took 41s, so the cost is roughly
	// linear per record. 372,628 records is therefore about seven hours, and
	// the rate-limit pauses this code is careful about are 20 minutes of it.
	//
	// NVD's own answer to that is incremental sync, and this is it: after one
	// full pass, a daily run asks only for what changed. The window may not
	// exceed 120 days, which the caller has to respect - a longer span is
	// rejected by the API, not silently truncated.
	Since time.Time
	// Progress is where retry notices go, or nil for io.Discard.
	//
	// It is an option rather than a parameter because provider.Annotator's
	// signature is Annotate(ctx, emit) and must stay that way — every
	// annotator shares it, and threading a writer through the interface to
	// serve one implementation's diagnostics is the wrong trade. A sync that
	// pauses 40 seconds with no output is indistinguishable from one that
	// has hung, and this one already runs for hours, so the notice is worth
	// an option field.
	Progress io.Writer
}

type Provider struct {
	since    time.Time
	apiKey   string
	baseURL  string
	pageSize int
	pause    time.Duration
	client   *http.Client
	progress io.Writer
}

func New(opts Options) *Provider {
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	pageSize := opts.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	// The rate-limit default applies only when Pause is left nil - an
	// explicit zero (or any other value) is used verbatim, never overridden,
	// per the Options.Pause doc comment above.
	pause := defaultPause
	if opts.APIKey != "" {
		pause = defaultPauseWithKey
	}
	if opts.Pause != nil {
		pause = *opts.Pause
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		apiKey:   opts.APIKey,
		baseURL:  baseURL,
		pageSize: pageSize,
		pause:    pause,
		// A single page is ~4.3 MB at the default page size (measured); a
		// generous timeout leaves room for a slow connection without hanging
		// forever.
		since: opts.Since,
		// Measured, not guessed: a single 2,000-record page took 114.5s
		// uncompressed and 135.8s with gzip on 2026-08-03, and the same
		// request had taken 33s earlier the same day. Two minutes - the
		// first value here - failed a real sync on the first page. NVD
		// generates these responses, so the variance is theirs and a margin
		// of a few seconds is not a margin.
		client:   &http.Client{Timeout: 10 * time.Minute},
		progress: progress,
	}
}

func (p *Provider) Name() string { return SourceName }

// defaultRetryWaits paces retries of a single page. A multi-hour sync makes
// a transient failure a near-certainty rather than an edge case: two real
// bootstrap attempts died at 42 and 116 minutes, one on a 503 and one on an
// HTTP/2 stream error, each losing every record it had fetched — Update
// builds into a temporary database and installs it only at the end, so there
// is no resume point.
//
// Values, not a fixed count, for the same reason replaceWaits is a slice in
// internal/dbcmd: the schedule IS the policy, and a test that shrinks it
// should not also change how many attempts happen. Roughly a minute total,
// which is long enough for NVD to come back from a blip and short enough
// that a genuine outage still fails the build rather than hanging it.
//
// Held separately from retryWaits so a test can assert the shipped values
// are non-zero even though TestMain zeroes the working copy. Without that
// split, zeroing the production schedule — turning every retry into a hot
// loop against NVD — would pass the suite.
var defaultRetryWaits = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 40 * time.Second}

// retryWaits is the working copy the retry loop reads. TestMain replaces it
// with a same-length, all-zero slice so the suite does not sleep.
var retryWaits = defaultRetryWaits

// retryable decides whether an error is worth another attempt.
//
// The policy is deny-list, not allow-list, and that is the correction of a
// real mistake. The first version retried HTTP status errors only, because a
// 503 was the failure that had just been observed. The next run died at
// 116 minutes on `stream error: stream ID 91; INTERNAL_ERROR` -- an HTTP/2
// transport failure surfacing during body decode, not a status at all -- and
// the retry never fired. Enumerating the transient cases means the next
// unenumerated one costs another two hours.
//
// So: everything is retryable except the two categories that are definitely
// not.
//
//   - A cancelled or expired context is the caller saying stop. Retrying it
//     ignores ^C and outlives the deadline it was given.
//   - A 4xx other than 429 is this code getting the request wrong. Retrying
//     makes the same mistake more slowly. 404 in particular was the
//     window-wider-than-maxWindow bug, which a retry loop would have buried
//     under a minute of silence before reporting the same error anyway.
//
// Everything else -- 5xx, 429, connection resets, stream errors, truncated
// or malformed bodies -- is NVD or the network having a bad moment. A
// genuinely malformed feed still fails, just after four attempts instead of
// one, and that is the cheaper direction to be wrong in when the alternative
// costs a multi-hour sync.
func retryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.code >= 500 || se.code == http.StatusTooManyRequests
	}
	return true
}

// httpStatusError carries the status code so fetchPageRetrying can decide
// whether to retry without parsing an error string.
type httpStatusError struct {
	code int
	msg  string
}

func (e *httpStatusError) Error() string { return e.msg }

// fetchPageRetrying retries one page through transient failures, reporting
// each attempt on stderr. Silence here would be worse than the failure: a
// sync that stalls for a minute with no output is indistinguishable from one
// that has hung, and this one already takes hours.
func (p *Provider) fetchPageRetrying(ctx context.Context, startIndex int, since, until time.Time) (apiResponse, time.Time, error) {
	for attempt := 0; ; attempt++ {
		page, asOf, err := p.fetchPage(ctx, startIndex, since, until)
		if err == nil {
			return page, asOf, nil
		}
		if !retryable(err) || attempt >= len(retryWaits) {
			return apiResponse{}, time.Time{}, err
		}
		wait := retryWaits[attempt]
		fmt.Fprintf(p.progress, nlFmt("nvd: page at startIndex %d failed (%v); retrying in %s (attempt %d of %d)"),
			startIndex, err, wait, attempt+1, len(retryWaits))
		if err := sleep(ctx, wait); err != nil {
			return apiResponse{}, time.Time{}, err
		}
	}
}

// nlFmt appends a newline to a format string. Assembled rather than typed,
// because a literal escape inside a tool argument or a generating script has
// silently become the byte it denotes three times on this repository -- see
// CLAUDE.md. One helper is cheaper than remembering that at every call site.
func nlFmt(s string) string { return s + string(rune(10)) }

// maxWindow is NVD's hard limit on any lastModStartDate/lastModEndDate
// range: 120 consecutive days, measured at request time. Exceeding it by
// even seconds is answered with 404, not a helpful error.
const maxWindow = 120 * 24 * time.Hour

// windowLabel describes what a run covered, for Provenance.Window. An
// unbounded run says so in words rather than returning "" — an empty Window
// is indistinguishable from a database built before this field existed, and
// "the whole feed" is precisely the claim a reader needs to be able to tell
// apart from "the last 30 days".
func windowLabel(since, until time.Time) string {
	if since.IsZero() {
		return "the whole feed"
	}
	return fmt.Sprintf("modified %s..%s",
		since.UTC().Format("2006-01-02"), until.UTC().Format("2006-01-02"))
}

// Annotate pages through NVD's CVE 2.0 API from startIndex 0 until it covers
// totalResults, emitting one Rating per record that carries at least one
// CVSS metric (D13, D27).
//
// Requests are made one at a time, in order, never in parallel: NVD's rate
// limit is per source IP, so concurrency would not buy throughput and would
// risk a block.
func (p *Provider) Annotate(ctx context.Context, emit func(advisory.Rating) error) (store.Provenance, error) {
	prov := store.Provenance{Source: p.baseURL}
	var (
		startIndex int
		total      int
		records    int
		asOf       time.Time
		first      = true
		// Read once, before the first request, and held for the whole sync:
		// see fetchPage on why the window must not move underneath the
		// pagination.
		until = nowUTC()
	)
	// Clamped here, where both ends are finally known, rather than where
	// Since was chosen.
	//
	// NVD rejects any date range wider than 120 consecutive days, and it
	// measures the span at request time. Since is computed when the options
	// are read, `until` when Annotate starts — and in between, db update runs
	// every advisory provider, which takes minutes. So NVD_SINCE_DAYS=120
	// arrived as 120 days plus the OSV fetch and was answered with a bare
	// 404, meaning the documented maximum could never actually be used. Found
	// by running it: the first real bootstrap died after 2m51s.
	//
	// Narrowing rather than failing is safe because the result is disclosed:
	// windowLabel below records the range actually requested, and db status
	// prints it, so a clamped run cannot report coverage it does not have.
	since := p.since
	if !since.IsZero() && until.Sub(since) > maxWindow {
		since = until.Add(-maxWindow)
	}
	// What this run actually covered, recorded so a windowed database cannot
	// present itself as a complete one (D20). Update rebuilds from empty, so
	// a bounded run's window IS the database's entire NVD coverage — there is
	// no earlier pass underneath it.
	prov.Window = windowLabel(since, until)
	// A do-while shape: the total is unknown before the first response, so
	// the loop condition alone cannot gate the first request.
	for first || startIndex < total {
		// Checked explicitly rather than left to fetchPage's own request:
		// every request is made with http.NewRequestWithContext, so a
		// cancelled ctx already fails the next RoundTrip on its own (mutation
		// tested - removing this check does not make the suite pass a
		// cancelled context through undetected, since the client aborts the
		// call itself). This check exists for the case that guarantee does
		// not cover: skipping the sleep AND the wasted request attempt
		// entirely when the cancellation is already known at the top of the
		// loop, rather than discovering it one HTTP call later.
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		if !first {
			// Paced between requests, not just checked between them: a
			// cancellation arriving mid-pause must not wait out the rest of
			// it before Annotate notices. Called through the sleep variable
			// (defaults to sleepCtx) rather than sleepCtx directly, so a test
			// can substitute a recording stub and assert pacing actually
			// happens without spending the real 6.5s to prove it.
			if err := sleep(ctx, p.pause); err != nil {
				return store.Provenance{}, err
			}
		}
		first = false

		page, pageAsOf, err := p.fetchPageRetrying(ctx, startIndex, since, until)
		if err != nil {
			return store.Provenance{}, err
		}
		total = page.TotalResults
		// The earliest page timestamp wins, mirroring OSV's "the oldest
		// upstream wins" (D12): a multi-page sync spans many timestamps, one
		// per request, and reporting the latest would claim a freshness the
		// earliest page fetched does not have.
		if !pageAsOf.IsZero() && (asOf.IsZero() || pageAsOf.Before(asOf)) {
			asOf = pageAsOf
		}
		for _, v := range page.Vulnerabilities {
			rating, ok := convert(v)
			if !ok {
				continue
			}
			if err := emit(rating); err != nil {
				return store.Provenance{}, err
			}
			records++
		}
		n := len(page.Vulnerabilities)
		// A page that returns zero records while startIndex has not yet
		// reached totalResults would otherwise re-request the exact same
		// startIndex on every following iteration, forever: nothing above
		// this point changes startIndex except this line, so a zero-length
		// page is the one response shape that leaves the loop with no way to
		// make progress. On a real ~187-page sync that is a hang with no
		// output and no error - the worst failure shape for something that
		// already takes 20 minutes - so it is refused outright rather than
		// retried. totalResults == 0, a shrinking total, a short final page,
		// and even a page repeating an earlier one's content are all fine;
		// this guards specifically against zero records with more still
		// expected.
		if n == 0 && startIndex < total {
			return store.Provenance{}, fmt.Errorf(
				"nvd: page at startIndex %d returned zero records but totalResults is %d - refusing to loop forever",
				startIndex, total)
		}
		// Advanced by what the page actually returned, not by the requested
		// page size: NVD's own resultsPerPage can be smaller on the last
		// page, and advancing by the request size would either skip records
		// or loop forever short of totalResults.
		startIndex += n
	}
	prov.Records = records
	prov.DataAsOf = asOf
	return prov, nil
}

// apiResponse is one page of NVD's CVE 2.0 API.
type apiResponse struct {
	TotalResults int `json:"totalResults"`
	// Timestamp is when NVD generated this page (D12): the feed's own clock,
	// not ours. A mirror replaying a stale snapshot today would still carry
	// an old Timestamp even though we fetched it just now.
	Timestamp       string             `json:"timestamp"`
	Vulnerabilities []rawVulnerability `json:"vulnerabilities"`
}

// nowUTC is a seam so a test can pin the lastModEndDate it expects.
var nowUTC = func() time.Time { return time.Now().UTC() }

// fetchPage requests one page. The window's upper bound is passed in rather
// than read from the clock here, because this is called once per page and
// pagination is by startIndex INTO the set the window defines: recomputing
// the end date per request would move that set while it is being walked.
// A 30-day sync is ~11 pages over ~25 minutes, and any CVE NVD modifies
// during those 25 minutes would enter the window mid-walk and shift every
// later offset by one — pushing a record past an offset already consumed,
// where it is never emitted. That is a rating silently absent from the
// database, so a finding keeps the lower band. NVD's own guidance is to
// hold the range fixed across a paged read.
func (p *Provider) fetchPage(ctx context.Context, startIndex int, since, until time.Time) (apiResponse, time.Time, error) {
	u := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", p.baseURL, p.pageSize, startIndex)
	if !since.IsZero() {
		// NVD requires both bounds together and caps the span at 120 days.
		// The end is a real timestamp rather than open-ended, because an
		// absent lastModEndDate is rejected rather than treated as "until
		// now".
		u += fmt.Sprintf("&lastModStartDate=%s&lastModEndDate=%s",
			url.QueryEscape(since.UTC().Format("2006-01-02T15:04:05.000-07:00")),
			url.QueryEscape(until.UTC().Format("2006-01-02T15:04:05.000-07:00")))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return apiResponse{}, time.Time{}, err
	}
	// Sent only when set: a provider that silently required a key would work
	// for whoever configured one and for nobody else.
	if p.apiKey != "" {
		req.Header.Set("apiKey", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return apiResponse{}, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiResponse{}, time.Time{}, &httpStatusError{
			code: resp.StatusCode,
			msg:  fmt.Sprintf("GET %s: %s", u, resp.Status),
		}
	}

	var body apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return apiResponse{}, time.Time{}, fmt.Errorf("decode nvd response: %w", err)
	}

	var asOf time.Time
	if body.Timestamp != "" {
		if t, err := parseTimestamp(body.Timestamp); err == nil {
			asOf = t
		}
	}
	return body, asOf, nil
}

// nvdTimeLayouts covers the shapes NVD's "timestamp" field is documented to
// take: fractional seconds and without, always without a UTC offset.
var nvdTimeLayouts = []string{
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
	time.RFC3339,
}

func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range nvdTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized NVD timestamp %q", s)
}

// sleep is the pacing hook Annotate actually calls. A package variable
// rather than a direct call to sleepCtx so a test can substitute a
// recording stub - the alternative, asserting on elapsed wall-clock time,
// is exactly the flakiness a rate-limit pause should not force onto the
// test suite.
var sleep = sleepCtx

// sleepCtx pauses for d, or returns early with ctx's error if it is
// cancelled mid-wait. A ^C during a 20-minute sync depends on this, not just
// the check made between pages.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
