package knvd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Checked here, not just at the first caller: a method added to
// provider.Enricher without a matching change here should fail this
// package's own build, not surface as a missing-method error somewhere else
// entirely. Same reasoning as the assertion in internal/provider/nvd.
var _ provider.Enricher = (*Provider)(nil)

// DefaultBaseURL is KNVD's security-notice list endpoint. It is a POST API
// with the query in the body, not a REST collection, so there is nothing to
// append to this URL — see listRequest.
const DefaultBaseURL = "https://knvd.krcert.or.kr/api/core/pu/view/vuln-notice/get"

// defaultPageSize is the page size KNVD's own site uses. Measured against
// the live service 2026-08-05: a 50-notice page is ~1.0 MB and returns in
// ~0.14 s, so the ~2,039-notice corpus is ~41 requests and a few seconds of
// network. Larger pages work (a limit of 500 returned exactly 500 notices,
// 10.2 MB) but 50 is the traffic pattern the service already expects.
const defaultPageSize = 50

// defaultPause spaces sequential requests. KISA publishes no rate limit, so
// unlike NVD's 6.5 s this is politeness rather than a documented budget: at
// 0.14 s per page the whole corpus would otherwise arrive as a six-second
// burst of 41 requests against a public-sector service, which is
// indistinguishable from scraping. One second keeps the walk under a minute.
const defaultPause = time.Second

// Options configures New. Callers normally set nothing; PageSize, BaseURL
// and Pause exist so a test can shrink a page and remove the spacing without
// changing the production defaults.
type Options struct {
	// BaseURL and PageSize default from their zero value ("" and 0) because
	// neither is a meaningful request on its own — nobody wants an empty URL
	// or a literal zero-notice page — so the zero value is an unambiguous
	// "not set".
	BaseURL  string
	PageSize int
	// Pause is the delay between requests, or nil for defaultPause.
	//
	// A *time.Duration, not a bare time.Duration, for the same reason
	// nvd.Options.Pause is: zero is a real, requestable value — "no pause at
	// all", which a test or a caller pointed at a local mirror genuinely
	// wants — and it is also Duration's zero value, so it cannot double as
	// "not set" without colliding with that explicit request.
	Pause *time.Duration
	// Progress is where per-page and retry notices go, or nil for
	// io.Discard.
	//
	// An option rather than a parameter because provider.Enricher's
	// signature is Enrich(ctx, emit) and must stay that way — every enricher
	// shares it, and threading a writer through the interface to serve one
	// implementation's diagnostics is the wrong trade.
	Progress io.Writer
}

type Provider struct {
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
	// The default applies only when Pause is left nil — an explicit zero is
	// used verbatim, never overridden, per the Options.Pause doc above.
	pause := defaultPause
	if opts.Pause != nil {
		pause = *opts.Pause
	}
	progress := opts.Progress
	if progress == nil {
		progress = io.Discard
	}
	return &Provider{
		baseURL:  baseURL,
		pageSize: pageSize,
		pause:    pause,
		// Ordinary TLS, deliberately: the default transport verifies the
		// chain. The reference KNVD crawler this work started from disables
		// verification, and checking the live service on 2026-08-05 showed
		// there is no reason to — it presents a chain that verifies strictly
		// ("Verify return code: 0 (ok)"). Turning verification off to fetch
		// security data would mean anyone on the path could choose what this
		// scanner believes about a vulnerability.
		//
		// The timeout is measured, not guessed: a 50-notice page is ~1.0 MB
		// and took 0.14 s on 2026-08-05, and even a 500-notice page (10.2 MB)
		// returned well inside a minute. Two minutes is room for a bad
		// connection without hanging forever.
		client:   &http.Client{Timeout: 2 * time.Minute},
		progress: progress,
	}
}

func (p *Provider) Name() string { return SourceName }

// defaultRetryWaits paces retries of a single page.
//
// The budget is ~4.5 minutes, which is far longer than this provider's own
// walk (seconds), and that is the point: the budget is measured against what
// giving up COSTS, not against how long the thing being retried takes. db
// update builds into a temporary database and installs it only at the end,
// so a KNVD failure discards everything the same run already fetched —
// including an NVD pass that can take hours. Retrying for four minutes to
// protect that is proportionate; nvd's first schedule totalled 62 s and
// threw away a run that had spent 5h52m.
//
// Values, not a fixed count, because the schedule IS the policy: a test that
// shrinks it must not also change how many attempts happen.
//
// Held separately from retryWaits so a test can assert the shipped values
// are non-zero even though TestMain zeroes the working copy. Without that
// split, zeroing the production schedule — turning every retry into a hot
// loop against a public service — would pass the suite.
var defaultRetryWaits = []time.Duration{
	5 * time.Second,
	20 * time.Second,
	time.Minute,
	3 * time.Minute,
}

// retryWaits is the working copy the retry loop reads. TestMain replaces it
// with a same-length, all-zero slice so the suite does not sleep.
var retryWaits = defaultRetryWaits

// retryable decides whether an error is worth another attempt.
//
// The policy is a deny-list, not an allow-list, and that is inherited from
// nvd as a correction rather than as a style. nvd's first version retried
// HTTP status errors only, because a 503 was the failure that had just been
// observed; the next run died at 116 minutes on an HTTP/2 stream error
// surfacing during body decode, and the retry never fired. Enumerating the
// transient cases only ever covers the one already seen.
//
// So everything is retryable except the two categories that definitely are
// not:
//
//   - A cancelled or expired context is the caller saying stop. Retrying it
//     ignores ^C and outlives the deadline it was given.
//   - A 4xx other than 429 is this code getting the request wrong. Retrying
//     makes the same mistake more slowly.
//
// Everything else — 5xx, 429, connection resets, stream errors, truncated
// bodies, and KNVD's own RES_ERROR (which arrives as HTTP 200, see
// fetchPage) — is the service or the network having a bad moment.
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

// nlFmt appends a newline to a format string. Assembled rather than typed,
// because a literal escape inside a tool argument or a generating script has
// silently become the byte it denotes three times on this repository — see
// CLAUDE.md.
func nlFmt(s string) string { return s + string(rune(10)) }

// fetchPageRetrying retries one page through transient failures, announcing
// each attempt. Silence here would be worse than the failure: a sync that
// stalls with no output is indistinguishable from one that has hung.
func (p *Provider) fetchPageRetrying(ctx context.Context, skipCount int) (listResponse, error) {
	for attempt := 0; ; attempt++ {
		page, err := p.fetchPage(ctx, skipCount)
		if err == nil {
			return page, nil
		}
		if !retryable(err) || attempt >= len(retryWaits) {
			return listResponse{}, err
		}
		wait := retryWaits[attempt]
		fmt.Fprintf(p.progress, nlFmt("knvd: page at skipCount %d failed (%v); retrying in %s (attempt %d of %d)"),
			skipCount, err, wait, attempt+1, len(retryWaits))
		if err := sleep(ctx, wait); err != nil {
			return listResponse{}, err
		}
	}
}

// Enrich walks KNVD's notice list from skipCount 0 and emits one enrichment
// record per CVE named in each notice.
//
// Requests are made one at a time, in order, never in parallel: this is a
// public-sector service with no published rate limit, and concurrency would
// buy a few seconds at the cost of looking like an attack.
//
// How the walk terminates, since the list response carries no total. The
// three behaviours below were confirmed against the live service on
// 2026-08-05, because guessing any of them is a silent partial sync:
//
//   - A skipCount past the end answers HTTP 200 with an empty resList. That
//     empty page is the end-of-corpus signal, and it is the only one this
//     API gives.
//   - limit is honoured exactly (a limit of 500 returned exactly 500), so a
//     SHORT page is the corpus ending inside it. It is not treated as
//     terminal even so: the walk continues to the empty page, which costs
//     one extra request out of ~41 and means a service that ever starts
//     capping page sizes truncates nothing.
//   - The separate count endpoint (.../count/get) is not usable — every body
//     tried, including the list endpoint's own, answered RES_ERROR — so
//     there is no total to page against the way nvd pages against
//     totalResults.
//
// That leaves the zero-record page carrying two different meanings, and the
// difference is where the cursor is; see the guard below.
func (p *Provider) Enrich(ctx context.Context, emit func(advisory.Enrichment) error) (store.Provenance, error) {
	prov := store.Provenance{
		Source: p.baseURL,
		// The FETCH time, not an upstream one, and deliberately so (D12).
		// KNVD's list response carries no feed timestamp: reservedDate is
		// when a notice was published, which says nothing about when the
		// list this run read was last current, and the newest notice's date
		// would report a quiet week as stale data. Recording the fetch time
		// under-claims — a mirror replaying an old snapshot would look fresh
		// — but inventing an upstream freshness the data does not support is
		// the failure D12 exists to prevent, and this is the honest half of
		// it.
		DataAsOf: nowUTC(),
	}
	var (
		skipCount int
		notices   int
		records   int
		first     = true
	)
	for {
		// Checked at the top of the loop rather than left to the request's
		// own context: this skips the pause AND the wasted request attempt
		// when the cancellation is already known, instead of discovering it
		// one HTTP call later.
		if err := ctx.Err(); err != nil {
			return store.Provenance{}, err
		}
		if !first {
			// Paced between requests, not merely checked between them: a
			// cancellation arriving mid-pause must not wait out the rest of
			// it. Called through the sleep variable so a test can substitute
			// a counting stub rather than spending the real pause to prove
			// pacing happens.
			if err := sleep(ctx, p.pause); err != nil {
				return store.Provenance{}, err
			}
		}
		first = false

		page, err := p.fetchPageRetrying(ctx, skipCount)
		if err != nil {
			return store.Provenance{}, err
		}

		n := len(page.ResList)
		// A zero-record page is the one response shape that cannot advance
		// skipCount — nothing below this point changes it except the number
		// of notices returned — so it can never be retried or re-requested,
		// only acted on. What it means depends on where the cursor is:
		//
		//   - past the first page it is the documented end of the corpus
		//     (verified above), and the walk is done;
		//   - at skipCount 0 it is a request that came back with nothing
		//     while the corpus holds ~2,039 notices. That is a broken sync —
		//     a moved endpoint, a changed request schema, a service refusing
		//     this client — and reporting it as a successful run over an
		//     empty corpus is exactly the "found nothing" / "was broken"
		//     confusion the CLI contract forbids. It is refused outright.
		if n == 0 {
			if skipCount == 0 {
				return store.Provenance{}, fmt.Errorf(
					"knvd: %s returned zero notices on the first page - refusing to "+
						"report a broken request as an empty corpus", p.baseURL)
			}
			break
		}

		for _, notice := range page.ResList {
			for _, e := range convert(notice) {
				if err := emit(e); err != nil {
					return store.Provenance{}, err
				}
				records++
			}
		}
		notices += n
		// Advanced by the number of NOTICES the page actually returned —
		// never by the requested page size, which the last page does not
		// honour, and never by the records emitted, which is a different
		// number entirely: a notice naming no CVE converts to nothing, and a
		// page of such notices would leave the cursor where it was and spin.
		skipCount += n

		// Progress, once per page. Without it this loop prints nothing
		// between "enriching with KISA" and its result, and lines that stop
		// arriving are the difference between stalled and slow. Both counts
		// are here because they diverge: notices is the walk's position,
		// records is what the walk is worth, and a corpus that suddenly
		// yields far fewer records per notice is worth seeing.
		fmt.Fprintf(p.progress, nlFmt("knvd: %d notices, %d records"), notices, records)
	}
	prov.Records = records
	return prov, nil
}

// listRequest is KNVD's query, sent as the POST body. Recorded verbatim from
// a live call on 2026-08-05; the service rejects or misinterprets partial
// bodies (the count endpoint answers RES_ERROR to every abbreviated form
// tried), so the unused-looking fields are sent as the site itself sends
// them rather than trimmed to what appears to matter.
//
// Sorting is by _id descending, as recorded. That leaves one hazard worth
// naming: notices are keyed by a time-ordered id, so a notice published
// DURING the walk is inserted at the front and shifts every later offset by
// one, pushing one notice past an offset already consumed. The walk is under
// a minute and KISA publishes a few notices a day, and the loss is bounded
// to one record of prose — an Enrichment can never reach a verdict — so this
// is not worth deviating from a request body confirmed against the live
// service. It would be, for anything that could change an exit code.
type listRequest struct {
	SortBy         string `json:"sortBy"`
	Order          int    `json:"order"`
	SkipCount      int    `json:"skipCount"`
	Limit          int    `json:"limit"`
	PreKey         string `json:"preKey"`
	NextKey        string `json:"nextKey"`
	ChangePerpage  bool   `json:"changePerpage"`
	SearchOption   string `json:"searchOption"`
	Content        string `json:"content"`
	CollectionType string `json:"collectionType"`
	Tabs           string `json:"tabs"`
}

// listResponse is one page of KNVD's notice list.
type listResponse struct {
	// ResType is "RES_OK" or "RES_ERROR". It matters because KNVD reports
	// application errors with HTTP 200 and an empty resList — verified
	// 2026-08-05 against the count endpoint, which answers
	// {"resType":"RES_ERROR",...} with a 200. Without this field a service
	// outage would arrive looking exactly like the end of the corpus.
	ResType string `json:"resType"`
	// ResMsg is null on success and a Korean diagnostic on failure. It is
	// carried into the error text rather than dropped: the message is the
	// only thing distinguishing one RES_ERROR from another.
	ResMsg  string      `json:"resMsg"`
	ResList []rawNotice `json:"resList"`
}

const resTypeOK = "RES_OK"

// nowUTC is a seam so a test can pin Provenance.DataAsOf.
var nowUTC = func() time.Time { return time.Now().UTC() }

// fetchPage requests one page.
func (p *Provider) fetchPage(ctx context.Context, skipCount int) (listResponse, error) {
	// Marshalled per attempt rather than once per page, so a retry sends a
	// fresh reader: a consumed body would make the second attempt a POST
	// with nothing in it, which this API answers with an error that looks
	// like the service's fault.
	body, err := json.Marshal(listRequest{
		SortBy:         "_id",
		Order:          -1,
		SkipCount:      skipCount,
		Limit:          p.pageSize,
		SearchOption:   "TITLE",
		CollectionType: "VULNOTICE",
		Tabs:           "ko",
	})
	if err != nil {
		return listResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL, bytes.NewReader(body))
	if err != nil {
		return listResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return listResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return listResponse{}, &httpStatusError{
			code: resp.StatusCode,
			msg:  fmt.Sprintf("POST %s (skipCount %d): %s", p.baseURL, skipCount, resp.Status),
		}
	}

	var out listResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return listResponse{}, fmt.Errorf("decode knvd response: %w", err)
	}
	if out.ResType != resTypeOK {
		// Not an httpStatusError, so retryable() treats it as transient —
		// which is right: RES_ERROR is the service saying it failed, the
		// same class as a 500, and it arrives with a 200 only because of how
		// this API is built.
		return listResponse{}, fmt.Errorf("knvd: %s at skipCount %d: %s", out.ResType, skipCount, out.ResMsg)
	}
	return out, nil
}

// sleep is the pacing hook Enrich actually calls. A package variable rather
// than a direct call to sleepCtx so a test can substitute a counting stub —
// the alternative, asserting on elapsed wall-clock time, is exactly the
// flakiness a pause should not force onto the suite.
var sleep = sleepCtx

// sleepCtx pauses for d, or returns early with ctx's error if it is
// cancelled mid-wait.
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
