package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

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
	APIKey   string
	BaseURL  string
	PageSize int
	Pause    time.Duration
}

type Provider struct {
	apiKey   string
	baseURL  string
	pageSize int
	pause    time.Duration
	client   *http.Client
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
	pause := opts.Pause
	if pause == 0 {
		pause = defaultPause
		if opts.APIKey != "" {
			pause = defaultPauseWithKey
		}
	}
	return &Provider{
		apiKey:   opts.APIKey,
		baseURL:  baseURL,
		pageSize: pageSize,
		pause:    pause,
		// A single page is ~4.3 MB at the default page size (measured); a
		// generous timeout leaves room for a slow connection without hanging
		// forever.
		client: &http.Client{Timeout: 2 * time.Minute},
	}
}

func (p *Provider) Name() string { return SourceName }

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
	)
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
			// it before Annotate notices.
			if err := sleepCtx(ctx, p.pause); err != nil {
				return store.Provenance{}, err
			}
		}
		first = false

		page, pageAsOf, err := p.fetchPage(ctx, startIndex)
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
		// Advanced by what the page actually returned, not by the requested
		// page size: NVD's own resultsPerPage can be smaller on the last
		// page, and advancing by the request size would either skip records
		// or loop forever short of totalResults.
		startIndex += len(page.Vulnerabilities)
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

func (p *Provider) fetchPage(ctx context.Context, startIndex int) (apiResponse, time.Time, error) {
	u := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", p.baseURL, p.pageSize, startIndex)
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
		return apiResponse{}, time.Time{}, fmt.Errorf("GET %s: %s", u, resp.Status)
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
