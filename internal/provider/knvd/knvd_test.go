package knvd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// TestMain zeroes the retry schedule for the whole package.
//
// Every failure test in this file would otherwise wait out the real
// schedule -- 4.5 minutes each -- and that is the
// wall-clock-standing-in-for-an-assertion hazard CLAUDE.md records, arriving
// as a side effect rather than as a test anyone wrote.
//
// The slice keeps its LENGTH, so attempt counts are unchanged and every
// assertion below still means what it means. Only the sleeping goes.
// TestRetryWaits_ShippedScheduleActuallyWaits covers the real values, which
// this necessarily hides.
func TestMain(m *testing.M) {
	retryWaits = make([]time.Duration, len(defaultRetryWaits))
	os.Exit(m.Run())
}

// The shipped schedule really waits. TestMain zeroes the working copy for
// speed, so without this, changing every production value to 0 -- turning
// each retry into a hot loop against a public-sector service -- would pass
// the entire suite.
//
// Asserted on the VALUES, never on elapsed time. A wall-clock version could
// only stop catching its mutation, never false-fail loudly: on a runner slow
// enough to blur the margin it quietly starts passing whatever the schedule
// says.
func TestRetryWaits_ShippedScheduleActuallyWaits(t *testing.T) {
	if len(defaultRetryWaits) == 0 {
		t.Fatal("no retry schedule at all")
	}
	var total time.Duration
	for i, w := range defaultRetryWaits {
		if w <= 0 {
			t.Errorf("defaultRetryWaits[%d] = %v, want a real pause", i, w)
		}
		total += w
	}
	// The BUDGET is the point, not merely that each value is non-zero. This
	// provider's own walk is seconds, but db update installs the database
	// only at the end, so giving up here discards whatever the same run
	// already fetched -- an NVD pass takes hours. The wait has to be
	// proportionate to what giving up costs, not to how long the retried
	// request takes.
	if min := 3 * time.Minute; total < min {
		t.Errorf("retry budget is %v, want at least %v -- giving up here discards the whole db update, not just this provider", total, min)
	}
	// ...and still short enough that a genuine outage fails the build rather
	// than hanging it.
	if max := 15 * time.Minute; total > max {
		t.Errorf("retry budget is %v, want at most %v", total, max)
	}
}

// durPtr takes the address of a duration literal, for Options.Pause: a
// *time.Duration cannot be constructed with & directly against a literal.
func durPtr(d time.Duration) *time.Duration { return &d }

// New fills in every default without making a request, and an explicitly set
// option is used verbatim -- including a zero Pause, which is a real request
// ("no spacing at all") rather than an absent one.
func TestNew_ResolvesOptions(t *testing.T) {
	t.Run("the zero Options is the production configuration", func(t *testing.T) {
		p := New(Options{})
		if p.baseURL != DefaultBaseURL {
			t.Errorf("baseURL = %q, want %q", p.baseURL, DefaultBaseURL)
		}
		if p.pageSize != defaultPageSize {
			t.Errorf("pageSize = %d, want %d", p.pageSize, defaultPageSize)
		}
		if p.pause != defaultPause {
			t.Errorf("pause = %v, want %v", p.pause, defaultPause)
		}
		// nil Progress must become io.Discard rather than staying nil: every
		// progress line goes through fmt.Fprintf, which panics on a nil
		// writer.
		if p.progress == nil {
			t.Error("progress is nil; a caller that sets no Progress must still be able to run")
		}
		if p.client == nil {
			t.Fatal("client is nil")
		}
		// An unbounded client would turn a hung service into a hung build.
		if p.client.Timeout <= 0 {
			t.Error("client has no timeout; a stalled response would hang db update forever")
		}
	})
	t.Run("explicit options are honoured verbatim", func(t *testing.T) {
		var buf bytes.Buffer
		p := New(Options{BaseURL: "http://example.invalid/x", PageSize: 7, Pause: durPtr(0), Progress: &buf})
		if p.baseURL != "http://example.invalid/x" {
			t.Errorf("baseURL = %q, want the one given", p.baseURL)
		}
		if p.pageSize != 7 {
			t.Errorf("pageSize = %d, want 7", p.pageSize)
		}
		if p.pause != 0 {
			t.Errorf("pause = %v, want the explicit 0 to survive rather than be defaulted", p.pause)
		}
	})
	t.Run("a non-zero Pause is honoured too", func(t *testing.T) {
		p := New(Options{Pause: durPtr(4 * time.Second)})
		if p.pause != 4*time.Second {
			t.Errorf("pause = %v, want 4s", p.pause)
		}
	})
	t.Run("Name is the authoring source stamped on every record", func(t *testing.T) {
		if got := New(Options{}).Name(); got != SourceName {
			t.Errorf("Name() = %q, want %q -- the enrichment bucket is keyed on it", got, SourceName)
		}
	})
}

// --- fixtures -------------------------------------------------------------

// notice builds one element of resList. content_text carries the CVE because
// that is the only field convert joins on; the other fields the live
// response carries are omitted deliberately, so a change that starts
// depending on one of them fails here rather than in production.
func notice(id, title, contentText string) string {
	b, err := json.Marshal(map[string]string{
		"id":           id,
		"title":        title,
		"content_text": contentText,
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// noticeNoID builds a notice with no id field at all -- broken data, but
// data the service can still serve. Written as a separate builder rather
// than notice("", …) so the JSON genuinely omits the key, which is what a
// missing field looks like on the wire.
func noticeNoID(title, contentText string) string {
	b, err := json.Marshal(map[string]string{
		"title":        title,
		"content_text": contentText,
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// page wraps notices in the envelope the live service returns:
// {"resType":"RES_OK","resMsg":null,"resList":[...]}.
func page(notices ...string) string {
	return `{"resType":"RES_OK","resMsg":null,"resList":[` + strings.Join(notices, ",") + `]}`
}

// emptyPage is what a skipCount past the end of the corpus answers --
// verified against the live service 2026-08-05, which returns HTTP 200 with
// an empty resList rather than an error or a 404.
var emptyPage = page()

func overview(cves ...string) string {
	return "□ 개요 o " + strings.Join(cves, " 및 ") + " 취약점 발견 □ 설명 o 상세"
}

// --- the fake service -----------------------------------------------------

// fakeKNVD serves canned pages keyed by the skipCount asked for.
//
// It fails the test on any skipCount it was not primed with, which is what
// makes the cursor arithmetic observable: advancing by the requested page
// size instead of by the notices actually returned asks for an offset that
// is not in the map, and that has to be a failure rather than a shrug.
//
// It also refuses to be spun. Beyond maxRequests it reports the walk as
// non-terminating and answers 400, which is not retryable -- so a loop that
// has lost its termination condition fails in milliseconds with a clear
// message instead of hanging until the package timeout.
type fakeKNVD struct {
	t           *testing.T
	pages       map[int]string
	maxRequests int

	mu     sync.Mutex
	skips  []int
	bodies []map[string]any
}

func (f *fakeKNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		f.t.Errorf("method = %s, want POST -- KNVD takes its query in the body", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		f.t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Errorf("request body is not JSON: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	skip, ok := body["skipCount"].(float64)
	if !ok {
		f.t.Errorf("request body carries no numeric skipCount: %v", body)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.skips = append(f.skips, int(skip))
	f.bodies = append(f.bodies, body)
	n := len(f.skips)
	f.mu.Unlock()

	if n > f.maxRequests {
		f.t.Errorf("request %d asked for skipCount %d: the walk made %d requests where at "+
			"most %d can make progress -- it is not terminating", n, int(skip), n, f.maxRequests)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body2, ok := f.pages[int(skip)]
	if !ok {
		f.t.Errorf("asked for skipCount %d, which this fake does not serve (it has %v) -- "+
			"the cursor must advance by the number of notices returned, not by the "+
			"requested page size", int(skip), sortedKeys(f.pages))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	io.WriteString(w, body2)
}

func (f *fakeKNVD) Skips() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.skips)
}

func (f *fakeKNVD) Body(i int) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[i]
}

func sortedKeys(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// newFake starts a server over pages. maxRequests bounds how many requests
// the walk may make before the fake calls it non-terminating.
func newFake(t *testing.T, maxRequests int, pages map[int]string) (*fakeKNVD, *httptest.Server) {
	t.Helper()
	f := &fakeKNVD{t: t, pages: pages, maxRequests: maxRequests}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// collect runs Enrich against srv and returns the CVEs emitted, in order.
func collect(t *testing.T, p *Provider) ([]string, []advisory.Enrichment, error) {
	t.Helper()
	var (
		cves []string
		recs []advisory.Enrichment
	)
	_, err := p.Enrich(context.Background(), func(e advisory.Enrichment) error {
		cves = append(cves, e.CVE)
		recs = append(recs, e)
		return nil
	})
	return cves, recs, err
}

// --- pagination -----------------------------------------------------------

// The pagination contract: keep asking until the corpus is covered, and emit
// every notice's CVEs along the way.
//
// The middle page is deliberately SHORT (one notice against a page size of
// two) rather than full. That is the only arrangement in which advancing by
// the requested page size and advancing by the notices actually returned
// produce different offsets, and the last page of a real walk is always the
// short one.
func TestEnrich_PagesThroughTheCorpus(t *testing.T) {
	f, srv := newFake(t, 4, map[int]string{
		0: page(
			notice("n-alpha", "제품 A 보안 업데이트 권고", overview("CVE-2026-1001")),
			notice("n-beta", "제품 B 보안 업데이트 권고", overview("CVE-2026-1002")),
		),
		2: page(notice("n-gamma", "제품 C 보안 업데이트 권고", overview("CVE-2026-1003"))),
		3: emptyPage,
	})

	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	cves, recs, err := collect(t, p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
	if !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v -- every page's notices, in page order", cves, want)
	}
	// The offsets, not just the count: a walk that asked for 0 three times
	// would also emit three records if the fake served them.
	if got, want := f.Skips(), []int{0, 2, 3}; !slices.Equal(got, want) {
		t.Errorf("skipCounts requested = %v, want %v -- advanced by notices returned", got, want)
	}
	// Every record is stamped with the authoring source, since that is half
	// the store key.
	for _, r := range recs {
		if r.Source != SourceName {
			t.Errorf("record %+v has Source %q, want %q", r, r.Source, SourceName)
		}
	}
}

// A short page does not end the walk on its own.
//
// The empty page is the only end-of-corpus signal this API documents by
// behaviour (verified 2026-08-05), so the walk asks once more after a short
// page and stops on the empty answer. That costs one request out of ~41 and
// means a service that ever starts capping page sizes below what was asked
// for truncates nothing: without it, the first capped page would end the
// sync and the missing notices would never be reported as missing.
func TestEnrich_AShortPageIsNotTheEndOfTheCorpus(t *testing.T) {
	f, srv := newFake(t, 3, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-2001"))),
		1: page(notice("n-beta", "제품 B 권고", overview("CVE-2026-2002"))),
		2: emptyPage,
	})

	// PageSize 5 against pages of one notice each: every page is short.
	p := New(Options{BaseURL: srv.URL, PageSize: 5, Pause: durPtr(0)})
	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CVE-2026-2001", "CVE-2026-2002"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v -- a short page must not be mistaken for the end", cves, want)
	}
	if got, want := f.Skips(), []int{0, 1, 2}; !slices.Equal(got, want) {
		t.Errorf("skipCounts requested = %v, want %v", got, want)
	}
}

// A zero-record page short of the end is refused rather than retried
// forever: nothing else advances skipCount, so it is the one response shape
// that cannot make progress.
//
// At skipCount 0 specifically it also means something worse than "no
// progress". KNVD's corpus holds ~2,039 notices, so a first page with
// nothing in it is a moved endpoint, a changed request schema, or a service
// refusing this client -- a broken run, which must never be reported as a
// successful one over an empty corpus.
func TestEnrich_RefusesAPageThatCannotMakeProgress(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		// This handler is the one shape that cannot advance the cursor, so a
		// walk that does not refuse it asks forever. Answering 400 -- which
		// is not retryable -- past the second request turns that into a
		// failure in milliseconds instead of a hang until the package
		// timeout. Verified: with the guard removed this test reports both
		// lines rather than blocking.
		if n > 2 {
			t.Errorf("request %d: the walk kept asking for a page that returns nothing", n)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		io.WriteString(w, emptyPage)
	}))
	defer srv.Close()

	p := New(Options{BaseURL: srv.URL, PageSize: 50, Pause: durPtr(0)})
	var emitted int
	prov, err := p.Enrich(context.Background(), func(advisory.Enrichment) error {
		emitted++
		return nil
	})
	if err == nil {
		t.Fatal("Enrich returned nil over a first page with no notices in it -- " +
			"a broken request must not report as an empty corpus")
	}
	if !strings.Contains(err.Error(), "zero notices") {
		t.Errorf("error %q does not say what went wrong", err)
	}
	if emitted != 0 {
		t.Errorf("emitted %d record(s) on a failed run", emitted)
	}
	if prov.Records != 0 {
		t.Errorf("Provenance.Records = %d on a failed run, want the zero value", prov.Records)
	}
	// Loud, not retried. Retrying cannot help -- the page cannot advance the
	// cursor however many times it is asked for -- and it would bury the
	// diagnosis under four minutes of silence.
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("made %d requests, want 1 -- a page that cannot make progress is refused, never retried", calls)
	}
}

// ...and past the first page the same zero-record answer is the ordinary end
// of the corpus, not an error. It is reached whenever the corpus size is an
// exact multiple of the page size, which for a corpus that grows daily is a
// routine day rather than an exotic one.
func TestEnrich_AnEmptyPagePastTheFirstEndsTheWalk(t *testing.T) {
	f, srv := newFake(t, 3, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-3001"))),
		1: emptyPage,
	})

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatalf("Enrich failed at the end of the corpus: %v", err)
	}
	if want := []string{"CVE-2026-3001"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v", cves, want)
	}
	if got, want := f.Skips(), []int{0, 1}; !slices.Equal(got, want) {
		t.Errorf("skipCounts requested = %v, want %v", got, want)
	}
}

// A service that ignores skipCount entirely must fail the run, not drive it
// forever.
//
// Nothing else in the walk can notice this. The pages are full, so the
// cursor advances; the record count climbs; the progress lines increment --
// it reads as a healthy sync while it repeats the same page and emits the
// same records indefinitely. Measured by review against a fake shaped like
// this one: 24,510 requests in two seconds, stopped only because the test
// supplied a context deadline. In production, paced at one request per
// second, that is db update hanging with every outward sign of working.
//
// Dropping nvd's `startIndex < total` loop bound is what opened this door,
// since the empty page then became the only exit. The assertion is that
// Enrich FAILS: merely stopping would report the first page's two notices as
// the whole corpus, which is the "found nothing" / "was broken" confusion one
// level up.
func TestEnrich_RefusesAServiceThatIgnoresSkipCount(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	// The same page every time, whatever is asked for.
	same := page(
		notice("n-alpha", "제품 A 권고", overview("CVE-2026-9301")),
		notice("n-beta", "제품 B 권고", overview("CVE-2026-9302")),
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n > 4 {
			t.Errorf("request %d: the walk is unbounded against a service that ignores skipCount", n)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		io.WriteString(w, same)
	}))
	defer srv.Close()

	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	_, _, err := collect(t, p)
	if err == nil {
		t.Fatal("Enrich returned nil against a service that serves the same page forever -- " +
			"a walk that cannot end must fail, not report what it happened to collect")
	}
	if !strings.Contains(err.Error(), "not honouring skipCount") {
		t.Errorf("error %q does not name the fault", err)
	}
	// ...and says WHERE, on both axes. The phrase above is a hard-coded
	// string in the format, so it passes just as well from a message that
	// dropped everything variable: the offset the walk stalled at and the
	// notice it kept being served. Both are what a reader needs to confirm
	// the diagnosis against the service by hand.
	if !strings.Contains(err.Error(), "skipCount 2") {
		t.Errorf("error %q does not say which offset the walk stalled at", err)
	}
	if !strings.Contains(err.Error(), "(n-alpha)") {
		t.Errorf("error %q does not name the notice that kept coming back", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Detected on the page after the first, which is the earliest it can be
	// known: one page alone is indistinguishable from a working service.
	if calls != 2 {
		t.Errorf("made %d requests, want 2", calls)
	}
}

// Two pages the walk cannot tell apart are refused as well.
//
// A notice with no id is broken data, and it defeats the guard above by
// removing the only thing pages are compared on. The gate is therefore on
// "is there a previous page" rather than on "did the previous page have an
// id": the alternative reads as the more careful check and is the opposite
// -- with every id empty, prevFirstID stays empty forever and the comparison
// meant to catch a repeat never runs, which is precisely the shape it exists
// to catch.
//
// The two pages here carry genuinely different notices, and refusing them is
// the intended answer rather than a tolerated false positive: with no id
// there is no evidence the service is advancing, and this provider does not
// trust unprovable progress. It costs nothing real -- convert builds a
// notice's link from its id, so an id-less corpus produces records pointing
// at nothing.
func TestEnrich_RefusesPagesItCannotTellApart(t *testing.T) {
	_, srv := newFake(t, 4, map[int]string{
		0: page(
			noticeNoID("제품 A 권고", overview("CVE-2026-9401")),
			noticeNoID("제품 B 권고", overview("CVE-2026-9402")),
		),
		2: page(
			noticeNoID("제품 C 권고", overview("CVE-2026-9403")),
			noticeNoID("제품 D 권고", overview("CVE-2026-9404")),
		),
	})

	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	_, _, err := collect(t, p)
	if err == nil {
		t.Fatal("Enrich returned nil over pages with no id on any notice -- with nothing " +
			"to compare, the walk cannot show it is making progress and must not proceed " +
			"as though it had")
	}
	if !strings.Contains(err.Error(), "not honouring skipCount") {
		t.Errorf("error %q does not name the fault", err)
	}
}

// The cursor advances by NOTICES, not by records emitted. Much of KNVD's
// corpus names no CVE at all, and convert returns nothing for those -- so a
// page of them yields zero records while still being a page that was read.
// Advancing by the record count would leave the cursor where it was and
// re-request the same offset forever.
func TestEnrich_AdvancesPastNoticesThatNameNoCVE(t *testing.T) {
	f, srv := newFake(t, 3, map[int]string{
		0: page(
			notice("n-alpha", "정기 점검 안내", "□ 개요 o 시스템 점검 일정 안내"),
			notice("n-beta", "정기 점검 안내 2", "□ 개요 o 두 번째 안내"),
		),
		2: page(notice("n-gamma", "제품 C 권고", overview("CVE-2026-4001"))),
		3: emptyPage,
	})

	p := New(Options{BaseURL: srv.URL, PageSize: 2, Pause: durPtr(0)})
	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CVE-2026-4001"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v", cves, want)
	}
	if got, want := f.Skips(), []int{0, 2, 3}; !slices.Equal(got, want) {
		t.Errorf("skipCounts requested = %v, want %v -- two notices were read even though they produced no records", got, want)
	}
}

// --- the request ----------------------------------------------------------

// The POST body is the contract with the service, and it is recorded rather
// than derived: the count endpoint answers RES_ERROR to every abbreviated
// body tried, so a field that looks inert is not known to be. Compared as a
// whole map, so dropping a field fails here rather than in production.
func TestEnrich_SendsTheRecordedRequestBody(t *testing.T) {
	f, srv := newFake(t, 2, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-5001"))),
		1: emptyPage,
	})

	p := New(Options{BaseURL: srv.URL, PageSize: 3, Pause: durPtr(0)})
	if _, _, err := collect(t, p); err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"sortBy":         "_id",
		"order":          float64(-1),
		"skipCount":      float64(0),
		"limit":          float64(3),
		"preKey":         "",
		"nextKey":        "",
		"changePerpage":  false,
		"searchOption":   "TITLE",
		"content":        "",
		"collectionType": "VULNOTICE",
		"tabs":           "ko",
	}
	if got := f.Body(0); !reflect.DeepEqual(got, want) {
		t.Errorf("first request body =\n  %v\nwant\n  %v", got, want)
	}
	// The second request differs only in skipCount, which is the whole
	// mechanism of the walk.
	if got := f.Body(1)["skipCount"]; got != float64(1) {
		t.Errorf("second request asked skipCount %v, want 1", got)
	}
	if got := f.Body(1)["limit"]; got != float64(3) {
		t.Errorf("second request asked limit %v, want the configured page size 3", got)
	}
}

// --- retries --------------------------------------------------------------

// A transient failure must not destroy the run. db update installs the
// database only at the end, so a failure here discards everything the same
// run already fetched, including an NVD pass that can take hours.
func TestEnrich_RetriesTransientFailures(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	pages := map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-6001"))),
		1: emptyPage,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		skip := int(body["skipCount"].(float64))
		io.WriteString(w, pages[skip])
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0), Progress: &progress})
	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatalf("Enrich failed despite the failures being transient: %v", err)
	}
	if want := []string{"CVE-2026-6001"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v -- the retry did not recover the page", cves, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 4 {
		t.Errorf("made %d requests, want 4 (two failures, then both pages)", calls)
	}
	// The wait is announced. A sync that pauses with no output is
	// indistinguishable from one that has hung.
	if !strings.Contains(progress.String(), "retrying in") {
		t.Errorf("progress = %q, want it to announce the retry", progress.String())
	}
}

// A failure that is NOT an HTTP status is retried too.
//
// This is the case an allow-list misses. nvd's first retry matched
// httpStatusError only, because a 503 was the failure that had just been
// seen -- and the next run died at 116 minutes on an HTTP/2 stream error
// surfacing during body decode, with the retry never firing. A truncated
// body reproduces that shape: the request succeeds with 200, the decode
// fails.
func TestEnrich_RetriesAFailureThatIsNotAnHTTPStatus(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	pages := map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-6002"))),
		1: emptyPage,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if n == 1 {
			// 200 with a body that stops mid-object: a decode error, not a
			// status error, which is what a dropped stream looks like by the
			// time it reaches this code.
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"resType":"RES_OK","resList":[{"id":`)
			return
		}
		io.WriteString(w, pages[int(body["skipCount"].(float64))])
	}))
	defer srv.Close()

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatalf("Enrich failed on a retryable decode error: %v", err)
	}
	if want := []string{"CVE-2026-6002"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v", cves, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Errorf("made %d requests, want 3 -- a non-status failure must still be retried", calls)
	}
}

// KNVD reports its own failures with HTTP 200 and an empty list. Verified
// 2026-08-05: the count endpoint answers
// {"resType":"RES_ERROR","resMsg":"시스템 오류가 발생하였습니다..."} with a
// 200. Without the resType check that arrives looking exactly like the end
// of the corpus -- so a service outage would silently truncate the walk, or,
// on the first page, be refused with a message blaming the wrong thing.
func TestEnrich_RetriesAnApplicationLevelError(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	pages := map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-6003"))),
		1: emptyPage,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if n == 1 {
			io.WriteString(w, `{"resType":"RES_ERROR","resMsg":"점검중","resList":[]}`)
			return
		}
		io.WriteString(w, pages[int(body["skipCount"].(float64))])
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0), Progress: &progress})
	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatalf("Enrich failed on a retryable application-level error: %v", err)
	}
	if want := []string{"CVE-2026-6003"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v", cves, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Errorf("made %d requests, want 3 -- RES_ERROR is the service failing, not an empty corpus", calls)
	}
	if !strings.Contains(progress.String(), "RES_ERROR") {
		t.Errorf("progress = %q, want the retry notice to name what failed", progress.String())
	}
}

// ...and one that never recovers fails naming what the service said, rather
// than with the empty-corpus message, which would send whoever reads it
// looking at the wrong thing.
//
// The rows past the first are why the check is "not RES_OK" rather than "is
// RES_ERROR". Every one of these decodes into a listResponse with no notices
// in it, so under an equality test against RES_ERROR they would all be read
// as the end of the corpus -- silently truncating the walk mid-corpus, or
// being blamed on an empty corpus at skipCount 0. A response type this code
// has not seen, and the bare {} a gateway can substitute for a body it could
// not proxy, are exactly the shapes nobody writes a case for.
func TestEnrich_AResponseThatIsNotRESOKIsNotAnEmptyCorpus(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantInErr string
	}{
		{"RES_ERROR, the documented failure", `{"resType":"RES_ERROR","resMsg":"점검중","resList":[]}`, "점검중"},
		{"a response type this code has never seen", `{"resType":"RES_WARN","resMsg":"부분 결과","resList":[]}`, "RES_WARN"},
		{"a bare object, as a gateway can substitute", `{}`, `resType ""`},
		{"a body carrying resList but no resType", `{"resList":[]}`, `resType ""`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
			_, _, err := collect(t, p)
			if err == nil {
				t.Fatal("Enrich returned nil against a service that never answered RES_OK")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q does not carry %q", err, tc.wantInErr)
			}
			// The failure must be attributed to the response, not to the
			// corpus. Blaming an empty corpus sends the reader to KISA's
			// content when the problem is the transport in front of it.
			if strings.Contains(err.Error(), "zero notices") {
				t.Errorf("error %q blames an empty corpus for a response that was never RES_OK", err)
			}
		})
	}
}

// A permanent failure is not retried. Retrying a 404 would bury a wrong
// request under four minutes of silence before reporting the same error.
func TestEnrich_DoesNotRetryAPermanentFailure(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	_, _, err := collect(t, p)
	if err == nil {
		t.Fatal("Enrich succeeded against a 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error %q does not carry the status", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("made %d requests, want 1 -- a 404 is this code getting the request wrong, not KISA having a bad moment", calls)
	}
}

// A context cancelled MID-REQUEST must not be retried: ^C has to stop, not
// wait out the whole schedule first.
//
// Cancelled mid-flight, deliberately. An already-cancelled context is caught
// by Enrich's own ctx.Err() check at the top of the loop, before fetchPage
// runs at all, so a test using one proves nothing about retryable.
//
// The assertion is on the retry NOTICE rather than the request count,
// because sleep() also honours the context: a mutated retryable would fail
// at the sleep instead and issue no extra request. The notice is the only
// externally visible difference.
func TestEnrich_DoesNotRetryAContextCancelledMidRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drained before blocking, and that is not incidental: net/http only
		// starts watching for the client disconnecting once the request body
		// has been consumed. This is a POST, so a handler that blocks
		// without reading the body never learns the client went away, and
		// httptest.Server.Close then waits on the connection until the
		// package timeout. (nvd's equivalent test is a GET, which is why it
		// does not need this.)
		io.Copy(io.Discard, r.Body)
		cancel()
		<-r.Context().Done()
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0), Progress: &progress})
	_, err := p.Enrich(ctx, func(advisory.Enrichment) error { return nil })
	if err == nil {
		t.Fatal("Enrich succeeded despite cancellation")
	}
	// The cancellation reaches the caller intact. Asserting only that the
	// progress writer stayed quiet is an assertion about a diagnostic: it
	// passes just as well if the writer went silent for an unrelated reason,
	// or if the retry was skipped and the error arrived as something the
	// caller cannot recognise as its own ^C.
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Enrich returned %v, want an error the caller can recognise as its own cancellation", err)
	}
	if strings.Contains(progress.String(), "retrying") {
		t.Errorf("progress = %q: a cancelled context was treated as retryable", progress.String())
	}
}

// A stalled page is retried, and that is the failure mode this provider is
// most likely to meet.
//
// net/http reports its OWN Client.Timeout as a deadline error: a
// timeoutError's Is(context.DeadlineExceeded) is true, for the
// response-header timeout and the body-read timeout alike (Go 1.26). So the
// obvious spelling of "do not retry a cancellation" --
// errors.Is(err, context.DeadlineExceeded) -- also catches this, and
// classifies the single most ordinary transient failure there is as
// permanent: the run aborts having retried nothing. Only the CALLER's
// context can answer the question that exclusion is asking.
func TestRetryable_JudgesTheCallersContextNotTheError(t *testing.T) {
	// Shaped like what net/http hands back, without waiting for a real
	// timeout to produce one: what matters is that errors.Is finds
	// DeadlineExceeded in it, which is precisely why the old test was wrong.
	timeout := fmt.Errorf("Post %q: %w", "http://example.invalid", context.DeadlineExceeded)

	if !retryable(context.Background(), timeout) {
		t.Error("a client timeout was judged permanent -- this is the retry's main reason to exist")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if retryable(cancelled, timeout) {
		t.Error("the caller's cancellation was retried; ^C must stop the walk, not restart it")
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if retryable(expired, timeout) {
		t.Error("an expired caller deadline was retried; the retry would outlive the deadline it was given")
	}
	// ...and the status rules are unchanged by the switch.
	for _, tc := range []struct {
		code int
		want bool
	}{
		{http.StatusNotFound, false},
		{http.StatusBadRequest, false},
		{http.StatusTooManyRequests, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusInternalServerError, true},
	} {
		if got := retryable(context.Background(), &httpStatusError{code: tc.code}); got != tc.want {
			t.Errorf("retryable(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

// ...and the same thing end to end, through a real net/http timeout rather
// than an error shaped like one, so this cannot pass on a wrong idea of what
// Client.Timeout produces.
func TestEnrich_RetriesARealClientTimeout(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	pages := map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-6004"))),
		1: emptyPage,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			// Never answers. The client's own Timeout ends the request; the
			// CALLER's context is untouched throughout, which is the whole
			// distinction being tested.
			<-r.Context().Done()
			return
		}
		var body map[string]any
		json.Unmarshal(raw, &body)
		io.WriteString(w, pages[int(body["skipCount"].(float64))])
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0), Progress: &progress})
	// A tenth of a second, against a local server that answers in
	// microseconds. The margin is still three orders of magnitude, so this
	// bounds a hang rather than asserting a speed -- and redness comes from
	// the explicit assertions below, not from the clock, so a loaded runner
	// can only make this slower, never flip it.
	p.client.Timeout = 100 * time.Millisecond

	cves, _, err := collect(t, p)
	if err != nil {
		t.Fatalf("Enrich failed on a client timeout, which is the most ordinary transient failure there is: %v", err)
	}
	if want := []string{"CVE-2026-6004"}; !slices.Equal(cves, want) {
		t.Errorf("emitted %v, want %v", cves, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Errorf("made %d requests, want 3 (one stalled page, then both pages)", calls)
	}
	if !strings.Contains(progress.String(), "retrying in") {
		t.Errorf("progress = %q, want the retry announced", progress.String())
	}
}

// Retries are bounded: a genuine outage fails the build rather than hanging
// it, and the schedule's LENGTH is the policy.
func TestEnrich_GivesUpAfterTheRetryScheduleIsExhausted(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	restore := retryWaits
	retryWaits = []time.Duration{0, 0, 0}
	defer func() { retryWaits = restore }()

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	_, _, err := collect(t, p)
	if err == nil {
		t.Fatal("Enrich succeeded against a permanently failing service -- a failed " +
			"sync must not read as a corpus with nothing in it")
	}
	mu.Lock()
	defer mu.Unlock()
	// One initial attempt plus one per scheduled wait.
	if want := len(retryWaits) + 1; calls != want {
		t.Errorf("made %d requests, want %d (the schedule is the policy)", calls, want)
	}
}

// --- progress, pacing, provenance ----------------------------------------

// The walk reports progress as it goes. Without it the loop prints nothing
// between "enriching with KISA" and its result, and lines that stop arriving
// are the only difference between stalled and slow.
func TestEnrich_ReportsProgress(t *testing.T) {
	_, srv := newFake(t, 3, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-7001"))),
		1: page(notice("n-beta", "제품 B 권고", overview("CVE-2026-7002", "CVE-2026-7003"))),
		2: emptyPage,
	})

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0), Progress: &progress})
	if _, _, err := collect(t, p); err != nil {
		t.Fatal(err)
	}
	out := progress.String()
	// One line per page that carried notices; the terminating empty page has
	// nothing to report.
	if got := strings.Count(out, "knvd: "); got != 2 {
		t.Errorf("progress has %d line(s), want one per page of notices (2):\n%s", got, out)
	}
	// The counts have to be real, not a bare heartbeat: a line that says
	// only "working" cannot distinguish progress from a loop re-reading the
	// same page. Both numbers are asserted because they diverge -- the
	// second page's one notice carries two CVEs.
	for _, want := range []string{"1 notices, 1 records", "2 notices, 3 records"} {
		if !strings.Contains(out, want) {
			t.Errorf("progress does not report %q:\n%s", want, out)
		}
	}
}

// Enrich paces requests through the sleep hook, not a bare sleepCtx call,
// specifically so this can be asserted without spending the real pause to
// prove it. Every other test here uses Pause: durPtr(0), and sleepCtx's
// "d <= 0 returns immediately" fast path means deleting the pacing call
// entirely breaks none of them.
func TestEnrich_PacesRequestsWithConfiguredPause(t *testing.T) {
	var calls []time.Duration
	orig := sleep
	sleep = func(_ context.Context, d time.Duration) error {
		calls = append(calls, d)
		return nil
	}
	defer func() { sleep = orig }()

	_, srv := newFake(t, 3, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-8001"))),
		1: page(notice("n-beta", "제품 B 권고", overview("CVE-2026-8002"))),
		2: emptyPage,
	})

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(3 * time.Second)})
	if _, _, err := collect(t, p); err != nil {
		t.Fatal(err)
	}
	// Three requests, so two gaps -- never before the first request, which
	// would add a pause to a one-page walk for nothing.
	want := []time.Duration{3 * time.Second, 3 * time.Second}
	if !slices.Equal(calls, want) {
		t.Errorf("sleep calls = %v, want %v -- paced between requests, using the configured Pause", calls, want)
	}
}

// sleepCtx must return when its context is cancelled, not wait out the full
// pause -- ^C during a paced walk depends on this, and every test above uses
// a zero pause, which returns through the "d <= 0" fast path before the
// cancellation-aware select is ever reached.
//
// Deterministic by construction rather than by timing: the context is
// already cancelled, so its channel is ready and the timer is an hour away.
// The 10-second bound is not an assertion about speed -- it is the only way
// to turn "this hangs" into a failure, and the gap between "returns at once"
// and "waits an hour" is far too wide for a loaded runner to blur.
func TestSleepCtx_ReturnsWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- sleepCtx(ctx, time.Hour) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("sleepCtx returned nil for a cancelled context; the caller cannot tell it was interrupted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sleepCtx ignored its cancelled context and is waiting out the full hour")
	}
}

// Provenance answers what was fetched, from where, and when this run read it.
//
// DataAsOf is the FETCH time, deliberately (D12): KNVD's list carries no
// feed timestamp -- reservedDate says when a notice was published, not when
// the list was last current -- so there is no upstream freshness to report
// and inventing one is the failure D12 exists to prevent.
func TestEnrich_ProvenanceRecordsWhatWasFetched(t *testing.T) {
	_, srv := newFake(t, 3, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-9001", "CVE-2026-9002"))),
		1: emptyPage,
	})

	pinned := time.Date(2026, 8, 5, 9, 30, 0, 0, time.UTC)
	restore := nowUTC
	nowUTC = func() time.Time { return pinned }
	defer func() { nowUTC = restore }()

	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	prov, err := p.Enrich(context.Background(), func(advisory.Enrichment) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if prov.Source != srv.URL {
		t.Errorf("Provenance.Source = %q, want the URL actually fetched %q", prov.Source, srv.URL)
	}
	if !prov.DataAsOf.Equal(pinned) {
		t.Errorf("Provenance.DataAsOf = %v, want the fetch time %v", prov.DataAsOf, pinned)
	}
	// Records counts what was EMITTED, which is one per CVE, not one per
	// notice: the store keys enrichment on the CVE.
	if prov.Records != 2 {
		t.Errorf("Provenance.Records = %d, want 2 (one per CVE named)", prov.Records)
	}
	// An enricher describes CVEs; it never says which package is affected,
	// so claiming ecosystem coverage here would widen what the database
	// reports it covers (D20).
	if len(prov.Ecosystems) != 0 {
		t.Errorf("Provenance.Ecosystems = %v, want none -- enrichment is not coverage", prov.Ecosystems)
	}
}

// An emit failure stops the emit loop instead of being swallowed. The caller is
// writing to a database; a failed write that the loop carries on past means
// db update reports a corpus it did not store.
//
// D33 moved emission after the walk, so this no longer saves requests — the
// walk has to finish before a winner can be chosen at all. What it must still
// guarantee is that the error reaches the caller verbatim and that no further
// record is offered after the first refusal, which is the half that protects
// the database rather than the network.
func TestEnrich_StopsWhenEmitFails(t *testing.T) {
	_, srv := newFake(t, 3, map[int]string{
		0: page(notice("n-alpha", "제품 A 권고", overview("CVE-2026-9101"))),
		1: page(notice("n-beta", "제품 B 권고", overview("CVE-2026-9102"))),
		2: emptyPage,
	})

	want := errBoom
	emits := 0
	p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
	_, err := p.Enrich(context.Background(), func(advisory.Enrichment) error {
		emits++
		return want
	})
	if err != want {
		t.Fatalf("Enrich returned %v, want the emit error %v verbatim", err, want)
	}
	// Two CVEs are in the corpus. Continuing past the first refusal would offer
	// the second, and a loop that ignored the error entirely would offer it and
	// return nil — the assertion above catches that, and this one catches the
	// half-measure that logs and carries on.
	if emits != 1 {
		t.Errorf("offered %d records after the first emit failed, want 1", emits)
	}
}

// D33. One CVE named by two notices used to keep whichever page arrived last —
// 1,791 of 20,314 records on the real corpus. The narrowest notice must win
// regardless of the order the pages come in, so the same corpus is walked twice
// with the notices swapped and both runs must agree.
func TestEnrich_NarrowestNoticeWins(t *testing.T) {
	// The roundup names the CVE the specific notice is about, plus two others,
	// exactly as KISA's monthly bulletins do.
	specific := notice("n-openssl", "OpenSSL 제품 보안 업데이트 권고", overview("CVE-2026-1111"))
	roundup := notice("n-monthly", "MS 정기 보안 업데이트 권고",
		overview("CVE-2026-1111 CVE-2026-2222 CVE-2026-3333"))

	for _, tc := range []struct {
		name       string
		first, snd string
	}{
		{"specific arrives first", specific, roundup},
		{"roundup arrives first", roundup, specific},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, srv := newFake(t, 3, map[int]string{
				0: page(tc.first),
				1: page(tc.snd),
				2: emptyPage,
			})
			got := map[string]advisory.Enrichment{}
			p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
			prov, err := p.Enrich(context.Background(), func(e advisory.Enrichment) error {
				got[e.CVE] = e
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// The shared CVE takes the notice that named only it.
			shared := got["CVE-2026-1111"]
			if shared.Title != "OpenSSL 제품 보안 업데이트 권고" {
				t.Errorf("CVE-2026-1111 kept %q, want the notice that names only it", shared.Title)
			}
			if shared.Claims != 1 {
				t.Errorf("CVE-2026-1111 Claims = %d, want 1", shared.Claims)
			}
			// The two the roundup alone names still get it — losing to a
			// narrower notice is not the same as being dropped, and a rule that
			// discarded roundups outright would take these with them.
			for _, cve := range []string{"CVE-2026-2222", "CVE-2026-3333"} {
				if got[cve].Title != "MS 정기 보안 업데이트 권고" {
					t.Errorf("%s kept %q, want the roundup that is its only source", cve, got[cve].Title)
				}
				if got[cve].Claims != 3 {
					t.Errorf("%s Claims = %d, want 3 — a reader must be able to see the breadth", cve, got[cve].Claims)
				}
			}
			if len(got) != 3 {
				t.Errorf("emitted %d CVEs, want 3", len(got))
			}
			// Records reports what the database will hold, not what convert
			// produced. Four records were converted; three survive selection.
			if prov.Records != 3 {
				t.Errorf("Provenance.Records = %d, want 3 — the count must not include what selection discarded", prov.Records)
			}
		})
	}
}

// better()'s equal-Claims tie-break on URL exists, per its own comment,
// purely so the winner does not depend on which page arrived first (D25/D33's
// forbidden tie-break) -- and nothing driving Enrich ever reached it.
// TestEnrich_NarrowestNoticeWins ties Claims 1 against 3, which resolves in
// the a.Claims != b.Claims branch, and TestKeep_UnknownBreadthDoesNotDisplaceKnown
// ties 0 against 9, the a.Claims == 0 branches. Only two notices tied on the
// SAME nonzero breadth reach the `default` arm this test targets, and only
// walking them in both page orders proves the winner is the URL, not
// whichever page the fake happened to serve first.
func TestEnrich_EqualBreadthTiesBreakOnURLNotArrivalOrder(t *testing.T) {
	// Both notices claim exactly two CVEs (Claims == 2, tied and nonzero) and
	// share CVE-2026-5001. detailURL + id makes n-alpha's URL lexically
	// smaller than n-beta's, so the shared CVE must end up with n-alpha's
	// title regardless of which page is served first.
	alpha := notice("n-alpha", "Product A 보안 업데이트 권고",
		overview("CVE-2026-5001", "CVE-2026-5002"))
	beta := notice("n-beta", "Product B 보안 업데이트 권고",
		overview("CVE-2026-5001", "CVE-2026-5003"))

	for _, tc := range []struct {
		name       string
		first, snd string
	}{
		{"alpha (smaller URL) arrives first", alpha, beta},
		{"beta (larger URL) arrives first", beta, alpha},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, srv := newFake(t, 3, map[int]string{
				0: page(tc.first),
				1: page(tc.snd),
				2: emptyPage,
			})
			got := map[string]advisory.Enrichment{}
			p := New(Options{BaseURL: srv.URL, PageSize: 1, Pause: durPtr(0)})
			if _, err := p.Enrich(context.Background(), func(e advisory.Enrichment) error {
				got[e.CVE] = e
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			shared := got["CVE-2026-5001"]
			if shared.Title != "Product A 보안 업데이트 권고" {
				t.Errorf("CVE-2026-5001 kept %q, want n-alpha's title (the lexically "+
					"smaller URL) regardless of arrival order", shared.Title)
			}
		})
	}
}

// A source that does not report breadth must not outrank one that does. Claims
// is zero for such a record, and reading zero as "narrowest" would let it win
// every tie against a notice that honestly said it covers one CVE.
func TestKeep_UnknownBreadthDoesNotDisplaceKnown(t *testing.T) {
	known := advisory.Enrichment{CVE: "CVE-2026-1", Source: "KISA", URL: "z", Claims: 9}
	unknown := advisory.Enrichment{CVE: "CVE-2026-1", Source: "OTHER", URL: "a", Claims: 0}

	// Either arrival order, same answer — and the URL ordering is deliberately
	// set so a tie-break on URL alone would pick the unknown one.
	for _, order := range [][]advisory.Enrichment{{known, unknown}, {unknown, known}} {
		best := map[string]advisory.Enrichment{}
		for _, e := range order {
			keep(best, e)
		}
		if got := best["CVE-2026-1"].Claims; got != 9 {
			t.Errorf("kept Claims = %d, want 9: an unreported breadth is unknown, not narrowest", got)
		}
	}
}

type boomError struct{}

func (boomError) Error() string { return "store is closed" }

var errBoom = boomError{}
