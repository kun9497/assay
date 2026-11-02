package photon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// fetchBackoffForTest shrinks the retry backoff to keep the retry tests
// fast, restoring the shipped schedule afterward -- eol.fetchBackoffForTest
// and epss/kev's own copies take the identical shape, for the identical
// reason: a test must not be able to silently zero the production backoff
// for every other test in the package.
func fetchBackoffForTest() func() {
	orig := fetchBackoff
	fetchBackoff = func(int) time.Duration { return time.Millisecond }
	return func() { fetchBackoff = orig }
}

// statusTruncate, as a scripted status, stages the one transport failure
// an httptest server can produce portably (the shape fedora's own
// TestFetch_RetriesAMidBodyTruncationThenSucceeds uses): a 200 that
// declares a large Content-Length and writes a fragment, so the client's
// decode dies with io.ErrUnexpectedEOF.
const statusTruncate = -1

// scriptedServer is photonServer with a per-major script of HTTP statuses:
// the n-th request for "/cve_data_photon<version>.json" answers script[n]
// until the script runs out, after which every request serves rows[version]
// as a 200. calls reports how many requests each major's path has seen,
// which is what every test below holds the retry loop to -- "retried" is a
// request count, not a log line.
func scriptedServer(t *testing.T, rows map[string][]rawRow, script map[string][]int) (*httptest.Server, func(version string) int) {
	t.Helper()
	var mu sync.Mutex
	calls := map[string]int{}
	mux := http.NewServeMux()
	for version, rs := range rows {
		version, rs := version, rs
		mux.HandleFunc("/cve_data_photon"+version+".json", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n := calls[version]
			calls[version]++
			seq := script[version]
			mu.Unlock()
			if n < len(seq) {
				switch status := seq[n]; status {
				case statusTruncate:
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Length", "100000")
					w.Write([]byte(`[{"cve_id": "CVE-`))
				default:
					http.Error(w, http.StatusText(status), status)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rs); err != nil {
				t.Fatal(err)
			}
		})
	}
	return httptest.NewServer(mux), func(version string) int {
		mu.Lock()
		defer mu.Unlock()
		return calls[version]
	}
}

// retryRows is one Fixed row per major, so a run whose retry succeeds
// yields three advisories and trips neither the zero-advisories guard nor
// the mux's 404 for a major it was given no rows for.
var retryRows = map[string][]rawRow{
	"3.0": {{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph3", Status: "Fixed"}},
	"4.0": {{CVEID: "CVE-2026-10002", Pkg: "krb5", ResVer: "1.20.2-9.ph4", Status: "Fixed"}},
	"5.0": {{CVEID: "CVE-2026-10003", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"}},
}

// runFetchProgress is runFetch with a caller-chosen context and the
// progress stream returned too, for the tests that hold the retry to its
// one disclosure line or cancel it mid-backoff.
func runFetchProgress(t *testing.T, ctx context.Context, srv *httptest.Server, majors []Major) ([]advisory.Advisory, string, error) {
	t.Helper()
	var progress strings.Builder
	p := New(Options{Majors: majors, BaseURL: srv.URL + "/", Progress: &progress})
	var emitted []advisory.Advisory
	_, err := p.Fetch(ctx, func(a advisory.Advisory) error {
		emitted = append(emitted, a)
		return nil
	})
	return emitted, progress.String(), err
}

// retryLine returns the one progress line that announces a retry, failing
// the test when there is not exactly one: two lines for one retry would
// mean the loop announced an attempt it did not make.
func retryLine(t *testing.T, progress string) string {
	t.Helper()
	var found []string
	for _, l := range strings.Split(progress, string(rune(10))) {
		if strings.Contains(l, "retrying") {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("progress carries %d retry line(s), want exactly 1:%s%s", len(found), string(rune(10)), progress)
	}
	return found[0]
}

// TestFetch_RetriesATransient404ThenSucceeds is the caller-first proof for
// the one deviation from fedora's policy: the 2026-10-17 nightly publish
// died on a 404 from the Photon CDN for one of three fixed, known-good
// URLs, and the file was back the next night. Fetch must ask again rather
// than fail the whole build on the first answer -- that path twice, the
// other two majors once, one progress line naming what happened.
func TestFetch_RetriesATransient404ThenSucceeds(t *testing.T) {
	defer fetchBackoffForTest()()
	srv, calls := scriptedServer(t, retryRows, map[string][]int{"4.0": {http.StatusNotFound}})
	defer srv.Close()

	advisories, progress, err := runFetchProgress(t, context.Background(), srv, threeMajors)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 3 {
		t.Fatalf("Fetch emitted %d advisories, want 3 (every major read)", len(advisories))
	}
	if got := calls("4.0"); got != 2 {
		t.Errorf("the 4.0 path saw %d request(s), want 2 (a 404 then the retry)", got)
	}
	for _, v := range []string{"3.0", "5.0"} {
		if got := calls(v); got != 1 {
			t.Errorf("the %s path saw %d request(s), want 1 -- only the failing major is retried", v, got)
		}
	}
	line := retryLine(t, progress)
	for _, want := range []string{"cve_data_photon4.0.json", "404", "attempt 2 of 3"} {
		if !strings.Contains(line, want) {
			t.Errorf("retry line %q does not name %q", line, want)
		}
	}
}

// TestFetch_RetriesA503ThenSucceeds is the fedora-shaped half: a 5xx is the
// server saying "not this time", and the same loop that absorbs the 404
// absorbs it.
func TestFetch_RetriesA503ThenSucceeds(t *testing.T) {
	defer fetchBackoffForTest()()
	srv, calls := scriptedServer(t, retryRows, map[string][]int{"3.0": {http.StatusServiceUnavailable}})
	defer srv.Close()

	advisories, progress, err := runFetchProgress(t, context.Background(), srv, threeMajors)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 3 {
		t.Fatalf("Fetch emitted %d advisories, want 3", len(advisories))
	}
	if got := calls("3.0"); got != 2 {
		t.Errorf("the 3.0 path saw %d request(s), want 2 (a 503 then the retry)", got)
	}
	for _, v := range []string{"4.0", "5.0"} {
		if got := calls(v); got != 1 {
			t.Errorf("the %s path saw %d request(s), want 1", v, got)
		}
	}
	if line := retryLine(t, progress); !strings.Contains(line, "503") {
		t.Errorf("retry line %q does not name the 503", line)
	}
}

// TestFetch_RetriesAMidBodyTruncationThenSucceeds covers the transport
// clause: a 200 whose body is cut short decodes to io.ErrUnexpectedEOF, and
// that is a retry, not a build failure -- the decode error on an INTACT body
// stays fatal (TestRetryable's syntax-error row).
func TestFetch_RetriesAMidBodyTruncationThenSucceeds(t *testing.T) {
	defer fetchBackoffForTest()()
	srv, calls := scriptedServer(t, retryRows, map[string][]int{"5.0": {statusTruncate}})
	defer srv.Close()

	advisories, _, err := runFetchProgress(t, context.Background(), srv, threeMajors)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advisories) != 3 {
		t.Fatalf("Fetch emitted %d advisories, want 3", len(advisories))
	}
	if got := calls("5.0"); got != 2 {
		t.Errorf("the 5.0 path saw %d request(s), want 2 (a truncation then the retry)", got)
	}
}

// TestFetch_Persistent404FailsAfterThreeAttempts is the bound on the 404
// deviation: a file that is really gone still fails the build, after
// exactly fetchAttempts requests, and the error says so -- the url, the
// status and the attempt count, so a nightly's log reads "the CDN said 404
// three times" rather than "the CDN said 404".
func TestFetch_Persistent404FailsAfterThreeAttempts(t *testing.T) {
	defer fetchBackoffForTest()()
	srv, calls := scriptedServer(t, retryRows, map[string][]int{
		"4.0": {http.StatusNotFound, http.StatusNotFound, http.StatusNotFound, http.StatusNotFound, http.StatusNotFound},
	})
	defer srv.Close()

	_, _, err := runFetchProgress(t, context.Background(), srv, threeMajors)
	if err == nil {
		t.Fatal("Fetch succeeded against a persistent 404; want an error")
	}
	if got := calls("4.0"); got != 3 {
		t.Errorf("the 4.0 path saw %d request(s), want exactly 3", got)
	}
	for _, want := range []string{srv.URL + "/cve_data_photon4.0.json", "404", "after 3 attempts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestFetch_Other4xxFailsOnTheFirstRequest holds the 404 clause to 404: a
// 400 is this code asking for the wrong thing, and asking twice more would
// only delay the same answer.
func TestFetch_Other4xxFailsOnTheFirstRequest(t *testing.T) {
	defer fetchBackoffForTest()()
	srv, calls := scriptedServer(t, retryRows, map[string][]int{
		"5.0": {http.StatusBadRequest, http.StatusBadRequest, http.StatusBadRequest},
	})
	defer srv.Close()

	_, progress, err := runFetchProgress(t, context.Background(), srv, threeMajors)
	if err == nil {
		t.Fatal("Fetch succeeded against a 400; want an error")
	}
	if got := calls("5.0"); got != 1 {
		t.Errorf("the 5.0 path saw %d request(s), want exactly 1 -- a 400 is not retried", got)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error %q does not name the 400", err.Error())
	}
	if strings.Contains(progress, "retrying") {
		t.Errorf("progress announces a retry that must not happen:%s%s", string(rune(10)), progress)
	}
}

// TestFetch_CancelledDuringBackoffReturnsPromptly is the sleepOrDone proof
// at the Fetch boundary: a build cancelled while the loop is waiting out a
// backoff must return the context's error at once, not sit out the pause
// and then make the attempts it was told not to. The cancel is fired from
// inside the backoff function itself -- the one point the loop consults
// strictly between "the attempt failed" and "wait" -- so the cancellation
// lands in the backoff and nowhere else, and a loop that stopped consulting
// fetchBackoff would never see the cancel at all and go on to request the
// file twice more.
func TestFetch_CancelledDuringBackoffReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orig := fetchBackoff
	fetchBackoff = func(int) time.Duration {
		cancel()
		return 10 * time.Second
	}
	defer func() { fetchBackoff = orig }()

	srv, calls := scriptedServer(t, retryRows, map[string][]int{
		"3.0": {http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable},
	})
	defer srv.Close()

	start := time.Now()
	_, progress, err := runFetchProgress(t, ctx, srv, threeMajors)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch error = %v, want one wrapping context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Fetch took %v to notice the cancel; it must return during the backoff, not after it", elapsed)
	}
	if got := calls("3.0"); got != 1 {
		t.Errorf("the 3.0 path saw %d request(s), want exactly 1 -- nothing is requested after the cancel", got)
	}
	// The request count alone cannot tell "stopped in the backoff" from
	// "ignored the backoff's cancel and let http.Client refuse the cancelled
	// context": both make one request. What differs is that the second
	// announces a retry it then does not make, so the progress stream is
	// the assertion that holds the sleepOrDone error check in place.
	if strings.Contains(progress, "retrying") {
		t.Errorf("progress announces a retry after the cancel; a cancelled build must stop in the backoff, not past it:%s%s",
			string(rune(10)), progress)
	}
	for _, v := range []string{"4.0", "5.0"} {
		if got := calls(v); got != 0 {
			t.Errorf("the %s path saw %d request(s), want 0 -- the build stops at the cancelled major", v, got)
		}
	}
}

// TestRetryable pins the policy retry.go's own doc comment describes:
// fedora's 429/5xx-plus-transport set with 404 added, cancellation checked
// before anything else.
func TestRetryable(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		want   bool
	}{
		{"429", nil, http.StatusTooManyRequests, true},
		{"500", nil, http.StatusInternalServerError, true},
		{"503", nil, http.StatusServiceUnavailable, true},
		// The deviation from fedora: three fixed, known-good URLs, and a
		// 404 from the CDN front observed transient once (2026-10-17).
		{"404", nil, http.StatusNotFound, true},

		{"403", nil, http.StatusForbidden, false},
		{"400", nil, http.StatusBadRequest, false},
		{"410", nil, http.StatusGone, false},
		{"200", nil, http.StatusOK, false},

		// A bare network failure with no status is NOT retried, the same
		// narrowness fedora keeps; the two transport failures below are.
		{"network failure with no status", errors.New("connection refused"), 0, false},
		{"truncated body with a 200", io.ErrUnexpectedEOF, http.StatusOK, true},
		// An EMPTY 200 body decodes to io.EOF, not ErrUnexpectedEOF: the server
		// completed a response with nothing in it, which is the feed's shape
		// changing rather than a cut transfer, so it fails the build at once.
		// Pinned so the choice reads as deliberate.
		{"empty 200 body", io.EOF, http.StatusOK, false},
		{"connection reset mid-body", syscall.ECONNRESET, http.StatusOK, true},
		{"wrapped connection reset", fmt.Errorf("decode feed: %w", syscall.ECONNRESET), http.StatusOK, true},
		// The feed's shape changed: a finding, not a blip.
		{"intact body that is not the expected JSON", &json.SyntaxError{}, http.StatusOK, false},
		{"no error at all", nil, 0, false},

		// Cancellation outranks everything, checked before the status.
		{"context cancelled", context.Canceled, 0, false},
		{"deadline exceeded", context.DeadlineExceeded, 0, false},
		// Alongside a status, and alongside a transport error, that would
		// otherwise retry -- proving the check really does run first.
		{"cancelled with a 503 status", context.Canceled, http.StatusServiceUnavailable, false},
		{"cancelled with a 404 status", context.Canceled, http.StatusNotFound, false},
		{"deadline wrapped with a reset", fmt.Errorf("%w: %w", context.DeadlineExceeded, syscall.ECONNRESET), http.StatusOK, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryable(tt.err, tt.status); got != tt.want {
				t.Errorf("retryable(%v, %d) = %v, want %v", tt.err, tt.status, got, tt.want)
			}
		})
	}
}

// TestFetchBackoff pins the shape and scale, identical to fedora's own
// TestPageBackoff: short on purpose, because this exists for a CDN front
// answering wrongly a moment ago, not a service under sustained load.
func TestFetchBackoff(t *testing.T) {
	for _, tt := range []struct {
		attempt int
		want    time.Duration
	}{
		{1, 500 * time.Millisecond},
		{2, time.Second},
	} {
		if got := fetchBackoff(tt.attempt); got != tt.want {
			t.Errorf("fetchBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
	var total time.Duration
	for i := 1; i < fetchAttempts; i++ {
		total += fetchBackoff(i)
	}
	if total > 2*time.Second {
		t.Errorf("a fully failing file waits %v before giving up; that is a hang, not a loud failure", total)
	}
}

// TestSleepOrDone_ReturnsEarlyOnCancellation mirrors fedora's own copy.
func TestSleepOrDone_ReturnsEarlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepOrDone(ctx, 10*time.Second); err == nil {
		t.Error("sleepOrDone returned nil for a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepOrDone waited %v on a cancelled context; it must return at once", elapsed)
	}
}

// TestSleepOrDone_WaitsWhenNotCancelled is the other half: a sleep that
// never sleeps would make the backoff decorative.
func TestSleepOrDone_WaitsWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if err := sleepOrDone(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("sleepOrDone: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("sleepOrDone returned after %v, want it to have waited ~50ms", elapsed)
	}
}
