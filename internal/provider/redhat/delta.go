package redhat

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// changesFile lists every published document with the time it last changed,
// newest first.
const changesFile = "changes.csv"

// maxDelta bounds how many documents a delta pass will fetch one at a time.
//
// Measured 2026-08-07 against a 2026-08-05 archive: 1,827 documents had
// changed, so a day of drift is roughly 900. The cap is about three weeks of
// that, and exceeding it means the archive has stopped being rebuilt rather
// than merely lagging — at which point fetching a third of the corpus
// document by document is the wrong answer and saying so is the right one.
const maxDelta = 20000

// deltaRequestTimeout bounds ONE document fetch. The archive read gets the
// client's hour because it is 262 MB; a single document is at most 94 MB and
// usually a few hundred kilobytes, so a request still running after this has
// hung rather than being slow.
const deltaRequestTimeout = 3 * time.Minute

// changesPath is the shape a row in changes.csv may have. Its contents become
// a URL, so it is validated for the same reason archive_latest.txt's is: a
// misrouted response, or a feed that started listing absolute URLs, must not
// turn into a request somewhere else.
var changesPath = regexp.MustCompile(`^[0-9]{4}/cve-[0-9]{4}-[0-9]+\.json$`)

// deltaSince fetches every document that changed on or after the archive's own
// date, and emits what they convert to.
//
// The archive is a snapshot and Red Hat rebuilds it on its own schedule, so a
// database built from it alone is behind by however long that has been. The
// gap is not theoretical: on both differential runs against grype — ubi9 and
// ubi8 — EVERY finding grype had and assay did not came from documents written
// after the archive was built, and nothing else did.
//
// The cutoff is the archive's DATE at midnight UTC rather than the time it was
// built, which nothing publishes. That over-fetches by up to a day of
// documents that are already in the archive, and over-fetching is the harmless
// direction: a re-emitted advisory replaces its own record (Bolt.Put keys on
// the ID) and the index append is idempotent.
//
// Emitted AFTER the archive walk, deliberately. Last write wins, so the newer
// document is the one that survives.
func (p *Provider) deltaSince(ctx context.Context, cutoff time.Time,
	emit func(advisory.Advisory) error, st *stats, covered map[string]bool) error {

	paths, err := p.changedSince(ctx, cutoff)
	if err != nil {
		return err
	}
	st.DeltaListed = len(paths)
	if len(paths) > maxDelta {
		return fmt.Errorf(
			"redhat: %d documents have changed since the %s archive was built, past the %d this "+
				"will fetch one at a time; the archive has stopped being rebuilt rather than "+
				"merely lagging", len(paths), cutoff.Format("2006-01-02"), maxDelta)
	}

	for _, rel := range paths {
		// A TRUE EQUIVALENT, recorded rather than left as a suspicious no-op:
		// deleting it survives the test table, because document() derives its
		// own request context from this one and a cancelled context fails the
		// very next fetch anyway. It stays for two reasons — it matches the
		// archive loop's shape one function over, and it stops BETWEEN
		// documents rather than inside a request, so cancellation surfaces as
		// a context error instead of a transport one.
		if err := ctx.Err(); err != nil {
			return err
		}
		d, err := p.document(ctx, rel)
		if err != nil {
			return err
		}
		if d == nil {
			// The document is listed and no longer served. changes.csv and
			// deletions.csv are written separately, so a document withdrawn
			// between the two being generated is a race rather than a fault —
			// counted, and not a reason to fail a build.
			st.DeltaGone++
			continue
		}
		st.DeltaFetched++
		adv, ok := convert(d, st)
		if !ok {
			continue
		}
		for _, a := range adv.Affected {
			covered[a.Ecosystem] = true
		}
		if err := emit(adv); err != nil {
			return err
		}
		st.DeltaAdvisories++
	}
	return nil
}

// changedSince reads changes.csv and returns the paths modified on or after
// cutoff.
//
// The file is sorted NEWEST FIRST, and the scan stops at the first row older
// than the cutoff instead of reading all 62,989.
//
// That early exit is a COST decision, not a correctness one, and the
// distinction is worth stating because a mutation of it survives the whole
// test table: replacing the break with a continue reads the rest of the file
// and produces exactly the same delta. What makes stopping early SAFE is the
// sort-order check below, which is tested — and the two belong together, since
// a continue would need no such check.
func (p *Provider) changedSince(ctx context.Context, cutoff time.Time) ([]string, error) {
	body, err := p.get(ctx, p.baseURL+"/"+changesFile)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	r := csv.NewReader(body)
	r.FieldsPerRecord = 2
	r.ReuseRecord = true

	var (
		out  []string
		last time.Time
		rows int
	)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("redhat: read %s: %w", changesFile, err)
		}
		rows++
		when, err := time.Parse(time.RFC3339, rec[1])
		if err != nil {
			return nil, fmt.Errorf("redhat: %s row %d has an unreadable timestamp %q: %w",
				changesFile, rows, rec[1], err)
		}
		if rows > 1 && when.After(last) {
			return nil, fmt.Errorf(
				"redhat: %s is not sorted newest first (row %d is %s, after the row before it at "+
					"%s); stopping early on it would silently miss documents",
				changesFile, rows, when.Format(time.RFC3339), last.Format(time.RFC3339))
		}
		last = when
		if when.Before(cutoff) {
			break
		}
		if !changesPath.MatchString(rec[0]) {
			return nil, fmt.Errorf(
				"redhat: %s row %d names %q, which is not a document path", changesFile, rows, rec[0])
		}
		// rec is reused by the reader, so the string has to be copied out.
		out = append(out, string([]byte(rec[0])))
	}
	return out, nil
}

// document fetches one CSAF document, or nil if it is no longer published.
//
// Only a 404 yields nil. Every other failure — a network error, a 5xx, a body
// that will not parse — fails the build, because this pass exists to close a
// known gap and a delta that quietly closed only part of it would be worse
// than not having one: the database would look complete and be somewhere in
// between.
func (p *Provider) document(ctx context.Context, rel string) (*document, error) {
	ctx, cancel := context.WithTimeout(ctx, deltaRequestTimeout)
	defer cancel()

	url := p.baseURL + "/" + rel
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("redhat: fetch %s: %w", url, err)
	}
	// Drained, not just closed. json.Decode stops at the end of the VALUE, so
	// any trailing byte left in the body makes net/http give up on the
	// connection instead of returning it to the pool — and this loop runs
	// 1,827 times against a two-day-old archive. Without the drain every
	// document costs a fresh TCP and TLS handshake and leaves a socket in
	// TIME_WAIT; it showed up first as an unrelated package's tests failing to
	// bind a port during `go test ./...`.
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("redhat: fetch %s: %s", url, resp.Status)
	}
	var d document
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocument)).Decode(&d); err != nil {
		return nil, fmt.Errorf("redhat: parse %s: %w", url, err)
	}
	return &d, nil
}
