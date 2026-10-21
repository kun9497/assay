package suse

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

// changesFile lists every published document with the time it last changed.
// Lives under "csaf-vex/", one level below the bulk archive (DefaultBaseURL
// points at the level above both).
const changesFile = "changes.csv"

// maxDelta bounds how many documents a delta pass will fetch one at a time,
// matching redhat.maxDelta's reasoning: exceeding it means the feed has
// stopped being rebuilt rather than merely lagging.
const maxDelta = 20000

// deltaRequestTimeout bounds ONE document fetch, matching redhat's.
const deltaRequestTimeout = 3 * time.Minute

// changesPath is the shape a row in changes.csv may have. Its contents become
// a URL ("csaf-vex/<row>"), so it is validated for the same reason
// redhat.changesPath is: a misrouted response, or a feed that started listing
// absolute URLs, must not turn into a request somewhere else.
//
// D122: year-prefixed since 2026-10-15, the same shape as Red Hat's. Until
// then SUSE listed bare "cve-YYYY-NNNNN.json" (verified live 2026-08-20); on
// 2026-10-15 index.txt, changes.csv and the tree all moved under year
// directories, the flat URLs began to 404, and the first nightly to see a row
// newer than its archive failed on this check. The directory is not the
// CVE's year ("2023/cve-2004-2541.json" is live), which is why the path is
// taken from the row rather than rebuilt from the ID. The flat form is NOT
// still accepted: its URLs 404, and document() reads a 404 as "withdrawn
// between the two files", so a flat row would be counted gone and the delta
// would look complete while having fetched nothing.
var changesPath = regexp.MustCompile(`^[0-9]{4}/cve-[0-9]{4}-[0-9]+\.json$`)

// deltaSince fetches every document that changed on or after the archive's
// own Last-Modified, emits what they convert to, and returns the CVE ids of
// the documents it actually fetched, so the archive walk that follows can
// skip its older copies (D129). Mirrors redhat.deltaSince's shape (fetch the
// list, bound it, fetch concurrently in order) with one real difference:
// changedSince below reads changes.csv start to finish rather than exiting
// early, because this feed's sort order is not one it has kept (D122).
//
// Run BEFORE the archive walk since D129. It used to run after, relying on
// last-write-wins by ID to let the newer document replace the archive's --
// which has nothing to win with when the newer document converts to nothing
// (a finding SUSE corrected to known_not_affected): the archive's stale
// record stood until the archive was regenerated, about a day (2026-10-20
// external review, #5). Only a FETCHED document supersedes; one listed and
// gone (DeltaGone) keeps its archive copy, so a transient 404 never drops a
// live advisory.
func (p *Provider) deltaSince(ctx context.Context, cutoff time.Time,
	emit func(advisory.Advisory) error, st *stats, covered map[string]bool) (map[string]bool, error) {

	paths, err := p.changedSince(ctx, cutoff)
	if err != nil {
		return nil, err
	}
	st.DeltaListed = len(paths)
	if len(paths) > maxDelta {
		return nil, fmt.Errorf(
			"suse: %d documents have changed since the %s archive was built, past the %d this "+
				"will fetch one at a time; the feed has stopped being rebuilt rather than merely "+
				"lagging", len(paths), cutoff.Format("2006-01-02"), maxDelta)
	}

	fetched := map[string]bool{}
	err = p.eachDocument(ctx, paths, func(rel string, d *document) error {
		if d == nil {
			// Listed and no longer served -- changes.csv and the individual
			// document being generated at slightly different times is a race,
			// not a fault, matching redhat.deltaSince's identical read.
			st.DeltaGone++
			return nil
		}
		st.DeltaFetched++
		// By the document's own id, never by file name. The first cut keyed
		// on the base name, and its review showed that inverts the failure
		// direction: any spelling drift between a changes.csv row and the
		// archive entry (a case change, a directory) would make the walk
		// emit the archive's stale copy AFTER the delta's, where the old
		// order had let the delta win by ID regardless. The id is what
		// convert keys the record on, so the skip and the record agree by
		// construction.
		if id := cveOf(d); id != "" {
			fetched[id] = true
		}
		adv, ok := convert(d, st)
		if !ok {
			return nil
		}
		for _, a := range adv.Affected {
			covered[a.Ecosystem] = true
		}
		if err := emit(adv); err != nil {
			return err
		}
		st.DeltaAdvisories++
		return nil
	})
	return fetched, err
}

// deltaWorkers is how many documents are fetched at once, matching
// redhat.deltaWorkers's reasoning: the requests are latency-bound, and eight
// is enough to make the pass fast without being rude to a service that is
// giving the data away for free.
const deltaWorkers = 8

// eachDocument fetches paths concurrently and hands them to fn IN ORDER.
// Identical to redhat.eachDocument -- see that function's doc comment for
// why the ordering and the consumer-released semaphore both matter.
func (p *Provider) eachDocument(ctx context.Context, paths []string,
	fn func(rel string, d *document) error) error {

	type result struct {
		doc *document
		err error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, deltaWorkers)
	slots := make([]chan result, len(paths))
	for i := range slots {
		slots[i] = make(chan result, 1)
	}
	go func() {
		for i, rel := range paths {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			go func(i int, rel string) {
				d, err := p.document(ctx, rel)
				slots[i] <- result{d, err}
			}(i, rel)
		}
	}()

	for i, rel := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		var r result
		select {
		case r = <-slots[i]:
		case <-ctx.Done():
			return ctx.Err()
		}
		<-sem
		if r.err != nil {
			return r.err
		}
		if err := fn(rel, r.doc); err != nil {
			return err
		}
	}
	return nil
}

// changedSince reads changes.csv and returns the paths modified on or after
// cutoff.
//
// Read start to finish rather than stopped early the way redhat.changedSince
// stops at the first old row. SUSE has sorted this file both ways: OLDEST
// FIRST when it was verified live on 2026-08-20, NEWEST FIRST since the
// 2026-10-15 layout change (D122). An early exit is only safe on a sort
// order the feed promises, and this one has already changed once without
// notice; under the old order it would have returned NOTHING, since the very
// first row was from 2023. At ~71,600 rows and a few megabytes, a full scan
// costs nothing an early exit would have saved -- a COST difference from
// redhat.changedSince, not a correctness one, the same distinction that
// function's own doc comment draws about its early exit.
func (p *Provider) changedSince(ctx context.Context, cutoff time.Time) ([]string, error) {
	body, err := p.get(ctx, p.baseURL+"/csaf-vex/"+changesFile)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	r := csv.NewReader(body)
	r.FieldsPerRecord = 2
	r.ReuseRecord = true

	var (
		out  []string
		rows int
	)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("suse: read %s: %w", changesFile, err)
		}
		rows++
		when, err := time.Parse(time.RFC3339, rec[1])
		if err != nil {
			return nil, fmt.Errorf("suse: %s row %d has an unreadable timestamp %q: %w",
				changesFile, rows, rec[1], err)
		}
		if when.Before(cutoff) {
			continue
		}
		if !changesPath.MatchString(rec[0]) {
			return nil, fmt.Errorf(
				"suse: %s row %d names %q, which is not a document path", changesFile, rows, rec[0])
		}
		// rec is reused by the reader, so the string has to be copied out.
		out = append(out, string([]byte(rec[0])))
	}
	return out, nil
}

// document fetches one CSAF document, retrying a transient failure (D58),
// mirroring redhat.document exactly. Only a 404 yields nil; everything else
// fails the build, because this pass exists to close a known gap and a delta
// that quietly closed only part of it would look complete while being
// somewhere in between.
func (p *Provider) document(ctx context.Context, rel string) (*document, error) {
	var lastErr error
	for attempt := 1; attempt <= deltaAttempts; attempt++ {
		if attempt > 1 {
			if err := sleepOrDone(ctx, deltaBackoff(attempt-1)); err != nil {
				return nil, err
			}
			p.retried.Add(1)
		}
		d, status, err := p.documentOnce(ctx, rel)
		if err == nil {
			if attempt > 1 {
				p.rescued.Add(1)
			}
			return d, nil
		}
		lastErr = err
		if !retryable(err, status) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("suse: %d attempts: %w", deltaAttempts, lastErr)
}

// documentOnce is one attempt, mirroring redhat.documentOnce exactly.
func (p *Provider) documentOnce(ctx context.Context, rel string) (*document, int, error) {
	ctx, cancel := context.WithTimeout(ctx, deltaRequestTimeout)
	defer cancel()

	url := p.baseURL + "/csaf-vex/" + rel
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("suse: fetch %s: %w", url, err)
	}
	// Drained, not just closed -- matches redhat.documentOnce's identical
	// reasoning: json.Decode stops at the end of the value, and an
	// undrained trailing byte costs the connection.
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("suse: fetch %s: %s", url, resp.Status)
	}
	var d document
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocument)).Decode(&d); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("suse: parse %s: %w", url, err)
	}
	return &d, resp.StatusCode, nil
}
