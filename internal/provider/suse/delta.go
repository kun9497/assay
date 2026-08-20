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

// changesPath is the shape a row in changes.csv may have -- a FLAT filename,
// unlike redhat.changesPath's year-prefixed one. Verified live 2026-08-20:
// SUSE's own index.txt and changes.csv both list bare "cve-YYYY-NNNNN.json"
// with no directory component, and the archive's own tar entries carry a
// "csaf-vex/" prefix that changes.csv's rows do not -- the two are not the
// same string and delta document fetches use changesPath's bare form
// directly against "csaf-vex/<name>".
var changesPath = regexp.MustCompile(`^cve-[0-9]{4}-[0-9]+\.json$`)

// deltaSince fetches every document that changed on or after the archive's
// own Last-Modified, and emits what they convert to. Mirrors
// redhat.deltaSince's shape (fetch the list, bound it, fetch concurrently in
// order, emit AFTER the archive walk so last-write-wins keeps the newer
// document) with one real difference: changedSince below reads changes.csv
// start to finish rather than exiting early, because this feed's file sorts
// the opposite way Red Hat's does.
func (p *Provider) deltaSince(ctx context.Context, cutoff time.Time,
	emit func(advisory.Advisory) error, st *stats, covered map[string]bool) error {

	paths, err := p.changedSince(ctx, cutoff)
	if err != nil {
		return err
	}
	st.DeltaListed = len(paths)
	if len(paths) > maxDelta {
		return fmt.Errorf(
			"suse: %d documents have changed since the %s archive was built, past the %d this "+
				"will fetch one at a time; the feed has stopped being rebuilt rather than merely "+
				"lagging", len(paths), cutoff.Format("2006-01-02"), maxDelta)
	}

	return p.eachDocument(ctx, paths, func(rel string, d *document) error {
		if d == nil {
			// Listed and no longer served -- changes.csv and the individual
			// document being generated at slightly different times is a race,
			// not a fault, matching redhat.deltaSince's identical read.
			st.DeltaGone++
			return nil
		}
		st.DeltaFetched++
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
// stops at the first old row. SUSE's own file is sorted OLDEST FIRST
// (verified live, 2026-08-20 -- the opposite of Red Hat's, which sorts
// newest first and documents the sort-order check that makes its early exit
// safe). An early exit here on the same assumption would return NOTHING:
// the very first row is from 2023, so a naive "stop at the first row older
// than cutoff" would stop immediately. At 63,784 rows and a few megabytes, a
// full scan costs nothing an early exit would have saved -- this is a COST
// difference from redhat.changedSince, not a correctness one, the same
// distinction that function's own doc comment draws about its early exit.
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
