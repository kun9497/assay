package redhat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// archiveAttempts is how many times the archive download is tried before the
// build fails. One more than the delta's (D58) because the cost of giving up
// differs: a delta document that will not come down loses one advisory, and
// the archive losing means no publish at all that day.
const archiveAttempts = 4

// archiveBackoff is the pause before each retry. Longer than the delta's
// because a reset on a 261 MB transfer is usually the far end shedding load,
// not a momentary blip, and hammering it immediately is what made it shed.
var archiveBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}

// spool downloads url to a temporary file and returns it, positioned at the
// start. The caller closes and removes it.
//
// Downloading before parsing rather than streaming through is the whole point.
// The archive was previously read as a live stream while every record it
// produced was being written to bbolt, so a transfer that takes two minutes
// held its connection open for over ten — and on 2026-08-13 the far end reset
// it eight minutes in, at 1h3m into a build, costing the entire day's publish.
// Spooling first closes the connection as soon as the bytes are down; the
// 17.1 GB decompression still streams, now off local disk where nothing can
// reset it.
//
// A reset is resumed rather than restarted: the server supports Range, so an
// interruption at 200 MB costs the remaining 61 MB and not the whole transfer.
func (p *Provider) spool(ctx context.Context, url, name string) (*os.File, error) {
	f, err := os.CreateTemp("", "assay-redhat-*.tar.zst")
	if err != nil {
		return nil, fmt.Errorf("redhat: spool %s: %w", name, err)
	}
	// Any return other than the happy one leaves nothing behind. A 261 MB file
	// per failed attempt would fill a CI runner within a week of bad nights.
	//
	// ok is a local rather than a named return value being checked for nil.
	// Written that way first, this panicked: `return nil, err` assigns the
	// named result BEFORE the deferred function runs, so the cleanup was
	// dereferencing the nil it had just been handed.
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()

	var (
		have  int64      // bytes on disk so far
		total int64 = -1 // the whole archive's length, -1 until the server says
		last  error
	)

	for attempt := 1; attempt <= archiveAttempts; attempt++ {
		if attempt > 1 {
			if err := sleepOrDone(ctx, archiveBackoff[min(attempt-2, len(archiveBackoff)-1)]); err != nil {
				return nil, err
			}
			p.retried.Add(1)
		}

		onDisk, size, rerr := p.download(ctx, url, f, have)
		have = onDisk
		if size > 0 {
			total = size
		}

		if rerr == nil && (total < 0 || have >= total) {
			if attempt > 1 {
				p.rescued.Add(1)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("redhat: rewind %s: %w", name, err)
			}
			ok = true
			return f, nil
		}

		// A clean end that is SHORT of the promised length counts as a failure
		// even with a nil error. zstd and tar both stop at a truncation without
		// complaining, so accepting one here would publish an artifact missing
		// however many advisories were in the tail, with nothing saying so.
		//
		// It retries without consulting retryable(), which classifies TRANSPORT
		// errors and has no opinion on one this loop synthesized. A transfer
		// that stopped early is the definition of the transient case, and
		// routing it through retryable() made every short read terminal - which
		// is how this was first written, and the resumed download then gave up
		// on the second attempt.
		if rerr == nil {
			last = fmt.Errorf("short read: %d of %d bytes", have, total)
			continue
		}
		last = rerr
		if !retryable(rerr, 0) {
			break
		}
	}

	return nil, fmt.Errorf("redhat: read %s: %d attempts: %w", name, archiveAttempts, last)
}

// download runs one request and returns how many bytes are on disk afterwards
// and how long the WHOLE archive is (0 when the server did not say). from is
// what is already on disk, sent as a Range so an interrupted transfer resumes
// rather than starting over.
//
// It returns the absolute size on disk rather than what this call added,
// because the two differ in the case that is easiest to get wrong: a server
// that ignores Range answers 200 with the whole file, the partial download is
// discarded, and a caller adding a delta would count the restarted bytes twice.
func (p *Provider) download(ctx context.Context, url string, f *os.File, from int64) (int64, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return from, 0, err
	}
	if from > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", from))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return from, 0, fmt.Errorf("redhat: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	var whole int64
	switch resp.StatusCode {
	case http.StatusOK:
		// Range ignored, or the first attempt. Either way this body is the
		// whole file, so anything already on disk is discarded rather than
		// having a second copy appended to it - which would corrupt the
		// archive in a way zstd reports as a checksum error minutes later and
		// nowhere near the cause.
		if from > 0 {
			if err := f.Truncate(0); err != nil {
				return 0, 0, err
			}
			from = 0
		}
		whole = resp.ContentLength
	case http.StatusPartialContent:
		// Resumed as asked: ContentLength describes the REMAINDER, so the
		// whole is that plus what is already down.
		//
		// Mutating this to `whole = resp.ContentLength` survives the suite, and
		// that is a true equivalence rather than a gap: net/http enforces
		// Content-Length on the client side, so a 206 that declares one either
		// delivers it in full (and the file is complete however `whole` was
		// computed) or errors before this loop can judge it. The arithmetic is
		// still written correctly because the completion check is the only
		// thing standing between a truncated archive and a published database,
		// and it should not depend on a property of another package to be safe.
		if resp.ContentLength > 0 {
			whole = from + resp.ContentLength
		}
	default:
		return from, 0, fmt.Errorf("redhat: fetch %s: %s", url, resp.Status)
	}

	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return from, whole, err
	}
	n, err := io.Copy(f, resp.Body)
	return from + n, whole, err
}
