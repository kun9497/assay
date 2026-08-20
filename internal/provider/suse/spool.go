package suse

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// archiveAttempts is how many times the archive download is tried before the
// build fails. Matches redhat.archiveAttempts: one more than the delta's
// (D58) because the cost of giving up differs -- a delta document that will
// not come down loses one advisory, and the archive losing means no publish
// at all that day.
const archiveAttempts = 4

// archiveBackoff is the pause before each retry, identical to
// redhat.archiveBackoff: longer than the delta's because a reset on a
// several-hundred-MB transfer is usually the far end shedding load, not a
// momentary blip.
var archiveBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}

// spool downloads url to a temporary file and returns it, positioned at the
// start. The caller closes and removes it.
//
// This is D64 applied to SUSE's archive the same way redhat.spool applies it
// to Red Hat's: the archive is 445 MB compressed (measured 2026-08-20,
// larger than Red Hat's 262 MB), so downloading before parsing is what keeps
// the connection open for minutes rather than for however long the 11+ GB
// decompressed corpus takes to parse and write.
//
// A reset is resumed rather than restarted: the server supports Range
// (verified live, Accept-Ranges: bytes on the archive response), so an
// interruption at 200 MB costs the remaining bytes and not the whole
// transfer.
func (p *Provider) spool(ctx context.Context, url string) (*os.File, error) {
	f, err := os.CreateTemp("", "assay-suse-*.tar.bz2")
	if err != nil {
		return nil, fmt.Errorf("suse: spool %s: %w", archiveName, err)
	}
	// Any return other than the happy one leaves nothing behind, matching
	// redhat.spool's identical cleanup discipline (and its identical
	// named-return hazard: ok is a local, not a named return value checked
	// for nil, for the reason that comment records).
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
				return nil, fmt.Errorf("suse: rewind %s: %w", archiveName, err)
			}
			ok = true
			return f, nil
		}

		// A clean end SHORT of the promised length counts as a failure even
		// with a nil error, matching redhat.spool's identical reasoning:
		// bzip2 and tar both stop at a truncation without complaining.
		if rerr == nil {
			last = fmt.Errorf("short read: %d of %d bytes", have, total)
			continue
		}
		last = rerr
		if !retryable(rerr, 0) {
			break
		}
	}

	return nil, fmt.Errorf("suse: read %s: %d attempts: %w", archiveName, archiveAttempts, last)
}

// download runs one request and returns how many bytes are on disk
// afterwards and how long the WHOLE archive is (0 when the server did not
// say). from is what is already on disk, sent as a Range so an interrupted
// transfer resumes rather than starting over. Identical logic to
// redhat.download; see that function's doc comment for why the absolute
// size is returned rather than the delta this call added.
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
		return from, 0, fmt.Errorf("suse: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	var whole int64
	switch resp.StatusCode {
	case http.StatusOK:
		// Range ignored, or the first attempt: this body is the whole file,
		// so anything already on disk is discarded rather than appended to.
		if from > 0 {
			if err := f.Truncate(0); err != nil {
				return 0, 0, err
			}
			from = 0
		}
		whole = resp.ContentLength
	case http.StatusPartialContent:
		// Resumed as asked: ContentLength describes the REMAINDER.
		if resp.ContentLength > 0 {
			whole = from + resp.ContentLength
		}
	default:
		return from, 0, fmt.Errorf("suse: fetch %s: %s", url, resp.Status)
	}

	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return from, whole, err
	}
	n, err := io.Copy(f, resp.Body)
	return from + n, whole, err
}
