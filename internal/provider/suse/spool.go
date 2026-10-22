package suse

import (
	"context"
	"errors"
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
//
// The returned time is the archive's Last-Modified as the GET reported it
// (D12, D135): the delta cutoff and the provenance both describe the bytes
// on disk, not a pre-flight HEAD's generation of the file. A resumed
// transfer whose response names a different Last-Modified is a file
// regenerated under the download; its partial bytes are discarded and the
// transfer restarts, because bzip2 would otherwise fail minutes later on a
// splice of two generations, or worse, not fail.
func (p *Provider) spool(ctx context.Context, url string) (*os.File, time.Time, error) {
	f, err := os.CreateTemp("", "assay-suse-*.tar.bz2")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("suse: spool %s: %w", archiveName, err)
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
		have     int64          // bytes on disk so far
		total    int64     = -1 // the whole archive's length, -1 until the server says
		modified time.Time      // the generation on disk, from the first response
		last     error
	)

	for attempt := 1; attempt <= archiveAttempts; attempt++ {
		if attempt > 1 {
			if err := sleepOrDone(ctx, archiveBackoff[min(attempt-2, len(archiveBackoff)-1)]); err != nil {
				return nil, time.Time{}, err
			}
			p.retried.Add(1)
		}

		onDisk, size, lm, rerr := p.download(ctx, url, f, have, modified)
		have = onDisk
		if size > 0 {
			total = size
		}
		if !lm.IsZero() {
			modified = lm
		}

		if rerr == nil && (total < 0 || have >= total) {
			if attempt > 1 {
				p.rescued.Add(1)
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil, time.Time{}, fmt.Errorf("suse: rewind %s: %w", archiveName, err)
			}
			ok = true
			return f, modified, nil
		}

		// A clean end SHORT of the promised length counts as a failure even
		// with a nil error, matching redhat.spool's identical reasoning:
		// bzip2 and tar both stop at a truncation without complaining.
		if rerr == nil {
			last = fmt.Errorf("short read: %d of %d bytes", have, total)
			continue
		}
		last = rerr
		// A generation change is retried from the start without consulting
		// retryable(), which classifies transport errors: the transfer is
		// fine, the file under it is not the one it began with.
		if errors.Is(rerr, errArchiveRegenerated) {
			have, total, modified = 0, -1, time.Time{}
			continue
		}
		if !retryable(rerr, 0) {
			break
		}
	}

	return nil, time.Time{}, fmt.Errorf("suse: read %s: %d attempts: %w", archiveName, archiveAttempts, last)
}

// errArchiveRegenerated is a resumed response naming a different
// Last-Modified than the bytes already on disk: the server rebuilt the
// archive mid-transfer (D135).
var errArchiveRegenerated = errors.New("archive regenerated during the download")

// download runs one request and returns how many bytes are on disk
// afterwards, how long the WHOLE archive is (0 when the server did not say),
// and the Last-Modified the response carried. from is what is already on
// disk, sent as a Range so an interrupted transfer resumes rather than
// starting over; sameAs is the generation those bytes belong to, and a
// resumed response that names another one is refused with
// errArchiveRegenerated after the partial file is truncated. Identical logic
// to redhat.download otherwise; see that function's doc comment for why the
// absolute size is returned rather than the delta this call added.
func (p *Provider) download(ctx context.Context, url string, f *os.File, from int64, sameAs time.Time) (int64, int64, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return from, 0, time.Time{}, err
	}
	if from > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", from))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return from, 0, time.Time{}, fmt.Errorf("suse: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	var whole int64
	switch resp.StatusCode {
	case http.StatusOK:
		// Range ignored, or the first attempt: this body is the whole file,
		// so anything already on disk is discarded rather than appended to.
		if from > 0 {
			if err := f.Truncate(0); err != nil {
				return 0, 0, time.Time{}, err
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
		return from, 0, time.Time{}, fmt.Errorf("suse: fetch %s: %s", url, resp.Status)
	}
	modified, err := lastModifiedOf(resp, url)
	if err != nil {
		if resp.StatusCode != http.StatusPartialContent || sameAs.IsZero() {
			// The whole-file response is the one statement of the
			// bytes' age (D12) and must carry it.
			return from, whole, time.Time{}, err
		}
		// A resumed response without the header: RFC 9110 only SHOULD-
		// requires it on a 206, and the generation was already recorded
		// from the 200 this transfer began with. Read as the same
		// generation rather than failing a download whose age is known
		// (D135's review); a server that does send it is still compared.
		modified = sameAs
	}
	if from > 0 && !sameAs.IsZero() && !modified.Equal(sameAs) {
		if err := f.Truncate(0); err != nil {
			return 0, 0, modified, err
		}
		return 0, 0, modified, fmt.Errorf("suse: fetch %s: %w (%s on disk, %s served)",
			url, errArchiveRegenerated, sameAs.Format(time.RFC3339), modified.Format(time.RFC3339))
	}

	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return from, whole, modified, err
	}
	n, err := io.Copy(f, resp.Body)
	return from + n, whole, modified, err
}
