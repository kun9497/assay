package oracle

import (
	"context"
	"fmt"
	"io"
	"os"
)

// spool downloads url to a temporary file and returns it, positioned at the
// start. The caller closes and removes it.
//
// This is D64's decision applied to a much smaller archive: redhat.spool
// exists because a 261 MB transfer held a connection open for over ten
// minutes while every record it produced was written to bbolt, and the far
// end reset it partway through. Oracle's archive is 12 MB (measured
// 2026-08-19) -- a download that size does not need Range-resume retry
// machinery to be safe, but it still needs to be OFF the wire before
// anything decompresses or parses it, so the same shape (GET, copy to disk,
// close the response, hand back a rewound file) is used here without
// redhat.spool's resume/backoff loop, which exists for a failure mode this
// archive's size does not create.
func (p *Provider) spool(ctx context.Context, url string) (*os.File, error) {
	f, err := os.CreateTemp("", "assay-oracle-*.xml.bz2")
	if err != nil {
		return nil, fmt.Errorf("oracle: spool %s: %w", url, err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()

	body, err := p.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if _, err := io.Copy(f, body); err != nil {
		return nil, fmt.Errorf("oracle: download %s: %w", url, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("oracle: rewind spool of %s: %w", url, err)
	}
	ok = true
	return f, nil
}
