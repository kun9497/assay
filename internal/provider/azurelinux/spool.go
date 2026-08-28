package azurelinux

import (
	"context"
	"fmt"
	"io"
	"os"
)

// spool downloads url to a temporary file and returns it, positioned at the
// start. The caller closes and removes it.
//
// D64 applied to a plain (uncompressed) XML file rather than Oracle's
// bzip2 archive (oracle.spool's own comment has the full reasoning): the
// point is not the file's size, it is getting the HTTP response body OFF
// the wire and the connection closed before anything downstream starts
// parsing it, so a slow or interrupted parse never holds the connection
// open the whole time.
func (p *Provider) spool(ctx context.Context, url string) (*os.File, error) {
	f, err := os.CreateTemp("", "assay-azurelinux-*.xml")
	if err != nil {
		return nil, fmt.Errorf("azurelinux: spool %s: %w", url, err)
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
		return nil, fmt.Errorf("azurelinux: download %s: %w", url, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("azurelinux: rewind spool of %s: %w", url, err)
	}
	ok = true
	return f, nil
}
