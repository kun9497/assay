package source

import (
	"fmt"
	"io"
)

// D112's two size bounds. Variables, not constants, so a test can lower them
// and prove the bound without a half-gigabyte fixture — the carryNow pattern
// (internal/dbcmd/carry.go). Nothing outside a test assigns either one: a
// number that moved per deployment would be a number nobody could reason
// about in a bug report (D112, "What stays out").

// MaxFileBytes is the most decompressed bytes a scan reads out of any one
// file. 512 MiB is the cap the jar cataloger has lived with since D61 — and
// since D112's 2026-10-07 revision it reads this variable, for a jar archive
// and for each entry in it — and the largest legitimate reads this path makes —
// an rpm Berkeley DB Packages file on a big enterprise image, a full Ubuntu's
// dpkg status, a large image's SBOM — sit an order of magnitude below it.
//
// scancmd reads an SBOM target through this same variable, so one number
// bounds every file a scan reads, whichever package opened it.
var MaxFileBytes int64 = 512 << 20

// MaxScanBytes is the most bytes one scan collects across every file and
// every layer pass. Four maximal files; the weekly differential's 23 targets
// stay inside a fraction of it.
var MaxScanBytes int64 = 2 << 30

// FileLimitError is the error for a file past MaxFileBytes. It names the path
// and the limit because those are the two things a reader needs to act — the
// fix for a legitimate over-limit file is to raise the number with the
// measurement that justifies it (D112), and that starts from knowing which
// file and which number. Exported so scancmd's SBOM read says the same thing
// in the same words as an image's.
func FileLimitError(path string) error {
	return fmt.Errorf("%s exceeds the %s per-file limit (D112)", path, formatBytes(MaxFileBytes))
}

// readEntry copies one wanted tar entry out under both of D112's size bounds.
// Every read site in this package goes through it — the four io.ReadAll calls
// it replaced had no bound of any kind between them.
//
// The LimitReader is what bounds memory; the length check only names the
// result. Reading limit+1 bytes is how an entry of exactly the limit is told
// apart from a longer one without reading the longer one to its end.
//
// An over-limit entry is an error, never a truncated file: for the package
// databases this path reads, a partial file is a smaller inventory presented
// as complete, which is worse than no answer (D112, D43).
func (img *Image) readEntry(path string, r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxFileBytes {
		return nil, FileLimitError(path)
	}
	img.read += int64(len(b))
	if img.read > MaxScanBytes {
		return nil, fmt.Errorf("image reads exceeded the %s per-scan limit (D112) at %s",
			formatBytes(MaxScanBytes), path)
	}
	return b, nil
}

// formatBytes renders a limit the way a person would write it, so the error
// reads "512 MiB" rather than "536870912". A lowered test limit that is not a
// whole number of KiB falls through to bytes rather than being rounded into a
// number it is not.
func formatBytes(n int64) string {
	switch {
	case n > 0 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n > 0 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n > 0 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}
