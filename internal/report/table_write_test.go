package report

import (
	"errors"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// failAfter accepts n writes and refuses every later one, so the branch under
// test can be chosen by WHERE the stream breaks: at the first byte, or only
// once the headline is out and the summary line is being written.
type failAfter struct {
	n   int
	err error
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, f.err
	}
	f.n--
	return len(p), nil
}

// TestTable_ReturnsTheWriteError is the renderer-level half of
// scancmd.TestRun_TableWriteFailureIsExitTwo (written first; this one covers
// the branches the caller cannot pick). Each headline branch writes with
// fmt.Fprint*, which drops the writer's error, so every one of them used to
// return nil over a report that never arrived. A failure on a LATER write --
// the summary line after a headline that succeeded -- is held too, because a
// check on the headline alone would pass it.
func TestTable_ReturnsTheWriteError(t *testing.T) {
	pkg := pkgmeta.Package{Name: "clean", Version: "1.0.0", Ecosystem: "Go"}
	cases := []struct {
		name string
		res  matcher.Result
		cat  cyclonedx.Stats
		cov  Coverage
	}{
		{"empty document", matcher.Result{}, cyclonedx.Stats{}, Coverage{}},
		{"clean scan", matcher.Result{}, cyclonedx.Stats{Components: 1, Cataloged: 1},
			Coverage{Keys: []CoverageRecord{{Ecosystem: "Go", Packages: 1, Evaluated: 1, State: "live"}}}},
		{"nothing evaluated", matcher.Result{Skipped: []matcher.Skipped{{Package: pkg, Reason: "unparseable"}}},
			cyclonedx.Stats{Components: 1, Cataloged: 1}, Coverage{}},
		{"all waived", matcher.Result{Suppressed: []matcher.Suppressed{{
			Finding: matcher.Finding{Package: pkg, Severity: severity.High},
			Reason:  "accepted", Source: "ignore-file"}}},
			cyclonedx.Stats{Components: 1, Cataloged: 1}, Coverage{}},
	}
	for _, tc := range cases {
		for _, after := range []int{0, 1} {
			t.Run(tc.name, func(t *testing.T) {
				w := &failAfter{n: after, err: errors.New("write /dev/stdout: broken pipe")}
				sum, err := Table(w, tc.res, tc.cat, nil, EOLStatus{}, tc.cov, false)
				if err == nil || err.Error() != "write /dev/stdout: broken pipe" {
					t.Fatalf("Table with a stream that fails after %d write(s): err = %v, want the write error", after, err)
				}
				if sum != (Summary{}) {
					t.Errorf("Table returned a summary %+v beside the write error; want Summary{}", sum)
				}
			})
		}
	}
}
