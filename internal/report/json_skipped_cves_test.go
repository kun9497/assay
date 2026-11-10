package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Schema 21: skipped[].cves renders, and is omitted when empty.
func TestJSON_SkippedCarriesCVEs(t *testing.T) {
	res := matcher.Result{Skipped: []matcher.Skipped{
		{Package: pkgmeta.Package{Name: "x", Version: "1", Ecosystem: "Go"}, AdvisoryID: "ALAS2031-0001", CVEs: []string{"CVE-2031-0001"}, Reason: "r", Cause: matcher.SkipAdvisory},
		{Package: pkgmeta.Package{Name: "y", Version: "1", Ecosystem: "Go"}, AdvisoryID: "GHSA-noid", Reason: "r", Cause: matcher.SkipAdvisory},
	}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2}, nil, EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"cves": [`) || !strings.Contains(out, `"CVE-2031-0001"`) {
		t.Errorf("skipped[].cves missing:\n%s", out)
	}
	if strings.Count(out, `"cves"`) != 1 {
		t.Errorf("a skip naming no CVE must omit cves:\n%s", out)
	}
}
