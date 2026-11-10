package main

import (
	"bytes"
	"strings"
	"testing"
)

// The 2026-11-10 amzn FNs: an ALAS finding names its CVE in neither id nor
// aliases nor upstream. Both joins hold it -- advisory.related (schema 20)
// and, for a document from before it, the ratings' advisory ids -- and a
// finding that names the CVE in neither is still a miss.
func TestRun_ALASFindingJoinsItsCVE(t *testing.T) {
	const purl = "pkg:rpm/amzn/openssl-libs@3.2.2-1.amzn2023.0.1?arch=x86_64&distro=amzn-2023&epoch=1"
	labels := []Label{label("amzn-openssl-libs-below", "amzn", purl, "openssl-libs", "3.2.2-1.amzn2023.0.1", "CVE-2025-9230", "affected", "1:3.2.2-1.amzn2023.0.2")}
	for _, tc := range []struct {
		name    string
		finding fakeFinding
		code    int
		want    string
	}{
		{"related (schema 20)", fakeFinding{name: "openssl-libs", id: "ALAS2023-2025-1225", related: []string{"CVE-2025-9231", "CVE-2025-9230"}, fixed: "1:3.2.2-1.amzn2023.0.2", fixState: "fixed"}, exitOK, "amzn    1       1   0   0   0"},
		{"ratings only (before schema 20)", fakeFinding{name: "openssl-libs", id: "ALAS2023-2025-1225", ratingIDs: []string{"ALAS2023-2025-1225", "CVE-2025-9230"}, fixed: "1:3.2.2-1.amzn2023.0.2", fixState: "fixed"}, exitOK, "amzn    1       1   0   0   0"},
		{"neither", fakeFinding{name: "openssl-libs", id: "ALAS2023-2025-1225", ratingIDs: []string{"ALAS2023-2025-1225"}, fixed: "1:3.2.2-1.amzn2023.0.2", fixState: "fixed"}, exitFindings, "FN          amzn-openssl-libs-below/CVE-2025-9230"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec, _ := fakeAssay(t, map[string]fakeScan{purl: {findings: []fakeFinding{tc.finding}}})
			var out, errOut bytes.Buffer
			if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay"}, &out, &errOut, exec); code != tc.code {
				t.Fatalf("exit = %d, want %d\n%s", code, tc.code, out.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("stdout lacks %q:\n%s", tc.want, out.String())
			}
		})
	}
}
