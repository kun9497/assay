package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// Schema 20: an ALAS / Bodhi / OVAL finding names its CVEs only in Related,
// and the JSON carries them, so a consumer can join the finding to a CVE
// without reading the ratings. A record without Related omits the field.
func TestJSON_AdvisoryCarriesRelated(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:     pkgmeta.Package{Name: "openssl-libs", Version: "1:3.2.2-1.amzn2023.0.1", Ecosystem: "Amazon Linux:2023"},
			Advisory:    advisory.Advisory{ID: "ALAS2023-2025-1225", Related: []string{"CVE-2025-9230", "CVE-2025-9231"}},
			MatchedName: "openssl-libs",
			Severity:    severity.Medium,
			Ratings:     []matcher.Rating{{Database: "ALAS2023", AdvisoryID: "ALAS2023-2025-1225", Severity: severity.Medium}},
		},
		{
			Package:     pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
			Advisory:    advisory.Advisory{ID: "GHSA-plain", Aliases: []string{"CVE-2025-0001"}},
			MatchedName: "p",
			Severity:    severity.Low,
			Ratings:     []matcher.Rating{{Database: "GHSA", AdvisoryID: "GHSA-plain", Severity: severity.Low}},
		},
	}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2}, nil, EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Advisory map[string]any `json:"advisory"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, f := range doc.Findings {
		byID[f.Advisory["id"].(string)] = f.Advisory
	}
	rel, ok := byID["ALAS2023-2025-1225"]["related"].([]any)
	if !ok || len(rel) != 2 || rel[0] != "CVE-2025-9230" || rel[1] != "CVE-2025-9231" {
		t.Errorf("ALAS advisory.related = %v, want [CVE-2025-9230 CVE-2025-9231]", byID["ALAS2023-2025-1225"]["related"])
	}
	if _, present := byID["GHSA-plain"]["related"]; present {
		t.Errorf("a record with no Related must omit the field: %v", byID["GHSA-plain"])
	}
}
