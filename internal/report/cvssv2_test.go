package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// D156: a band from NVD's CVSS v2 fallback says so in every place a reader
// sees the rating -- the JSON's ratings[] (schema 15) and --explain's
// per-source breakdown (D10). A rating banded by v3 says nothing.
func v2Result() matcher.Result {
	return matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "zlib-fixture", Version: "1.2.8", Ecosystem: "Debian:12"},
		Advisory: advisory.Advisory{ID: "DSA-V2-0001"},
		Severity: severity.High, Score: 7.5,
		Ratings: []matcher.Rating{
			{Database: "DEBIAN", AdvisoryID: "DSA-V2-0001", Severity: severity.Unknown},
			{Database: "NVD", AdvisoryID: "CVE-2014-9999", Severity: severity.High, Score: 7.5, FromCVSSv2: true},
		},
		Identifiers: []string{"DSA-V2-0001", "CVE-2014-9999"},
	}}}
}

func TestJSON_D156_ARatingFromCVSSv2SaysSo(t *testing.T) {
	var buf bytes.Buffer
	if _, err := JSON(&buf, v2Result(), cyclonedx.Stats{}, nil, EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Findings      []struct {
			Ratings []map[string]any `json:"ratings"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion < 15 {
		t.Errorf("schemaVersion = %d, want 15 or later: ratings gained cvssV2", doc.SchemaVersion)
	}
	got := map[string]any{}
	for _, r := range doc.Findings[0].Ratings {
		got[r["database"].(string)] = r["cvssV2"]
	}
	if got["NVD"] != true {
		t.Errorf("NVD rating cvssV2 = %v, want true", got["NVD"])
	}
	if v, present := got["DEBIAN"]; present && v != nil {
		t.Errorf("DEBIAN rating carries cvssV2 = %v; a rating not banded by v2 omits it", v)
	}
}

func TestExplain_D156_ARatingFromCVSSv2SaysSo(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Explain(&buf, v2Result(), "DSA-V2-0001"); err != nil {
		t.Fatal(err)
	}
	var nvd, debian string
	for _, line := range strings.Split(buf.String(), "\n") {
		switch {
		case strings.Contains(line, "CVE-2014-9999"):
			nvd = line
		case strings.HasPrefix(strings.TrimSpace(line), "DEBIAN"):
			debian = line
		}
	}
	if !strings.Contains(nvd, "(CVSS v2)") {
		t.Errorf("NVD rating line = %q, want it marked (CVSS v2)", nvd)
	}
	if strings.Contains(debian, "CVSS v2") {
		t.Errorf("DEBIAN rating line = %q, marked though not banded by v2", debian)
	}
}
