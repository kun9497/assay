package osv

import (
	"testing"

	"github.com/kun9497/assay/internal/severity"
)

// QA 2026-11-20. Severity published anywhere but the record's top level was
// dropped: Bitnami's (on each affected entry) and a GHSA record's word.
func TestConvert_ReadsSeverityWhereTheRecordStatesIt(t *testing.T) {
	const (
		crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		low  = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
	)
	aff := func(name, sev string) string {
		return `{"package":{"name":"` + name + `","ecosystem":"Bitnami"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]` + sev + `}`
	}
	sev := func(v string) string { return `,"severity":[{"type":"CVSS_V3","score":"` + v + `"}]` }
	npm := `{"package":{"name":"x","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`
	for _, tc := range []struct {
		name, eco, rec string
		n              int
		want           severity.Band
	}{
		{"affected only", "Bitnami", `{"id":"BIT-a","affected":[` + aff("a", sev(crit)) + `]}`, 1, severity.Critical},
		{"affected, two ratings, one repeated", "Bitnami", `{"id":"BIT-a","affected":[` + aff("a", sev(low)) + `,` + aff("b", sev(crit)) + `,` + aff("c", sev(crit)) + `]}`, 2, severity.Critical},
		{"the record's own wins", "Bitnami", `{"id":"BIT-a","severity":[{"type":"CVSS_V3","score":"` + low + `"}],"affected":[` + aff("a", sev(crit)) + `]}`, 1, severity.Low},
		{"GHSA critical", "npm", `{"id":"GHSA-a","database_specific":{"severity":"CRITICAL"},"affected":[` + npm + `]}`, 1, severity.Critical},
		{"GHSA high", "npm", `{"id":"GHSA-a","database_specific":{"severity":"HIGH"},"affected":[` + npm + `]}`, 1, severity.High},
		{"GHSA moderate", "npm", `{"id":"GHSA-a","database_specific":{"severity":"MODERATE"},"affected":[` + npm + `]}`, 1, severity.Medium},
		{"GHSA low", "npm", `{"id":"GHSA-a","database_specific":{"severity":"LOW"},"affected":[` + npm + `]}`, 1, severity.Low},
		{"a vector beats the word", "npm", `{"id":"GHSA-a","severity":[{"type":"CVSS_V3","score":"` + low + `"}],"database_specific":{"severity":"CRITICAL"},"affected":[` + npm + `]}`, 1, severity.Low},
		{"another database's word is not read", "npm", `{"id":"PYSEC-a","database_specific":{"severity":"CRITICAL"},"affected":[` + npm + `]}`, 0, severity.Unknown},
		{"database_specific of another shape", "npm", `{"id":"GHSA-a","database_specific":{"severity":[1]},"affected":[` + npm + `]}`, 0, severity.Unknown},
	} {
		var st stats
		got, ok, err := convert([]byte(tc.rec), tc.eco, &st, nil)
		if err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", tc.name, ok, err)
			continue
		}
		var vs []string
		for _, s := range got.Severity {
			vs = append(vs, s.Score)
		}
		if band, _ := severity.Highest(vs); len(vs) != tc.n || band != tc.want {
			t.Errorf("%s: stored %q banding %v, want %d entries banding %v", tc.name, vs, band, tc.n, tc.want)
		}
	}
}
