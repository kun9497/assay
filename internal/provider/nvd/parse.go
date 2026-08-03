// Package nvd converts NVD's CVE 2.0 API into advisory.Rating: an opinion
// about what a CVE is worth, independent of which package is affected. That
// is why it enters through provider.Annotator rather than provider.Provider
// (D27) - NVD never says a package is affected, only how bad the CVE is.
package nvd

import (
	"github.com/kun9497/assay/internal/advisory"
)

// SourceName identifies ratings this provider supplied.
const SourceName = "NVD"

// rawVulnerability is one entry in an NVD API 2.0 page's "vulnerabilities"
// array.
type rawVulnerability struct {
	CVE rawCVE `json:"cve"`
}

type rawCVE struct {
	ID      string     `json:"id"`
	Metrics rawMetrics `json:"metrics"`
}

// rawMetrics mirrors the CVSS versions NVD carries side by side on one
// record: v2, v3.0, v3.1 and v4.0 all appear in the live feed. All four are
// read, not just cvssMetricV31 - dropping any one bakes today's scorer into
// the database, since severity.Highest (D13) picks among whichever versions
// are present at query time.
type rawMetrics struct {
	CvssMetricV2  []rawCvssMetric `json:"cvssMetricV2"`
	CvssMetricV30 []rawCvssMetric `json:"cvssMetricV30"`
	CvssMetricV31 []rawCvssMetric `json:"cvssMetricV31"`
	CvssMetricV40 []rawCvssMetric `json:"cvssMetricV40"`
}

type rawCvssMetric struct {
	CvssData rawCvssData `json:"cvssData"`
}

type rawCvssData struct {
	VectorString string `json:"vectorString"`
}

// convert turns one NVD vulnerability entry into a Rating. ok is false when
// the record carries no CVSS metric at all.
//
// That is a deliberate skip, not an oversight. severity.Highest(nil) already
// derives an empty Severity as "unknown", so the band would come out right
// either way - the reason to skip it is different. A Rating with no Severity
// would still name NVD as a source wherever ratings are listed (RatingsFor's
// result, --explain's per-source breakdown), so the report would show NVD as
// having weighed in on every CVE it fetched, including the ones it has no
// opinion about at all. That is noise in the one view built to explain a
// verdict.
func convert(v rawVulnerability) (advisory.Rating, bool) {
	var sev []advisory.Severity
	for _, m := range v.CVE.Metrics.CvssMetricV2 {
		if m.CvssData.VectorString != "" {
			sev = append(sev, advisory.Severity{Type: "CVSS_V2", Score: m.CvssData.VectorString})
		}
	}
	for _, m := range v.CVE.Metrics.CvssMetricV30 {
		if m.CvssData.VectorString != "" {
			sev = append(sev, advisory.Severity{Type: "CVSS_V30", Score: m.CvssData.VectorString})
		}
	}
	for _, m := range v.CVE.Metrics.CvssMetricV31 {
		if m.CvssData.VectorString != "" {
			sev = append(sev, advisory.Severity{Type: "CVSS_V31", Score: m.CvssData.VectorString})
		}
	}
	for _, m := range v.CVE.Metrics.CvssMetricV40 {
		if m.CvssData.VectorString != "" {
			sev = append(sev, advisory.Severity{Type: "CVSS_V40", Score: m.CvssData.VectorString})
		}
	}
	if len(sev) == 0 {
		return advisory.Rating{}, false
	}
	return advisory.Rating{
		CVE:      v.CVE.ID,
		Source:   SourceName,
		Severity: sev,
		URL:      "https://nvd.nist.gov/vuln/detail/" + v.CVE.ID,
	}, true
}
