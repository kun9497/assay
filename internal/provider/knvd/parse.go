// Package knvd converts KISA's KNVD security notices into advisory
// enrichment records. It is deliberately pure: no HTTP, no store. Fetching
// notices and writing them to the store are separate concerns layered on
// top of convert.
package knvd

import (
	"regexp"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// SourceName identifies KISA as the authoring source on every Enrichment
// this package produces.
const SourceName = "KISA"

// detailURL is a notice's own page, built from its id. The list response
// also carries a `url` field, but that one is an external reference and is
// frequently null -- measured against the live service 2026-08-05 -- so it
// is never what a reader should be sent to.
const detailURL = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id="

// rawNotice is the subset of KNVD's list response convert needs.
// content_html exists on the real response too, but it is not read here:
// content_text is already plain text, and the reference crawler's HTML
// table parsing exists only to build affected/fixed version rules, which
// D3 says enrichment is not.
type rawNotice struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	ContentText string `json:"content_text"`
}

// cveRE finds CVE identifiers in KISA's Korean prose. Matched
// case-insensitively because the corpus is not consistent about casing;
// every match is upper-cased before use since the store key is exact and a
// stray lower-case form must not become a second record for the same CVE.
//
// The task brief's interface section suggested `\d{4,7}` for the sequence
// number, but real CVE IDs have no upper bound on digit count (e.g.
// CVE-2017-1000001) and no lower bound below the convention of 4 -- and the
// brief's own verbatim test fixtures use single-digit sequence numbers like
// "CVE-2026-1". A fixed range rejects both ends, so this matches one or
// more digits instead.
var cveRE = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)

// overviewHeading and nextHeading delimit the summary. KISA marks its
// overview section "□ 개요" and ends it at the next "□ " heading (□ 설명,
// □ 영향, □ 해결, □ 기타, □ 참고, ...); matching on the bullet character
// rather than an enumerated set of headings means an unseen heading still
// ends the section instead of swallowing the rest of the notice.
const overviewHeading = "□ 개요"

var nextHeadingRE = regexp.MustCompile(`□ `)

// fallbackSummaryLimit bounds the fallback summary when a notice has no
// overview heading. Measured in runes, not bytes: this text is Korean, and
// slicing a UTF-8 string by byte offset can land inside a multi-byte
// syllable and emit replacement characters instead of truncating cleanly.
const fallbackSummaryLimit = 300

// convert turns one notice into zero or more enrichment records, one per
// distinct CVE it names. A notice naming no CVE produces nothing: an
// enrichment record is reached only by joining on its CVE, so a record with
// no key could never be read back.
func convert(n rawNotice) []advisory.Enrichment {
	cves := extractCVEs(n.ContentText)
	if len(cves) == 0 {
		return nil
	}

	summary := summarize(n.ContentText)
	url := detailURL + n.ID

	out := make([]advisory.Enrichment, 0, len(cves))
	for _, cve := range cves {
		out = append(out, advisory.Enrichment{
			CVE:     cve,
			Source:  SourceName,
			Title:   n.Title,
			Summary: summary,
			URL:     url,
		})
	}
	return out
}

// extractCVEs returns the distinct CVE IDs named in text, upper-cased and
// sorted so a run is reproducible -- no map iteration order may reach a
// caller.
func extractCVEs(text string) []string {
	seen := map[string]bool{}
	for _, m := range cveRE.FindAllString(text, -1) {
		seen[strings.ToUpper(m)] = true
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for cve := range seen {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

// summarize extracts the overview section (between "□ 개요" and the next
// "□ " heading), whitespace-collapsed. When there is no overview heading,
// it falls back to the whole text, whitespace-collapsed and truncated to a
// sensible display length, so a notice that does not follow the usual
// shape still yields a record that gained something rather than an empty
// field.
func summarize(text string) string {
	start := strings.Index(text, overviewHeading)
	if start < 0 {
		return truncateRunes(collapseWhitespace(text), fallbackSummaryLimit)
	}
	body := text[start+len(overviewHeading):]

	if loc := nextHeadingRE.FindStringIndex(body); loc != nil {
		body = body[:loc[0]]
	}
	return collapseWhitespace(body)
}

var whitespaceRE = regexp.MustCompile(`\s+`)

func collapseWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRE.ReplaceAllString(s, " "))
}

// truncateRunes cuts s to at most n runes. Byte-slicing a Korean string can
// split a multi-byte syllable in half and produce replacement characters;
// converting to []rune first keeps the cut on a character boundary.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
