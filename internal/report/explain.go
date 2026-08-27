package report

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/kun9497/assay/internal/matcher"
)

// Explain writes a human-readable account of every finding in res whose
// advisory is identified by id — its own ID, or one of the aliases/upstream
// identifiers it carries (D3) — to w. This is D10 made visible: which range
// matched, which comparer decided it, what the comparison actually
// returned, and which name reached the advisory (D8), the fields Evidence
// and MatchedName exist on Finding to carry rather than leaving to a log
// line.
//
// Matching against BOTH aliases and upstream, exactly like otherIDs (the
// table's own ALIASES column), because which field carries a CVE depends on
// the ecosystem (D3): the Go dump files it under aliases, the Alpine dump
// under upstream. A reader who greps the table for an identifier must be
// able to hand that same identifier to --explain and get the finding back,
// regardless of which field it happened to live in.
//
// It returns the number of findings written, not just an error, so the
// caller can tell "id matched nothing" apart from "matched and had nothing
// to say" — the two would otherwise be indistinguishable from an empty w.
// Zero writes nothing at all to w: a partial or empty-but-successful report
// for a typo'd identifier would be a quiet wrong answer, the opposite of
// what explain mode exists for.
func Explain(w io.Writer, res matcher.Result, id string) (int, error) {
	n := 0
	for _, f := range res.Findings {
		if !identifiesFinding(f, id) {
			continue
		}
		if err := explainOne(w, f); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// identifiesFinding reports whether id names f: the displayed advisory's own
// ID, or any identifier any record that joined this finding answered to. It reuses otherIDs — the exact set the
// table's ALIASES column shows — rather than re-deriving which fields count
// as identifiers a second time, and compares with ==, never Contains: real
// identifiers nest (ALPINE-CVE-2025-46394 contains CVE-2025-46394), so a
// substring match here would explain the wrong advisory on a false-positive
// hit.
//
// A table marker is trimmed off first (trimCellMarker), because the table's
// own footnote tells the reader to hand this the cell that carries one.
func identifiesFinding(f matcher.Finding, id string) bool {
	id = trimCellMarker(id)
	if f.Advisory.ID == id {
		return true
	}
	for _, other := range otherIDs(f) {
		if other == id {
			return true
		}
	}
	return false
}

// trimCellMarker removes a table marker a reader copied along with the cell it
// annotates — "GHSA-1 +" becomes "GHSA-1".
//
// This is not lenient input handling; it closes a loop the report opens itself.
// The table appends enrichmentMarker INSIDE the ADVISORY cell (table.go), and
// the footnote beneath it says "see --explain <id>". The ADVISORY cell is
// literally --explain's input, so a reader who follows that instruction by
// copying the cell was answered with `no finding matches advisory or alias
// "GHSA-1 +"` and exit 2 — the report's own instruction failing on the report's
// own output.
//
// Safe because the marker must be preceded by a SPACE and advisory identifiers
// contain none: CVE-2024-12345, GHSA-w24h-v9qh-8gxj, ALPINE-CVE-2025-46394,
// PYSEC-2022-191, GO-2022-0999. Nothing that could be a real identifier ends in
// " +" or " *", so this cannot swallow one — and an id that ends in a marker
// with no space ("CVE-2024-1+") is left exactly as typed. The comparison after
// it is still ==, never Contains.
//
// One marker, not a loop: the two markers live in different columns on purpose
// (table.go's enrichmentMarker doc comment), so no cell carries both, and a
// loop here would be a branch nothing can reach. disagreementMarker is trimmed
// as well even though it sits in SEVERITY — the argument for handling it costs
// one line and removes the question of what happens if a marker ever moves.
func trimCellMarker(id string) string {
	id = strings.TrimRight(id, " ")
	for _, marker := range []string{enrichmentMarker, disagreementMarker} {
		if cut, ok := strings.CutSuffix(id, " "+marker); ok {
			return strings.TrimRight(cut, " ")
		}
	}
	return id
}

// explainOne writes one finding's account: the package and how it was
// named, the advisory and its other identifiers, the severity, and the full
// version.Evidence — which comparer, which range, and the comparison's own
// Reason string.
func explainOne(w io.Writer, f matcher.Finding) error {
	lines := []string{
		fmt.Sprintf("package:  %s %s [%s]", f.Package.Name, f.Package.Version, f.Package.Ecosystem),
	}
	switch {
	case f.MatchedName == "" || f.MatchedName == f.Package.Name:
		lines = append(lines, fmt.Sprintf("matched:  %s (direct match)", f.Package.Name))
	case f.MatchedViaProvides:
		// D95: an apk provides join, NOT a D8 source-package one -- both
		// leave MatchedName != Package.Name, and printing the D8 wording
		// here would claim the installed package's own apk origin is the
		// name that matched, which BellSoft's Liberica JDK packages
		// disprove (their own origin is themselves; the join is through a
		// sibling package's `p:` clause instead).
		lines = append(lines, fmt.Sprintf(
			"matched:  %s (apk provides, D95 — declared by installed package %s)",
			f.MatchedName, f.Package.Name))
	default:
		// D8: the advisory names the source package, not the installed one.
		// Spelled out in words as well as names, because a reader who only
		// sees two names side by side has no way to tell which one is the
		// indirection this line exists to explain.
		lines = append(lines, fmt.Sprintf(
			"matched:  %s (source package, D8 — installed package is %s)",
			f.MatchedName, f.Package.Name))
	}
	lines = append(lines, fmt.Sprintf("advisory: %s", f.Advisory.ID))
	if ids := otherIDs(f); len(ids) > 0 {
		lines = append(lines, fmt.Sprintf("also known as: %s", strings.Join(ids, ", ")))
	}
	if f.Advisory.Summary != "" {
		lines = append(lines, fmt.Sprintf("summary:  %s", f.Advisory.Summary))
	}
	// Explain is the "why" view (D10), so unlike the table's single SEVERITY
	// cell it shows every source in full, not just the one that set the
	// band — agreeing or not.
	//
	// The base line is unconditional; the source count and the per-source
	// breakdown are purely additive on top of it. Deliberately NOT an
	// if/else between "has Ratings" and "does not": Match always populates
	// at least one Rating (D25), so a Finding with none reaches this
	// function only by direct construction — several older fixtures in this
	// package still do that, for reasons unrelated to D25 (D8 indirection,
	// alias matching, and so on). An if/else here would give those fixtures
	// their own dedicated rendering branch that nothing built by Match could
	// ever reach, which is not a real code path worth maintaining as one.
	// Structuring it as one line plus a loop means the zero-Ratings case is
	// just that same loop running zero times, not a different branch.
	sevLine := fmt.Sprintf("severity: %s", formatSeverity(f.Severity, f.Score))
	if n := len(f.Ratings); n > 0 {
		source := "source"
		if n != 1 {
			source = "sources"
		}
		sevLine += fmt.Sprintf("   [highest of %d %s]", n, source)
	}
	lines = append(lines, sevLine)
	for _, r := range f.Ratings {
		// D86: an EPSS/KEV row carries no severity opinion at all
		// (matcher.Rating.NoSeverityOpinion's own doc comment) and must never
		// render as a ratingLine pretending to be a severity source --
		// ratingLine's fixed SEVERITY column would print "unknown" beside a
		// database that never claimed a band, reading as a fourth source
		// that looked at this CVE and shrugged rather than what it actually
		// is: a different kind of opinion entirely. Rendered separately,
		// below, after every real severity source.
		if isExploitSignal(r) {
			continue
		}
		lines = append(lines, ratingLine(r))
	}
	lines = append(lines, epssKevLines(f.Ratings)...)
	lines = append(lines, fmt.Sprintf("comparer: %s", comparerName(f.Package.Ecosystem)))

	ev := f.Evidence
	lines = append(lines, fmt.Sprintf(
		"range:    type=%s introduced=%q fixed=%q lastAffected=%q",
		ev.RangeType, ev.Introduced, ev.Fixed, ev.LastAffected))
	reason := ev.Reason
	if reason == "" {
		reason = "matched an enumerated affected version, not a range"
	}
	lines = append(lines, fmt.Sprintf("result:   %s", reason))
	lines = append(lines, enrichmentLines(f.Enrichment)...)

	_, err := fmt.Fprintln(w, strings.Join(lines, "\n")+"\n")
	return err
}

// enrichmentLines renders what another authority wrote about this
// vulnerability in prose (D3): who wrote it, the headline, the overview, and
// where to read the rest.
//
// This is where the feature actually pays off. The table can only carry a
// marker — Korean is double-width in a fixed-width terminal, so a title in a
// cell misaligns every column after it — so --explain is the only renderer
// that shows the text at all, and it shows all of it rather than a truncation.
//
// It stays strictly below "result:" and adds nothing to the lines above,
// because everything above is the account of why this package matched and
// enrichment is not evidence of anything (D3). A reader who stops before this
// block has read the whole match.
//
// Nothing here carries a severity, and none is derived from what KISA's own
// grading says (D17): the finding's band is above, set by sources that scored
// it, and a second band-shaped statement here would be read as one.
//
// Empty title, summary or link lines are dropped rather than printed blank.
// The source is always named when there is anything to attribute, so a record
// that arrived with only a link still says who is speaking — an unattributed
// URL in a vulnerability report is worse than none.
func enrichmentLines(es []matcher.Enrichment) []string {
	var lines []string
	for _, e := range es {
		lines = append(lines, fmt.Sprintf("enrichment: %s", e.Source))
		for _, f := range []struct{ label, value string }{
			{"title", e.Title},
			{"summary", e.Summary},
			{"link", e.URL},
		} {
			if f.value == "" {
				continue
			}
			// A fixed label width, for ratingLine's own reason: this is a
			// handful of lines under one finding, not a table whose rows must
			// line up with a header printed once for the document, so a fixed
			// width keeps each block independently predictable. 9 clears
			// "summary:", the longest of the three labels.
			lines = append(lines, fmt.Sprintf("  %-9s %s", f.label+":", f.value))
		}
		// D33: how much else the notice was about. A source's narrowest notice
		// for a CVE still may not be about that CVE — 70% of KISA's records
		// come from notices naming more than twenty, and where a roundup is the
		// only notice naming a CVE it is what a reader gets. Saying so is the
		// difference between prose about this vulnerability and a monthly
		// bulletin that happened to list it; without the count they render
		// identically. Printed only above one, because "covers 1 vulnerability"
		// is what the reader already assumed.
		if e.Claims > 1 {
			lines = append(lines, fmt.Sprintf("  %-9s this notice covers %d vulnerabilities, not only this one",
				"scope:", e.Claims))
		}
	}
	return lines
}

// ratingLine formats one source's assessment of a finding for the full
// breakdown printed under "severity:" — the detail the table's marker only
// points at.
//
// Column widths are fixed rather than computed from the ratings actually
// present: this is a handful of lines under one finding, not a table whose
// rows must line up with a header printed once for the whole document
// (table.go's own tabwriter), so a fixed width keeps each finding's
// breakdown independently predictable rather than shifting with whichever
// other findings happen to be explained alongside it. 6 fits every database
// name measured so far ("ALPINE" is the longest); 24 clears real advisory
// IDs including Alpine's own "ALPINE-CVE-2025-46394"; 16 clears the longest
// formatSeverity output, "critical (10.0)".
//
// The URL, when present, is appended after the fixed-width columns rather
// than given one of its own: an OSV rating leaves it empty (matcher.Rating's
// own doc comment — the advisory ID already names something to look up), so
// a fixed-width URL column would print blank space on most lines for a value
// that exists at all only for an annotation (D27). An annotation carries no
// Evidence, no matched range and no fixed version (D25 narrowed by D27) — no
// advisory of its own to check — so without this, the breakdown states what
// NIST scored a CVE and gives a reader nowhere to verify it, against goal #1.
func ratingLine(r matcher.Rating) string {
	fixed := r.Fixed
	if fixed == "" {
		fixed = "-"
	}
	line := fmt.Sprintf("  %-6s %-24s %-16s fixed %s",
		r.Database, r.AdvisoryID, formatSeverity(r.Severity, r.Score), fixed)
	if r.URL != "" {
		line += "  " + r.URL
	}
	return line
}

// isExploitSignal reports whether r is one of D86's EPSS/KEV rows rather
// than a severity source.
//
// A signal check, not an identity check on r.Database: EPSSModel is set on
// every EPSS row and on no other source's rating (advisory.Rating's own
// comment — the typed fields are additive and copied verbatim, never routed
// through Severity), and KEV is a plain bool no other source ever sets. This
// mirrors the check matcher.Finding.MaxEPSS/KnownExploited themselves use,
// rather than hardcoding the string "EPSS"/"KEV" a second time in this
// package.
func isExploitSignal(r matcher.Rating) bool {
	return r.EPSSModel != "" || r.KEV
}

// epssKevLines renders D86's exploit-likelihood/known-exploitation rows as
// short labeled lines, on enrichmentLines' own precedent (that function's own
// doc comment): this is a different kind of information than a severity
// source's rating, so it earns its own shape rather than being squeezed into
// ratingLine's fixed columns, which is exactly why isExploitSignal excludes
// these rows from the loop that precedes this block.
//
// One finding can carry both a separate EPSS rating and a separate KEV
// rating (the store keys each source under its own "<CVE>\x00<Source>" —
// two rows, not one with both sets of fields), so this checks each field
// independently per row rather than assuming they are mutually exclusive.
func epssKevLines(rs []matcher.Rating) []string {
	var lines []string
	for _, r := range rs {
		// r.Database already names the source ("EPSS"/"KEV") via the %-6s
		// column, so the label after it says what the row means rather than
		// repeating the name a second time.
		if r.EPSSModel != "" {
			lines = append(lines, fmt.Sprintf(
				"  %-6s probability %.5f, percentile %.5f, model %s",
				r.Database, r.EPSS, r.EPSSPercentile, r.EPSSModel))
		}
		if r.KEV {
			lines = append(lines, fmt.Sprintf(
				"  %-6s added %s, ransomware use: %s",
				r.Database, r.KEVDateAdded, r.KEVRansomware))
		}
	}
	return lines
}

// mainlineUbuntuName mirrors version.For's own Ubuntu pattern, anchored for
// the same reason: the Pro and FIPS lineages resolve no comparer (D53), and
// a prefix here would have --explain name one for a package the matcher
// refused to evaluate. The drift guard caught exactly that on the first
// attempt at this function.
var mainlineUbuntuName = regexp.MustCompile(`^Ubuntu:[0-9]{2}\.[0-9]{2}(:LTS)?$`)

// comparerName names the version.Comparer that version.For would select
// for ecosystem, without exporting version's own unexported registry just
// for this display purpose. It mirrors version.For's dispatch exactly —
// Alpine:vX.Y -> apk, Debian:N and Ubuntu:NN.NN -> deb, Red Hat:N -> rpm,
// Go/npm -> semver,
// PyPI -> pep440 — and
// TestComparerName_AgreesWithVersionFor cross-checks the two directly, so a
// future ecosystem added to one and not the other fails loudly here rather
// than explain mode quietly naming the wrong comparer (D9: comparison rules
// are genuinely per-ecosystem, and getting the name wrong is exactly the
// kind of quiet error D9 exists to prevent).
func comparerName(ecosystem string) string {
	if rel, ok := strings.CutPrefix(ecosystem, "Alpine:"); ok && rel != "" {
		return "apk"
	}
	if rel, ok := strings.CutPrefix(ecosystem, "Debian:"); ok && rel != "" {
		return "deb"
	}
	// Ubuntu is dpkg too (D53). Added in the same commit that taught
	// version.For about it, because this mirror going stale is not
	// hypothetical: it had already been wrong for Debian and Red Hat for two
	// slices, and the drift guard below missed Ubuntu on the very next one
	// for the same reason — a hardcoded list cannot cover a family nobody
	// remembered to add to it.
	if mainlineUbuntuName.MatchString(ecosystem) {
		return "deb"
	}
	if rel, ok := strings.CutPrefix(ecosystem, "Red Hat:"); ok && rel != "" {
		return "rpm"
	}
	// Rocky is RPM too (D71), added in the same commit that taught
	// version.For about it for the reason the comment above this function
	// gives.
	if rel, ok := strings.CutPrefix(ecosystem, "Rocky Linux:"); ok && rel != "" {
		return "rpm"
	}
	// AlmaLinux is RPM too (D72), added in the same commit that taught
	// version.For about it, for the same reason.
	if rel, ok := strings.CutPrefix(ecosystem, "AlmaLinux:"); ok && rel != "" {
		return "rpm"
	}
	// Amazon Linux is RPM too (D73), added in the same commit that taught
	// version.For about it, for the same reason.
	if rel, ok := strings.CutPrefix(ecosystem, "Amazon Linux:"); ok && rel != "" {
		return "rpm"
	}
	// Oracle Linux is RPM too (D74), added in the same commit that taught
	// version.For about it, for the same reason.
	if rel, ok := strings.CutPrefix(ecosystem, "Oracle Linux:"); ok && rel != "" {
		return "rpm"
	}
	// Fedora is RPM too (D75), added in the same commit that taught
	// version.For about it, for the same reason.
	if rel, ok := strings.CutPrefix(ecosystem, "Fedora:"); ok && rel != "" {
		return "rpm"
	}
	// SLES and openSUSE Leap are RPM too (D77), added in the same commit that
	// taught version.For about them, for the same reason.
	if rel, ok := strings.CutPrefix(ecosystem, "SLES:"); ok && rel != "" {
		return "rpm"
	}
	if rel, ok := strings.CutPrefix(ecosystem, "openSUSE Leap:"); ok && rel != "" {
		return "rpm"
	}
	// Azure Linux is RPM too (D94), added in the same commit that taught
	// version.For about it, for the same reason -- this is the exact drift
	// D92's review found and this function's own doc comment warns about.
	if rel, ok := strings.CutPrefix(ecosystem, "Azure Linux:"); ok && rel != "" {
		return "rpm"
	}
	// Alpaquita and BellSoft Hardened Containers are apk too (D95), added in
	// the same commit that taught version.For about them, for the same
	// reason -- both have a genuine release axis (measured 2026-08-26: 0
	// bare-key occurrences on either family), so this is a prefix rule like
	// Rocky/AlmaLinux/Azure Linux's above, not a plain-name case like
	// Wolfi/Chainguard/MinimOS below.
	if rel, ok := strings.CutPrefix(ecosystem, "Alpaquita:"); ok && rel != "" {
		return "apk"
	}
	if rel, ok := strings.CutPrefix(ecosystem, "BellSoft Hardened Containers:"); ok && rel != "" {
		return "apk"
	}
	// Photon OS is RPM too (D96), added in the same commit that taught
	// version.For about it, for the same reason.
	if rel, ok := strings.CutPrefix(ecosystem, "Photon OS:"); ok && rel != "" {
		return "rpm"
	}
	switch ecosystem {
	// crates.io joins here in the same commit that taught version.For about
	// it, which is the rule the comment above was written for.
	case "Go", "npm", "crates.io":
		return "semver"
	case "PyPI":
		return "pep440"
	// RubyGems, Packagist, NuGet and Maven each get their own case rather than
	// folding into the semver one above: they are NOT semver (Gem, Composer,
	// NuGet and Maven are each their own Comparer, D9), and collapsing them
	// into "semver" would have this function agree with version.For on
	// PRESENCE while naming the wrong comparer — the exact drift
	// TestComparerName_ExactNamePerEcosystem was written to catch for PyPI.
	case "RubyGems":
		return "gem"
	case "Packagist":
		return "composer"
	case "NuGet":
		return "nuget"
	case "Maven":
		return "maven"
	// The release-less distro keys (D88 Wolfi/Chainguard, D92 MinimOS —
	// apk; D92 Echo — deb). Wolfi and Chainguard shipped in D88 WITHOUT
	// these cases, so --explain printed "comparer: unknown" for two
	// ecosystems version.For orders perfectly well — the drift this
	// function's own doc comment warns about, caught by D92's review.
	case "Wolfi", "Chainguard", "MinimOS":
		return "apk"
	case "Echo":
		return "deb"
	// D97: "Arch:rolling" is the literal sentinel version.For's registry
	// carries too, not a prefix — see that map's own comment.
	case "Arch:rolling":
		return "pacman"
	// D98: "Hummingbird" is a bare, release-less RPM registry entry too,
	// added in the same commit that taught version.For about it, for the
	// same reason every case above this comment's own doc warns about.
	case "Hummingbird":
		return "rpm"
	// D99: "Bitnami" is a bare, release-less registry entry too -- not a
	// distro at all, but named here for the same drift reason as every case
	// above: version.For carries a real Comparer (Bitnami{}) for it, and
	// this function must say so rather than fall through to "unknown".
	case "Bitnami":
		return "bitnami"
	default:
		return "unknown"
	}
}
