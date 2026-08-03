package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/version"
)

// explainLine returns the line in out that starts with prefix (e.g.
// "range:"), or fails the test if no such line exists. Explain's output is
// one label-prefixed line per fact, so resolving a line by its own label and
// asserting the WHOLE line — not just a value that might also appear
// elsewhere — pins the label and its value together. This is the fix for
// the exact hazard CLAUDE.md's "substring assertions" note warns about:
// Evidence.Reason routinely restates the same version numbers that also
// belong to the "range:" line, so a bare Contains(out, "1.5.0") check can
// pass entirely from the result: line while the range: line itself is
// missing, empty, or has its fields swapped.
func explainLine(t *testing.T, out, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no line starting with %q in output:\n%s", prefix, out)
	return ""
}

// TestExplain_PrintsTheFindingsEvidence is D10 made visible: which range
// matched, what the comparison actually returned, and which name reached the
// advisory (D8). Every rendered line is asserted exactly, by its own label,
// rather than checked with a loose Contains over the whole output — a bare
// substring check here previously passed even with the "range:" line deleted
// entirely, because Evidence.Reason (built by hand in this fixture, exactly
// as version.describe() would build it from a real match) restates the same
// introduced/fixed values the range: line prints. This fixture's Reason
// deliberately does NOT restate Introduced, Fixed, or Package.Version, so
// each line's own assertion can only be satisfied by that line itself, and a
// swap of the Introduced/Fixed format arguments cannot hide inside a
// Contains match on either value alone.
func TestExplain_PrintsTheFindingsEvidence(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package: pkgmeta.Package{
			Name: "github.com/foo/bar-explain", Version: "v1.2.3-explain-pkgver", Ecosystem: "Go",
		},
		Advisory: advisory.Advisory{ID: "GHSA-explain-hit", Summary: "explain-summary-code-injection"},
		Evidence: version.Evidence{
			RangeType:  advisory.RangeSemver,
			Introduced: "1.0.0-explain-introduced",
			Fixed:      "1.5.0-explain-fixed",
			Reason:     "the installed release falls inside the vulnerable window (explain-reason-text)",
		},
		MatchedName: "github.com/foo/bar-explain",
		Severity:    severity.High,
		Score:       7.5,
	}}}

	var buf bytes.Buffer
	n, err := Explain(&buf, res, "GHSA-explain-hit")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	out := buf.String()

	for _, tt := range []struct{ prefix, want string }{
		{"package:", "package:  github.com/foo/bar-explain v1.2.3-explain-pkgver [Go]"},
		{"matched:", "matched:  github.com/foo/bar-explain (direct match)"},
		{"advisory:", "advisory: GHSA-explain-hit"},
		{"summary:", "summary:  explain-summary-code-injection"},
		{"severity:", "severity: high (7.5)"},
		{"comparer:", "comparer: semver"}, // Go -> SemVer (D9/D10)
		{"range:", `range:    type=SEMVER introduced="1.0.0-explain-introduced" ` +
			`fixed="1.5.0-explain-fixed" lastAffected=""`},
		{"result:", "result:   the installed release falls inside the vulnerable window (explain-reason-text)"},
	} {
		if got := explainLine(t, out, tt.prefix); got != tt.want {
			t.Errorf("line %q = %q, want %q\nfull output:\n%s", tt.prefix, got, tt.want, out)
		}
	}

	// No aliases/upstream on this advisory, so the "also known as:" line
	// must not appear at all.
	if strings.Contains(out, "also known as:") {
		t.Errorf("output has an \"also known as:\" line for an advisory with no aliases/upstream:\n%s", out)
	}
}

// TestExplain_MatchesByAliasOrUpstream: D3 read both aliases and upstream
// when joining on an identifier, because which field carries the CVE
// depends on the ecosystem. A reader who grepped the table's ALIASES column
// for a CVE must be able to hand that same CVE to --explain.
//
// Each subtest also asserts the exact "also known as:" line, not just the
// returned count: a mutation that dropped that whole line (F7) still found
// the finding (the identifier match happens in identifiesAdvisory, a
// different function from the line that prints it) and so left a
// count-only assertion green.
func TestExplain_MatchesByAliasOrUpstream(t *testing.T) {
	t.Run("alias (Go shape)", func(t *testing.T) {
		res := matcher.Result{Findings: []matcher.Finding{{
			Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-alias-carrier", Aliases: []string{"CVE-2024-11111"}},
			Severity: severity.High, Score: 7.5,
		}}}
		var buf bytes.Buffer
		n, err := Explain(&buf, res, "CVE-2024-11111")
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("n = %d, want 1 (lookup by alias must find the finding)", n)
		}
		if got, want := explainLine(t, buf.String(), "also known as:"), "also known as: CVE-2024-11111"; got != want {
			t.Errorf("also known as line = %q, want %q", got, want)
		}
	})

	t.Run("upstream (Alpine shape)", func(t *testing.T) {
		// The advisory ID deliberately does not contain the CVE as a
		// substring (real Alpine IDs like ALPINE-CVE-2025-46394 do, which
		// would let a substring-based lookup pass by accident).
		res := matcher.Result{Findings: []matcher.Finding{{
			Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Alpine:v3.19"},
			Advisory: advisory.Advisory{ID: "ALPINE-2025-0001", Upstream: []string{"CVE-2025-46394"}},
			Severity: severity.High, Score: 7.5,
		}}}
		var buf bytes.Buffer
		n, err := Explain(&buf, res, "CVE-2025-46394")
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("n = %d, want 1 (lookup by upstream must find the finding)", n)
		}
		if got, want := explainLine(t, buf.String(), "also known as:"), "also known as: CVE-2025-46394"; got != want {
			t.Errorf("also known as line = %q, want %q", got, want)
		}
	})
}

// TestExplain_NoMatchWritesNothing: asking to explain an identifier nothing
// matched must not print a partial or empty-but-successful report. The
// caller (scancmd.Run) turns n == 0 into an error naming the identifier
// rather than a silent, empty stdout — a typo must be loud (the theme
// running through every --fail-on* flag in this codebase).
func TestExplain_NoMatchWritesNothing(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-real"},
		Severity: severity.High, Score: 7.5,
	}}}
	var buf bytes.Buffer
	n, err := Explain(&buf, res, "CVE-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
	if buf.Len() != 0 {
		t.Errorf("Explain wrote %q for a non-matching id, want nothing", buf.String())
	}
}

// TestExplain_ShowsSourcePackageIndirection: when the advisory was written
// against the source package (D8), the explanation must say so explicitly
// and distinctly from a direct match — otherwise a reader cannot tell why
// the installed package name does not appear in the advisory they look up.
func TestExplain_ShowsSourcePackageIndirection(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package: pkgmeta.Package{
			Name: "libssl3-explain", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19",
			Source: &pkgmeta.SourcePackage{Name: "openssl-explain"},
		},
		Advisory:    advisory.Advisory{ID: "CVE-2024-explain-source"},
		MatchedName: "openssl-explain",
		Severity:    severity.High, Score: 7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Explain(&buf, res, "CVE-2024-explain-source"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "libssl3-explain") {
		t.Errorf("output does not name the installed package:\n%s", out)
	}
	if !strings.Contains(out, "openssl-explain") {
		t.Errorf("output does not name the source package the advisory was written against (D8):\n%s", out)
	}
	if !strings.Contains(out, "source package") {
		t.Errorf("output does not explain the D8 indirection in words:\n%s", out)
	}
}

// A direct match (MatchedName == Package.Name) must not claim a source
// package indirection that did not happen — the mirror-image mistake table.go
// itself already guards against (TestTable_DoesNotRepeatTheNameWhenItMatchedDirectly).
func TestExplain_DirectMatchDoesNotClaimSourceIndirection(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:     pkgmeta.Package{Name: "busybox-explain", Version: "1.36.1-r15", Ecosystem: "Alpine:v3.19"},
		Advisory:    advisory.Advisory{ID: "CVE-2024-explain-direct"},
		MatchedName: "busybox-explain",
		Severity:    severity.High, Score: 7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Explain(&buf, res, "CVE-2024-explain-direct"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "source package") {
		t.Errorf("a direct match must not claim a source-package indirection:\n%s", buf.String())
	}
}

// TestExplain_MultipleFindingsShareOneAdvisory: one advisory can affect
// several installed packages, so explaining it must show every finding it
// produced, not just the first.
func TestExplain_MultipleFindingsShareOneAdvisory(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "pkg-one-explain", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-shared-explain"},
			Severity: severity.High, Score: 7.5,
		},
		{
			Package:  pkgmeta.Package{Name: "pkg-two-explain", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-shared-explain"},
			Severity: severity.Medium, Score: 5.0,
		},
	}}
	var buf bytes.Buffer
	n, err := Explain(&buf, res, "GHSA-shared-explain")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("n = %d, want 2", n)
	}
	out := buf.String()
	if !strings.Contains(out, "pkg-one-explain") || !strings.Contains(out, "pkg-two-explain") {
		t.Errorf("output does not name both affected packages:\n%s", out)
	}
}

// TestExplain_LookupIsExactNotSubstring: identifiesAdvisory must compare
// with ==, never Contains. Advisory IDs nest (GHSA-1 is a substring of
// GHSA-10, exactly as in table.go's own TestCellAt_PicksTheRowByItsAdvisoryCell),
// so a substring-based lookup for "GHSA-1" would spuriously also explain the
// unrelated GHSA-10 finding.
func TestExplain_LookupIsExactNotSubstring(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-10"},
			Severity: severity.Low, Score: 2.0,
		},
		{
			Package:  pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-1"},
			Severity: severity.High, Score: 7.5,
		},
	}}
	var buf bytes.Buffer
	n, err := Explain(&buf, res, "GHSA-1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("n = %d, want exactly 1 — a substring match would also explain GHSA-10:\n%s", n, buf.String())
	}
	if strings.Contains(buf.String(), "package:  a ") {
		t.Errorf("explained the wrong finding (GHSA-10's package) for a lookup of \"GHSA-1\":\n%s", buf.String())
	}
}

// TestExplain_AliasLookupIsExactNotSubstring: the same exact-match
// requirement as TestExplain_LookupIsExactNotSubstring, but for the
// alias/upstream path through otherIDs rather than the advisory's own ID —
// a separate code path, so it needs its own nesting fixture. "CVE-2024-1" is
// a substring of "CVE-2024-10", so a Contains-based lookup for the former
// would spuriously also explain the finding whose alias is the latter.
func TestExplain_AliasLookupIsExactNotSubstring(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "has-cve-10", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-nest-a", Aliases: []string{"CVE-2024-10"}},
			Severity: severity.Low, Score: 2.0,
		},
		{
			Package:  pkgmeta.Package{Name: "has-cve-1", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-nest-b", Aliases: []string{"CVE-2024-1"}},
			Severity: severity.High, Score: 7.5,
		},
	}}
	var buf bytes.Buffer
	n, err := Explain(&buf, res, "CVE-2024-1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("n = %d, want exactly 1 — a substring match on the alias would also "+
			"explain the CVE-2024-10 finding:\n%s", n, buf.String())
	}
	if strings.Contains(buf.String(), "has-cve-10") {
		t.Errorf("explained the wrong finding (aliased CVE-2024-10) for a lookup of "+
			"\"CVE-2024-1\":\n%s", buf.String())
	}
}

// TestComparerName_ExactNamePerEcosystem pins the exact name comparerName
// returns per ecosystem, not just "some real name versus unknown".
// TestComparerName_AgreesWithVersionFor below only ever checks presence
// against version.For's ok bool, so "PyPI" -> "semver" (the wrong comparer
// entirely — PEP 440 and SemVer disagree on precedence, D9) and
// "Alpine:v3.19" -> "semver" both survived it: version.For also reports ok
// for those ecosystems, so the presence check alone is satisfied regardless
// of which name comes back. A reader debugging a suspected false negative
// who is told "semver" for a PyPI package would go check the wrong
// comparer's rules — the opposite of what explain mode exists for.
func TestComparerName_ExactNamePerEcosystem(t *testing.T) {
	for _, tt := range []struct{ ecosystem, want string }{
		{"Go", "semver"},
		{"npm", "semver"},
		{"PyPI", "pep440"},
		{"Alpine:v3.19", "apk"},
		{"Alpine:v3.99", "apk"},
		{"Alpine:", "unknown"}, // no release -> not a key version.For ever builds
		{"bogus-eco", "unknown"},
	} {
		if got := comparerName(tt.ecosystem); got != tt.want {
			t.Errorf("comparerName(%q) = %q, want %q", tt.ecosystem, got, tt.want)
		}
	}
}

// TestRatingLine_FormatsOneSource is the direct unit test for ratingLine's
// fixed-width layout, exactly the way TestFormatSeverity in table_test.go
// directly tests formatSeverity. Expected strings were captured from a real
// run of ratingLine and hand-verified against its format string
// ("  %-6s %-24s %-16s fixed %s") rather than re-derived through the same
// code under test, so a width constant drifting silently still fails this.
func TestRatingLine_FormatsOneSource(t *testing.T) {
	got := ratingLine(matcher.Rating{
		Database: "GHSA", AdvisoryID: "GHSA-w24h-v9qh-8gxj",
		Severity: severity.Critical, Score: 9.8, Fixed: "2.2.28",
	})
	want := "  GHSA   GHSA-w24h-v9qh-8gxj      critical (9.8)   fixed 2.2.28"
	if got != want {
		t.Errorf("ratingLine = %q, want %q", got, want)
	}

	// A rating that gave no fixed version renders "-", the same filler
	// table.go's own FIXED IN column uses for the same absence, rather than
	// a blank that a reader could mistake for a rendering glitch.
	got = ratingLine(matcher.Rating{Database: "PYSEC", AdvisoryID: "PYSEC-2022-191", Severity: severity.Unknown})
	want = "  PYSEC  PYSEC-2022-191           unknown          fixed -"
	if got != want {
		t.Errorf("ratingLine (no fixed version) = %q, want %q", got, want)
	}
}

// TestExplain_ShowsAllSourcesInFull is D10's "why" view applied to D25:
// where the table collapses to one SEVERITY cell (marked when sources
// disagree), --explain lists every source in full. GHSA (the winner, per
// matcher.beats) and PYSEC (the loser) disagree here — GHSA critical, PYSEC
// unknown — and the assertion on the PYSEC line is the one a mutation that
// prints only the winning source cannot pass: everything else in this
// finding (advisory:, severity:, evidence) is already sourced from
// Finding.Advisory/Severity/Score, which is GHSA's own data, so only the
// Ratings loop can put PYSEC's line in the output at all.
func TestExplain_ShowsAllSourcesInFull(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "django", Version: "3.2.12", Ecosystem: "PyPI"},
		Advisory: advisory.Advisory{ID: "GHSA-w24h-v9qh-8gxj"},
		Severity: severity.Critical,
		Score:    9.8,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-w24h-v9qh-8gxj", Severity: severity.Critical, Score: 9.8, Fixed: "2.2.28"},
			{Database: "PYSEC", AdvisoryID: "PYSEC-2022-191", Severity: severity.Unknown, Fixed: "2.2.28"},
		},
	}}}
	var buf bytes.Buffer
	n, err := Explain(&buf, res, "GHSA-w24h-v9qh-8gxj")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	out := buf.String()

	if got, want := explainLine(t, out, "severity:"),
		"severity: critical (9.8)   [highest of 2 sources]"; got != want {
		t.Errorf("severity line = %q, want %q", got, want)
	}
	if got, want := explainLine(t, out, "  GHSA"),
		"  GHSA   GHSA-w24h-v9qh-8gxj      critical (9.8)   fixed 2.2.28"; got != want {
		t.Errorf("GHSA rating line = %q, want %q\nfull output:\n%s", got, want, out)
	}
	// PYSEC is the source matcher.beats did NOT pick to set Advisory/
	// Severity/Score. Its line can only come from the Ratings loop.
	if got, want := explainLine(t, out, "  PYSEC"),
		"  PYSEC  PYSEC-2022-191           unknown          fixed 2.2.28"; got != want {
		t.Errorf("PYSEC rating line = %q, want %q\nfull output:\n%s", got, want, out)
	}
}

// TestExplain_ZeroRatingsIsTheBoundaryNotABranch exercises n == 0: Match
// never produces a Finding with an empty Ratings — this is a boundary case
// of the general (additive) rendering, reachable only by constructing a
// Finding directly, exactly as several OTHER tests in this file still do for
// reasons unrelated to D25 (alias matching, D8 indirection). It is worth
// pinning anyway because explainOne has no dedicated branch for it: the
// severity line and the empty breakdown loop are the same code that runs for
// n > 0, just with nothing to add and nothing to iterate over. If that ever
// stops being true — if a special case for "no Ratings" gets reintroduced —
// this is what would catch it.
func TestExplain_ZeroRatingsIsTheBoundaryNotABranch(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-no-ratings"},
		Severity: severity.High, Score: 7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Explain(&buf, res, "GHSA-no-ratings"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got, want := explainLine(t, out, "severity:"), "severity: high (7.5)"; got != want {
		t.Errorf("severity line = %q, want %q (no annotation without Ratings)", got, want)
	}
	if strings.Contains(out, "highest of") {
		t.Errorf("output claims a source count for a finding with no Ratings:\n%s", out)
	}
}

// TestExplain_SingleSourceShowsAnnotationAndOneLine pins n == 1 specifically.
// TestExplain_ZeroRatingsIsTheBoundaryNotABranch above covers n == 0 and
// TestExplain_ShowsAllSourcesInFull covers n == 2, but nothing pinned the
// boundary in between: widening the `n > 0` guard in explainOne to `n > 1`
// (treating one source the same as no Ratings at all) would leave every
// other explain test in this file green.
func TestExplain_SingleSourceShowsAnnotationAndOneLine(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-solo-explain"},
		Severity: severity.High, Score: 7.5,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-solo-explain", Severity: severity.High, Score: 7.5, Fixed: "2.0.0"},
		},
	}}}
	var buf bytes.Buffer
	if _, err := Explain(&buf, res, "GHSA-solo-explain"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got, want := explainLine(t, out, "severity:"),
		"severity: high (7.5)   [highest of 1 source]"; got != want {
		t.Errorf("severity line = %q, want %q", got, want)
	}
	if got, want := explainLine(t, out, "  GHSA"),
		"  GHSA   GHSA-solo-explain        high (7.5)       fixed 2.0.0"; got != want {
		t.Errorf("rating line = %q, want %q\nfull output:\n%s", got, want, out)
	}
}

// TestComparerName_AgreesWithVersionFor is the drift guard for the small,
// local ecosystem -> comparer-name mirror explain.go uses to say "which
// comparer" without exporting version's unexported registry (D9). If
// version.For ever starts (or stops) recognizing an ecosystem, this table
// must be updated in the same commit, or this test goes red.
func TestComparerName_AgreesWithVersionFor(t *testing.T) {
	for _, eco := range []string{"Go", "npm", "PyPI", "Alpine:v3.19", "Alpine:v3.99", "Alpine:", "bogus-eco"} {
		_, ok := version.For(eco)
		name := comparerName(eco)
		if ok && name == "unknown" {
			t.Errorf("comparerName(%q) = %q, but version.For(%q) has a real comparer", eco, name, eco)
		}
		if !ok && name != "unknown" {
			t.Errorf("comparerName(%q) = %q, but version.For(%q) has no comparer", eco, name, eco)
		}
	}
}
