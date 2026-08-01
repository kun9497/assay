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

// TestExplain_PrintsTheFindingsEvidence is D10 made visible: which range
// matched, what the comparison actually returned, and which name reached the
// advisory (D8). Every value here is deliberately unique so a check for the
// rendered pair ("label: value") cannot pass from an unrelated part of the
// output — the exact hazard CLAUDE.md's "substring assertions" note warns
// about.
func TestExplain_PrintsTheFindingsEvidence(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package: pkgmeta.Package{
			Name: "github.com/foo/bar-explain", Version: "v1.2.3", Ecosystem: "Go",
		},
		Advisory: advisory.Advisory{ID: "GHSA-explain-hit", Summary: "Code injection"},
		Evidence: version.Evidence{
			RangeType:  advisory.RangeSemver,
			Introduced: "0",
			Fixed:      "1.5.0-explain-fix",
			Reason:     "v1.2.3 is at or above any earlier version and below the fix 1.5.0-explain-fix",
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
	for _, want := range []string{
		"github.com/foo/bar-explain",
		"v1.2.3",
		"GHSA-explain-hit",
		"1.5.0-explain-fix",
		"high (7.5)",
		"semver", // the comparer that decided this: Go uses SemVer (D9/D10)
		"v1.2.3 is at or above any earlier version and below the fix 1.5.0-explain-fix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestExplain_MatchesByAliasOrUpstream: D3 read both aliases and upstream
// when joining on an identifier, because which field carries the CVE
// depends on the ecosystem. A reader who grepped the table's ALIASES column
// for a CVE must be able to hand that same CVE to --explain.
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
