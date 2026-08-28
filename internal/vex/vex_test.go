package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// finding builds the smallest matcher.Finding Apply needs: a package purl to
// match against a statement's products, and an Identifiers list to match
// against a statement's vulnerability. id is included in Identifiers, the
// way a real Finding's own advisory ID always is — a test that only put
// aliases in Identifiers would prove nothing about matching the plain-ID
// case.
func finding(id, purl string, aliases ...string) matcher.Finding {
	return matcher.Finding{
		Package:     pkgmeta.Package{PURL: purl},
		Advisory:    advisory.Advisory{ID: id},
		Identifiers: append([]string{id}, aliases...),
	}
}

// collector gathers every warn() call a test drives, so an assertion can
// check both "did it warn" and "did it warn about the right thing" rather
// than only the latter — a warn func that fires for the wrong reason and
// still contains the expected substring would otherwise pass by accident.
type collector struct{ msgs []string }

func (c *collector) warn(msg string) { c.msgs = append(c.msgs, msg) }

func (c *collector) contains(sub string) bool {
	for _, m := range c.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// applyOne runs Apply against a single finding and reports whether it was
// suppressed, its reason if so, and every warning collected — the shape
// every row of the adversarial table below checks.
func applyOne(doc *Document, f matcher.Finding) (suppressed bool, reason string, warnings *collector) {
	c := &collector{}
	kept, sup := doc.Apply([]matcher.Finding{f}, c.warn)
	switch {
	case len(sup) == 1 && len(kept) == 0:
		return true, sup[0].Reason, c
	case len(kept) == 1 && len(sup) == 0:
		return false, "", c
	default:
		panic("applyOne: Apply must return exactly one finding across kept+suppressed")
	}
}

// TestApply_AdversarialTable transcribes every row of D104's rules doc
// adversarial table (docs/superpowers/... d104-openvex-rules.md, "Adversarial
// table") as one subtest each, in the doc's own numbering, so a reviewer can
// check this file against that doc row by row. Fixture values are distinct
// PER ROW specifically so a row cannot pass by colliding with another row's
// expectation (the CLAUDE.md substring-collision rule) — e.g. row 11's purl
// name and row 12's are the same on purpose (only the version differs, which
// is the one thing that row is testing), but every OTHER row uses its own
// package/vulnerability name so a copy-paste mistake fails loudly instead of
// silently matching the wrong row's fixture.
func TestApply_AdversarialTable(t *testing.T) {
	t.Run("1: not_affected+justification, purl exact -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0001"},
			Status:        "not_affected", Justification: "vulnerable_code_not_present",
			Products: []Product{{PURLAttr: "pkg:deb/debian/row1pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0001", "pkg:deb/debian/row1pkg@1.0.0")
		sup, reason, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed")
		}
		if !strings.Contains(reason, "vulnerable_code_not_present") {
			t.Errorf("reason = %q, want it to name the justification", reason)
		}
	})

	t.Run("2: not_affected, no justification, no impact_statement -> NOT suppressed + warning", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0002"},
			Status:        "not_affected",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/row2pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0002", "pkg:deb/debian/row2pkg@1.0.0")
		sup, _, w := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed")
		}
		if !w.contains("neither justification nor impact_statement") {
			t.Errorf("warnings = %v, want one naming the missing reason", w.msgs)
		}
	})

	t.Run("3: not_affected+impact_statement only -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability:   Vulnerability{Name: "CVE-2031-0003"},
			Status:          "not_affected",
			ImpactStatement: "The vulnerable function is never invoked in this build.",
			Products:        []Product{{PURLAttr: "pkg:deb/debian/row3pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0003", "pkg:deb/debian/row3pkg@1.0.0")
		sup, reason, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed")
		}
		if !strings.Contains(reason, "never invoked in this build") {
			t.Errorf("reason = %q, want the impact statement quoted", reason)
		}
	})

	t.Run("4: not_affected+justification outside enum -> suppressed + warning", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0004"},
			Status:        "not_affected", Justification: "reviewed_and_dismissed",
			Products: []Product{{PURLAttr: "pkg:deb/debian/row4pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0004", "pkg:deb/debian/row4pkg@1.0.0")
		sup, reason, w := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — a non-standard justification IS a stated reason")
		}
		if !strings.Contains(reason, "reviewed_and_dismissed") {
			t.Errorf("reason = %q, want the justification named even though it is non-standard", reason)
		}
		if !w.contains("not one of OpenVEX's standard values") {
			t.Errorf("warnings = %v, want one flagging the non-standard justification", w.msgs)
		}
	})

	t.Run("5: fixed -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0005"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/row5pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0005", "pkg:deb/debian/row5pkg@1.0.0")
		sup, reason, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — fixed needs no justification")
		}
		if !strings.HasPrefix(reason, "VEX: fixed") {
			t.Errorf("reason = %q, want it to start with %q", reason, "VEX: fixed")
		}
	})

	t.Run("6: affected -> NOT suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0006"},
			Status:        "affected",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/row6pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0006", "pkg:deb/debian/row6pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — affected has no annotate/augment path")
		}
	})

	t.Run("7: under_investigation -> NOT suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0007"},
			Status:        "under_investigation",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/row7pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0007", "pkg:deb/debian/row7pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed")
		}
	})

	t.Run("8: unrecognized status strings -> statement skipped + warning", func(t *testing.T) {
		for _, status := range []string{"resolved", "NotAffected", "not affected"} {
			t.Run(status, func(t *testing.T) {
				doc := &Document{Statements: []Statement{{
					Vulnerability: Vulnerability{Name: "CVE-2031-0008"},
					Status:        status,
					Products:      []Product{{PURLAttr: "pkg:deb/debian/row8pkg@1.0.0"}},
				}}}
				f := finding("CVE-2031-0008", "pkg:deb/debian/row8pkg@1.0.0")
				sup, _, w := applyOne(doc, f)
				if sup {
					t.Fatalf("status %q must never silently equal not_affected", status)
				}
				if !w.contains("unrecognized status") {
					t.Errorf("warnings = %v, want one naming the unrecognized status", w.msgs)
				}
			})
		}
	})

	t.Run("9: name GHSA-x, aliases [CVE], finding identifier CVE -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "GHSA-row9-xxxx-yyyy", Aliases: []string{"CVE-2025-1234"}},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/row9pkg@1.0.0"}},
		}}}
		// The finding's own advisory ID is the CVE; the statement never
		// names it as Name, only as an alias — name-only matching would miss.
		f := finding("CVE-2025-1234", "pkg:deb/debian/row9pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed via the alias, not the name")
		}
	})

	t.Run("10: lowercase vulnerability name vs uppercase finding id -> suppressed (EqualFold)", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "cve-2025-9999"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/row10pkg@1.0.0"}},
		}}}
		f := finding("CVE-2025-9999", "pkg:deb/debian/row10pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — case-insensitive match (assay's own divergence from go-vex)")
		}
	})

	t.Run("11: doc purl exact vs package purl exact -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0011"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/openssl@3.0.11-1"}},
		}}}
		f := finding("CVE-2031-0011", "pkg:deb/debian/openssl@3.0.11-1")
		sup, _, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed")
		}
	})

	t.Run("12: same doc purl vs a different package version -> NOT", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0012"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:deb/debian/openssl@3.0.11-1"}},
		}}}
		f := finding("CVE-2031-0012", "pkg:deb/debian/openssl@3.0.14-1")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — versions differ")
		}
	})

	t.Run("13: version-less doc purl matches any version + reason notes it", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0013"},
			Status:        "not_affected", Justification: "vulnerable_code_not_present",
			Products: []Product{{PURLAttr: "pkg:pypi/django"}},
		}}}
		f := finding("CVE-2031-0013", "pkg:pypi/django@5.0.1")
		sup, reason, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — version-less doc purl matches every version")
		}
		if !strings.Contains(reason, "product purl has no version") {
			t.Errorf("reason = %q, want the version-less footnote", reason)
		}
	})

	t.Run("14: versioned doc purl vs version-less package purl -> NOT", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0014"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:pypi/django@5.0"}},
		}}}
		f := finding("CVE-2031-0014", "pkg:pypi/django")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — nothing to compare the doc's version against")
		}
	})

	t.Run("15: namespace mismatch -> NOT", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0015"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:apk/wolfi/openssl@9.9.9-r0"}},
		}}}
		f := finding("CVE-2031-0015", "pkg:apk/alpine/openssl@9.9.9-r0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — different namespace")
		}
	})

	t.Run("16: type mismatch -> NOT", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0016"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:golang/example.com/row16@1.0.0"}},
		}}}
		f := finding("CVE-2031-0016", "pkg:npm/row16@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — different purl type")
		}
	})

	t.Run("17: doc qualifier absent from package -> NOT", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0017"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:apk/alpine/row17pkg@1.0.0?arch=x86_64"}},
		}}}
		f := finding("CVE-2031-0017", "pkg:apk/alpine/row17pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — the package purl lacks the doc's arch qualifier")
		}
	})

	t.Run("18: package carries extra qualifiers the doc says nothing about -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0018"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:apk/alpine/row18pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0018", "pkg:apk/alpine/row18pkg@1.0.0?arch=x86_64&distro=alpine-3.19")
		sup, _, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — extra package qualifiers are a one-directional subset, not set equality")
		}
	})

	t.Run("19: purls differing only in #subpath -> suppressed (deliberate)", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0019"},
			Status:        "fixed",
			Products:      []Product{{PURLAttr: "pkg:golang/example.com/row19@1.0.0#cmd/foo"}},
		}}}
		f := finding("CVE-2031-0019", "pkg:golang/example.com/row19@1.0.0#cmd/bar")
		sup, _, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — subpath is not part of pkgmeta.PURL at all, this must not regress")
		}
	})

	t.Run("20: non-purl @id vs package purl -> NOT (exact-string only)", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0020"},
			Status:        "fixed",
			Products:      []Product{{ID: "nginx"}},
		}}}
		f := finding("CVE-2031-0020", "pkg:golang/example.com/row20@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — \"nginx\" never purl-parses and never equals a purl string")
		}
	})

	// row21Doc is shared by rows 21-23: one statement whose product is an
	// image-level purl (never matched directly by a package-as-product
	// query) with one subcomponent naming the actual package.
	row21Doc := &Document{Statements: []Statement{{
		Vulnerability: Vulnerability{Name: "CVE-2031-0021"},
		Status:        "fixed",
		Products: []Product{{
			PURLAttr:      "pkg:oci/row21image@sha256:deadbeef",
			Subcomponents: []Product{{PURLAttr: "pkg:deb/debian/row21libssl3@3.0.11"}},
		}},
	}}}

	t.Run("21: product=image purl+subcomponent purl, finding matches the subcomponent -> suppressed", func(t *testing.T) {
		f := finding("CVE-2031-0021", "pkg:deb/debian/row21libssl3@3.0.11")
		sup, _, _ := applyOne(row21Doc, f)
		if !sup {
			t.Fatal("want suppressed via the subcomponent")
		}
	})

	t.Run("22: same statement, a different package -> NOT", func(t *testing.T) {
		f := finding("CVE-2031-0021", "pkg:deb/debian/row22zlib1g@3.0.11")
		sup, _, _ := applyOne(row21Doc, f)
		if sup {
			t.Fatal("want NOT suppressed — this package is not the subcomponent named")
		}
	})

	t.Run("23: statement has subcomponents, finding has no purl to offer -> NOT (diverges from go-vex)", func(t *testing.T) {
		f := finding("CVE-2031-0021", "") // no purl at all
		sup, _, _ := applyOne(row21Doc, f)
		if sup {
			t.Fatal("want NOT suppressed — go-vex would default-match here (subIdentifier==\"\"), assay must not")
		}
	})

	t.Run("24: statement with no products -> skipped + warning", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0024"},
			Status:        "fixed",
		}}}
		f := finding("CVE-2031-0024", "pkg:deb/debian/row24pkg@1.0.0")
		sup, _, w := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — no product to name what is exonerated")
		}
		if !w.contains("names no product") {
			t.Errorf("warnings = %v, want one naming the product-less statement", w.msgs)
		}
	})

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC) // strictly after t1

	t.Run("25: fixed@T1 then affected@T2 -> NOT suppressed (latest wins over an earlier fix)", func(t *testing.T) {
		doc := &Document{Statements: []Statement{
			{
				Vulnerability: Vulnerability{Name: "CVE-2031-0025"}, Status: "fixed",
				Products:  []Product{{PURLAttr: "pkg:deb/debian/row25pkg@1.0.0"}},
				Timestamp: t1, HasTimestamp: true,
			},
			{
				Vulnerability: Vulnerability{Name: "CVE-2031-0025"}, Status: "affected",
				Products:  []Product{{PURLAttr: "pkg:deb/debian/row25pkg@1.0.0"}},
				Timestamp: t2, HasTimestamp: true,
			},
		}}
		f := finding("CVE-2031-0025", "pkg:deb/debian/row25pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — the later 'affected' statement supersedes the earlier fix; grype would wrongly suppress here")
		}
	})

	t.Run("26: affected@T1 then not_affected@T2 -> suppressed", func(t *testing.T) {
		doc := &Document{Statements: []Statement{
			{
				Vulnerability: Vulnerability{Name: "CVE-2031-0026"}, Status: "affected",
				Products:  []Product{{PURLAttr: "pkg:deb/debian/row26pkg@1.0.0"}},
				Timestamp: t1, HasTimestamp: true,
			},
			{
				Vulnerability: Vulnerability{Name: "CVE-2031-0026"}, Status: "not_affected",
				Justification: "vulnerable_code_not_present",
				Products:      []Product{{PURLAttr: "pkg:deb/debian/row26pkg@1.0.0"}},
				Timestamp:     t2, HasTimestamp: true,
			},
		}}
		f := finding("CVE-2031-0026", "pkg:deb/debian/row26pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — the later not_affected statement wins")
		}
	})

	t.Run("27: equal timestamps, conflicting statuses -> last in document order wins", func(t *testing.T) {
		t.Run("fixed then affected (equal ts) -> NOT suppressed", func(t *testing.T) {
			doc := &Document{Statements: []Statement{
				{
					Vulnerability: Vulnerability{Name: "CVE-2031-0027A"}, Status: "fixed",
					Products:  []Product{{PURLAttr: "pkg:deb/debian/row27apkg@1.0.0"}},
					Timestamp: t1, HasTimestamp: true,
				},
				{
					Vulnerability: Vulnerability{Name: "CVE-2031-0027A"}, Status: "affected",
					Products:  []Product{{PURLAttr: "pkg:deb/debian/row27apkg@1.0.0"}},
					Timestamp: t1, HasTimestamp: true,
				},
			}}
			f := finding("CVE-2031-0027A", "pkg:deb/debian/row27apkg@1.0.0")
			sup, _, _ := applyOne(doc, f)
			if sup {
				t.Fatal("want NOT suppressed — the LAST statement in the document wins the tie")
			}
		})
		t.Run("affected then fixed (equal ts) -> suppressed", func(t *testing.T) {
			doc := &Document{Statements: []Statement{
				{
					Vulnerability: Vulnerability{Name: "CVE-2031-0027B"}, Status: "affected",
					Products:  []Product{{PURLAttr: "pkg:deb/debian/row27bpkg@1.0.0"}},
					Timestamp: t1, HasTimestamp: true,
				},
				{
					Vulnerability: Vulnerability{Name: "CVE-2031-0027B"}, Status: "fixed",
					Products:  []Product{{PURLAttr: "pkg:deb/debian/row27bpkg@1.0.0"}},
					Timestamp: t1, HasTimestamp: true,
				},
			}}
			f := finding("CVE-2031-0027B", "pkg:deb/debian/row27bpkg@1.0.0")
			sup, _, _ := applyOne(doc, f)
			if !sup {
				t.Fatal("want suppressed — the LAST statement in the document wins the tie, reversing row 27's other direction")
			}
		})
	})

	t.Run("28: statement with no timestamp inherits the document's for ordering", func(t *testing.T) {
		docTS := t2 // later than the explicit statement timestamp below
		doc := &Document{
			Timestamp: docTS, HasTimestamp: true,
			Statements: []Statement{
				{
					Vulnerability: Vulnerability{Name: "CVE-2031-0028"}, Status: "fixed",
					Products:  []Product{{PURLAttr: "pkg:deb/debian/row28pkg@1.0.0"}},
					Timestamp: t1, HasTimestamp: true, // explicit, EARLIER than the doc's
				},
				{
					// No timestamp of its own: must inherit docTS (t2), which
					// is LATER than the first statement's explicit t1 — if
					// inheritance were broken (read as zero instead), this
					// statement would lose the contest instead of winning it.
					Vulnerability: Vulnerability{Name: "CVE-2031-0028"}, Status: "affected",
					Products: []Product{{PURLAttr: "pkg:deb/debian/row28pkg@1.0.0"}},
				},
			},
		}
		f := finding("CVE-2031-0028", "pkg:deb/debian/row28pkg@1.0.0")
		sup, _, _ := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — the undated 'affected' statement inherits the later document timestamp and wins")
		}
	})

	t.Run("29: neither statement nor document carries a timestamp -> zero time, warns, never crashes", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0029"}, Status: "fixed",
			Products: []Product{{PURLAttr: "pkg:deb/debian/row29pkg@1.0.0"}},
		}}}
		f := finding("CVE-2031-0029", "pkg:deb/debian/row29pkg@1.0.0")
		sup, _, w := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — it is the only candidate, so a zero timestamp still wins by default")
		}
		if !w.contains("no timestamp") {
			t.Errorf("warnings = %v, want one about the missing timestamp", w.msgs)
		}
	})

	t.Run("30: statements: [] -> valid, zero suppressions, quiet", func(t *testing.T) {
		doc := &Document{Statements: nil}
		f := finding("CVE-2031-0030", "pkg:deb/debian/row30pkg@1.0.0")
		sup, _, w := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — no statements to suppress with")
		}
		if len(w.msgs) != 0 {
			t.Errorf("warnings = %v, want none — an empty document is not a malformed one", w.msgs)
		}
	})

	t.Run("31: v0.0.1 document parses and suppresses equivalently", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "legacy.vex.json")
		body := `{
  "@context": "https://openvex.dev/ns",
  "@id": "https://example.com/vex/row31",
  "author": "Row31 Author",
  "version": "1",
  "timestamp": "2026-01-01T00:00:00Z",
  "statements": [
    {
      "vulnerability": "CVE-2031-0031",
      "products": ["pkg:deb/debian/row31pkg@1.0.0"],
      "subcomponents": [],
      "status": "fixed"
    }
  ]
}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		doc, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		f := finding("CVE-2031-0031", "pkg:deb/debian/row31pkg@1.0.0")
		sup, reason, _ := applyOne(doc, f)
		if !sup {
			t.Fatal("want suppressed — v0.0.1 must parse and suppress the same as v0.2.0")
		}
		if !strings.Contains(reason, "Row31 Author") {
			t.Errorf("reason = %q, want the document author carried through", reason)
		}
	})

	t.Run("33: unparseable doc purl -> statement never matches + warning", func(t *testing.T) {
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0033"}, Status: "fixed",
			// identifiers.purl is always meant to BE a purl (unlike @id,
			// which may legitimately be a non-purl string) — setting it to
			// garbage must warn and never fall back to exact-string
			// comparison against this literal.
			Products: []Product{{PURLAttr: "totally-not-a-purl"}},
		}}}
		f := finding("CVE-2031-0033", "pkg:deb/debian/row33pkg@1.0.0")
		sup, _, w := applyOne(doc, f)
		if sup {
			t.Fatal("want NOT suppressed — an unparseable doc purl must never become a wildcard")
		}
		if !w.contains("could not be parsed") {
			t.Errorf("warnings = %v, want one naming the unparseable purl", w.msgs)
		}
	})

	t.Run("34: Apply only ever sees the findings it is given (ordering is the caller's job)", func(t *testing.T) {
		// Row 34's actual proof lives at the scancmd level
		// (TestRun_IgnoreRulesRunBeforeVEX): applyIgnoreRules removes an
		// already-waived finding from res.Findings before applyVEX ever
		// runs. What belongs here is the contract that makes that ordering
		// work at all — Apply is a pure function of whatever slice it is
		// handed, so a finding already removed upstream is never
		// re-evaluated, never double-suppressed, and produces no reason
		// naming this document.
		doc := &Document{Statements: []Statement{{
			Vulnerability: Vulnerability{Name: "CVE-2031-0034"}, Status: "fixed",
			Products: []Product{{PURLAttr: "pkg:deb/debian/row34pkg@1.0.0"}},
		}}}
		kept, sup := doc.Apply(nil, func(string) {})
		if len(kept) != 0 || len(sup) != 0 {
			t.Errorf("Apply(nil) = kept %v, suppressed %v, want both empty", kept, sup)
		}
	})

	t.Run("35: Load on an unreadable or non-JSON path fails, naming the path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.json")
		if _, err := Load(missing); err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("Load(%s) err = %v, want an error naming the path", missing, err)
		}

		garbage := filepath.Join(t.TempDir(), "garbage.json")
		if err := os.WriteFile(garbage, []byte("not json at all {{{"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(garbage); err == nil {
			t.Error("Load on non-JSON content should error")
		}
	})
}

// TestLoad_UnknownContextIsRefused is row 32: a missing, garbage, or
// future-version @context is exactly as untrustworthy as a document that is
// not JSON at all (D11) — Load must refuse it rather than silently applying
// zero statements, and the three shapes below (absent, garbage, a version
// this package predates) are the ones a real file could plausibly carry.
func TestLoad_UnknownContextIsRefused(t *testing.T) {
	cases := []struct {
		name, context string
	}{
		{"missing @context entirely", ""},
		{"garbage @context", "not-a-context-at-all"},
		{"a future version this package predates", "https://openvex.dev/ns/v9.9.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "doc.json")
			body := `{"statements": []}`
			if tc.context != "" {
				body = `{"@context": "` + tc.context + `", "statements": []}`
			}
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Error("want an error — an unrecognized @context is untrustworthy input, not zero statements")
			}
		})
	}
}
