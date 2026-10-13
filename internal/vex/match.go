package vex

import (
	"fmt"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// justificationEnum is OpenVEX's five stated `not_affected` reasons (the
// spec's closed list). A justification outside it still suppresses — it IS
// a stated reason, D104's rules are explicit that assay does not second-guess
// an author's wording — but it is unusual enough to warn about, the same way
// an unknown status warns without necessarily meaning the document is wrong.
var justificationEnum = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// Apply matches every live statement in d against findings, exactly the
// shape ignore.Config.Apply already established for .assay.yaml: findings
// that no statement exonerates pass through unchanged in kept, the rest move
// to suppressed with the reason the winning statement gives. warn (never nil
// at the call site) receives one message per statement this document could
// not honour — an unknown status, a reasonless not_affected, a product-less
// statement, an unparseable product purl — so the statement is skipped
// rather than silently treated as either "suppress everything" or "suppress
// nothing".
//
// Unlike ignore.Config.Apply there is no `now`: a VEX statement carries no
// expiry, only a timestamp used for precedence between statements about the
// SAME finding (see resolve below), which is a comparison between two
// statements, not against the clock.
//
// target is what was scanned (D121): a statement whose products include an
// image applies only when one of those images is the target, and target's
// Ubuntu codename is the second distro spelling an Ubuntu package answers
// to. stats counts what became of this document's statements, so a caller
// can say how many applied to nothing rather than let them vanish.
func (d *Document) Apply(findings []matcher.Finding, target Target, warn func(string)) (kept []matcher.Finding, suppressed []matcher.Suppressed, stats Stats) {
	live, stats := d.liveStatements(target, warn)
	matched := make([]bool, len(d.Statements))

	for _, f := range findings {
		st, ok := resolve(live, f, target, matched)
		if !ok {
			kept = append(kept, f)
			continue
		}
		suppressed = append(suppressed, matcher.Suppressed{
			Finding: f,
			Reason:  st.reason,
			// D104: distinguishes a VEX exoneration from a D102 ignore-file
			// waiver in the report, so a reader (and a future second VEX-like
			// source) can tell suppressions apart by origin, not just by
			// reason text.
			Source: "vex",
		})
	}
	stats.Applied = len(suppressed)
	for _, m := range matched {
		if !m {
			stats.Unmatched++
		}
	}
	return kept, suppressed, stats
}

// Stats is what became of one document's statements in one scan (D121).
// Unmatched counts every statement that matched no finding, for whatever
// reason — including the ones also counted in Skipped (refused with a
// warning) and OutOfScope (naming an image that is not the target) — so
// Statements - Unmatched is the number that matched something.
type Stats struct {
	Statements int
	Unmatched  int
	Skipped    int
	OutOfScope int
	// Applied is how many findings this document suppressed.
	Applied int
}

// liveProduct is a Product with its purl-or-exact matching precomputed once
// per document load rather than once per finding: an unparseable product
// purl is a fact about the DOCUMENT, independent of which finding is being
// checked against it, so warning about it here — once — is both correct and
// avoids one warning per finding for a scan with many findings and one bad
// statement.
type liveProduct struct {
	isPURL  bool
	purl    pkgmeta.PURL
	exactID string
	// isSource marks a package product that declares itself a SOURCE
	// package — arch=src on an rpm purl (Red Hat), arch=source on a deb purl
	// (Canonical) — which applies to every installed binary built from it
	// (D121). No binary carries either arch, so the marker cannot be
	// mistaken. An unmarked name is never read as a source, even where it
	// is one: "openssl" on Rocky is both the source and a binary, and
	// reading the statement the wide way would hide openssl-libs' finding
	// behind a statement about the command.
	isSource bool
	// image is set for a product naming an image rather than a package
	// (D121): it never matches a finding itself, it scopes its statement.
	image         *imageRef
	subcomponents []liveProduct
}

// buildLiveProduct resolves one Product into its matchable form. A product
// whose "@id" starts with "pkg:" is matched by purl semantics even with no
// identifiers.purl (the v0.0.1 shape, and any v0.2.0 document that names a
// purl directly as @id) — PURLAttr wins when both are present, since it is
// the field the spec defines specifically to carry a purl.
func buildLiveProduct(p Product, warn func(string)) (liveProduct, bool) {
	docPurlStr := p.PURLAttr
	if docPurlStr == "" && strings.HasPrefix(p.ID, "pkg:") {
		docPurlStr = p.ID
	}
	var lp liveProduct
	if docPurlStr != "" {
		parsed, err := pkgmeta.ParsePURL(docPurlStr)
		if err != nil {
			if isImagePURLType(docPurlStr) {
				// D121: an image product that cannot be read still names an
				// image. Dropping it would unscope its statement, and the
				// bare top-level duplicates beside it (the Docker Hardened
				// Images shape) would then apply to every image. It scopes
				// the statement to an image no target matches instead — when
				// in doubt, skipped, never applied. Its subcomponents go with
				// it: they could only ever apply inside that image.
				warn(fmt.Sprintf("vex product purl %q names an image but could not be parsed; its statement applies to no target: %v",
					docPurlStr, err))
				return liveProduct{image: &imageRef{}}, true
			}
			// Row 33: an unparseable DOC purl must not become a wildcard —
			// this product contributes no match, ever, rather than falling
			// back to exact-string comparison against a purl-shaped literal
			// nothing will ever equal.
			warn(fmt.Sprintf("vex product purl %q could not be parsed and will never match: %v", docPurlStr, err))
			return liveProduct{}, false
		}
		lp.isPURL = true
		lp.purl = parsed
		if img, ok := imageFromPURL(parsed); ok {
			lp.image = &img
		}
		lp.isSource = isSourcePURL(parsed)
	} else {
		lp.exactID = p.ID
		if img, ok := imageFromReference(p.ID); ok {
			lp.image = &img
		}
	}
	for _, sc := range p.Subcomponents {
		if built, ok := buildLiveProduct(sc, warn); ok {
			lp.subcomponents = append(lp.subcomponents, built)
		}
	}
	return lp, true
}

// matches reports whether this product (or, failing that, one of its
// subcomponents) identifies the finding's own package — s, the purl as
// written and its parsed form (parsed once per finding by resolve, not once
// per product). versionless reports whether the WINNING purl match was
// against a version-less document purl, for the reason string's own footnote
// (D104's rule: such a match must say so).
//
// s.raw == "" — no purl on the finding at all — is the "nothing to offer"
// case the rules doc calls out by name (row 23): go-vex short-circuits an
// empty subcomponent identifier to a match (suppressing the WHOLE product).
// The explicit `s.raw != ""` guard below is redundant on the current shape
// of this function — a purl-typed subcomponent already refuses via s.ok
// (ParsePURL("") errors, so s.ok is false), and an exact-string one already
// refuses via `exactID != ""` — but it is kept as the guard that makes the
// "never default to a match" rule true BY CONSTRUCTION rather than as an
// emergent property of two unrelated checks; a mutation deleting it
// (verified 2026-08-28) does not turn row 23 red, which is recorded here
// rather than left as an unexplained survivor.
//
// viaSource names the source package when the match was a marked source
// statement's (D121), so the reason can say the binary was exonerated
// through its source rather than by its own name.
func (lp liveProduct) matches(s subject) (matched, versionless bool, viaSource string) {
	switch {
	case lp.image != nil:
		// An image is not a package; it scoped the statement instead.
	case lp.isPURL && lp.isSource:
		if s.ok {
			if m, vl := sourcePatternMatches(lp.purl, s); m {
				return true, vl, lp.purl.Name
			}
		}
	case lp.isPURL:
		if s.ok {
			if m, vl := purlPatternMatches(lp.purl, s.parsed, s.codename); m {
				return true, vl, ""
			}
		}
	case lp.exactID != "" && lp.exactID == s.raw:
		return true, false, ""
	}
	if len(lp.subcomponents) > 0 && s.raw != "" {
		for _, sc := range lp.subcomponents {
			if m, vl, via := sc.matches(s); m {
				return true, vl, via
			}
		}
	}
	return false, false, ""
}

// subject is one finding's package as a product is matched against it: the
// purl as written, parsed once per finding (ok false when there is none or
// it does not parse), the package itself for a source statement's
// Source.Name, and the target's Ubuntu codename.
type subject struct {
	raw      string
	parsed   pkgmeta.PURL
	ok       bool
	pkg      pkgmeta.Package
	codename string
}

// isSourcePURL reports whether a document purl marks itself a source
// package: arch=src on rpm, arch=source on deb (D121). apk has no such
// convention among the producers measured, so an apk product is always a
// binary one.
func isSourcePURL(p pkgmeta.PURL) bool {
	switch p.Type {
	case "rpm":
		return p.Qualifiers["arch"] == "src"
	case "deb":
		return p.Qualifiers["arch"] == "source"
	}
	return false
}

// sourcePatternMatches applies a marked source statement (D121) to an
// installed binary built from that source: the type and namespace as any
// purl match, the document's name against the package's Source.Name, its
// version against the source version, and its other qualifiers as the usual
// one-directional subset — arch excluded, since the marker is the one value
// no binary carries.
//
// The source version is Source.Version, falling back to the binary's own
// (D8's "empty means same as the binary"), except on rpm, where Source.Version
// is the binary's EVR and the SRPM's own version is read off its file name
// instead (rpmSourceVersions). An rpm document writes the epoch as a
// qualifier, so it is joined to the version before comparing and left out of
// the subset check.
func sourcePatternMatches(doc pkgmeta.PURL, s subject) (matched, versionless bool) {
	pkg := s.parsed
	if doc.Type != pkg.Type || !namespaceEqual(doc.Type, doc.Namespace, pkg.Namespace) {
		return false, false
	}
	if s.pkg.Source == nil || s.pkg.Source.Name == "" || s.pkg.Source.Name != doc.Name {
		return false, false
	}
	versionless = doc.Version == ""
	if !versionless {
		want, got := doc.Version, s.pkg.Source.Version
		if got == "" {
			got = s.pkg.Version
		}
		if doc.Type == "rpm" {
			want, got = rpmSourceVersions(doc, s)
		}
		if got == "" || want != got {
			return false, false
		}
	}
	for k, v := range doc.Qualifiers {
		if k == "arch" || (doc.Type == "rpm" && k == "epoch") {
			continue
		}
		if !qualifierMatches(pkg, k, v, s.codename) {
			return false, false
		}
	}
	return true, versionless
}

// rpmSourceVersions is the pair a marked rpm source statement compares: the
// document's version and the version of the SRPM the binary was built from,
// each with its epoch.
//
// The SRPM's version-release comes from its file name — Package.Upstream as
// the rpmdb cataloger records SOURCERPM, else the purl's upstream qualifier
// (an SBOM's package) — and not from Source.Version, which the rpm catalogers
// set to the binary's own EVR because the matcher compares source-keyed
// advisories at it. The two differ whenever a binary is versioned apart from
// its source: device-mapper-libs 1.02.181 is built from lvm2 2.03.14, and
// Red Hat's statement names lvm2@2.03.14-15.el8_10?arch=src.
//
// The file name carries no epoch, so the document's epoch is compared with
// the binary's, a missing one on either side reading as 0 (syft writes
// epoch=0 where the rpmdb holds an explicit zero). An epoch the source and
// binary do not share therefore errs toward reporting. With no SOURCERPM the
// binary is its own source and its full EVR is compared, as before.
func rpmSourceVersions(doc pkgmeta.PURL, s subject) (want, got string) {
	docEpoch := rpmEpoch(doc.Qualifiers["epoch"])
	srpm := s.pkg.Upstream
	if srpm == "" {
		srpm = s.parsed.Qualifiers["upstream"]
	}
	if vr := pkgmeta.SourceRPMVersion(srpm); vr != "" {
		binEpoch := s.parsed.Qualifiers["epoch"]
		if e, _, ok := strings.Cut(s.pkg.Version, ":"); ok {
			binEpoch = e
		}
		return docEpoch + ":" + doc.Version, rpmEpoch(binEpoch) + ":" + vr
	}
	want = doc.Version
	if docEpoch != "0" {
		want = docEpoch + ":" + want
	}
	got = s.pkg.Source.Version
	if got == "" {
		got = s.pkg.Version
	}
	return want, got
}

// rpmEpoch spells an absent epoch as the zero it means.
func rpmEpoch(e string) string {
	if e == "" {
		return "0"
	}
	return e
}

// purlPatternMatches implements the doc-purl-as-pattern rule (D104): type,
// namespace and name compare exactly; a version-less doc purl matches every
// version (and reports so, via versionless, for the reason string); a
// versioned doc purl against a version-less package purl never matches
// (there is nothing to compare); every doc qualifier must be present with an
// equal value on the package purl, but the package purl may carry extra
// qualifiers the doc says nothing about (one-directional subset, not set
// equality). Subpath is not part of pkgmeta.PURL at all — ParsePURL discards
// it during parsing — so two purls differing only in #subpath compare equal
// here, which row 19 of the rules table asserts is the intended behavior,
// not an oversight.
//
// D121 relaxes two comparisons, each to a spelling the same package already
// has: the namespace compares case-insensitively for apk, deb and rpm
// (syft's own ELF-note cataloger writes pkg:deb/Debian/…), and qualifiers go
// through qualifierMatches, where an rpm epoch of 0 equals no epoch and an
// Ubuntu package's distro also answers to the release codename.
func purlPatternMatches(doc, pkg pkgmeta.PURL, codename string) (matched, versionless bool) {
	if doc.Type != pkg.Type || !namespaceEqual(doc.Type, doc.Namespace, pkg.Namespace) || doc.Name != pkg.Name {
		return false, false
	}
	versionless = doc.Version == ""
	if !versionless {
		if pkg.Version == "" || doc.Version != pkg.Version {
			return false, false
		}
	}
	for k, v := range doc.Qualifiers {
		if !qualifierMatches(pkg, k, v, codename) {
			return false, false
		}
	}
	return true, versionless
}

// namespaceEqual compares purl namespaces: case-insensitively for the three
// distro types (D121), where the namespace is a vendor name some producers
// capitalise, and exactly for everything else, where it can be a
// case-sensitive Go module path or Maven group.
func namespaceEqual(typ, a, b string) bool {
	switch typ {
	case "apk", "deb", "rpm":
		return strings.EqualFold(a, b)
	}
	return a == b
}

// qualifierMatches reports whether the package purl satisfies one document
// qualifier. Two equivalences, both D121's:
//   - rpm epoch: absent and "0" are the same epoch. syft writes epoch=0 when
//     the rpmdb holds an explicit zero; the rpmdb cataloger does not.
//   - Ubuntu distro: a deb purl in the ubuntu namespace also answers to
//     distro=<VERSION_CODENAME>, Canonical's own spelling (distro=jammy).
func qualifierMatches(pkg pkgmeta.PURL, k, v, codename string) bool {
	got, ok := pkg.Qualifiers[k]
	if ok && got == v {
		return true
	}
	if pkg.Type == "rpm" && k == "epoch" && v == "0" && (!ok || got == "") {
		return true
	}
	if k == "distro" && codename != "" && v == codename &&
		pkg.Type == "deb" && strings.EqualFold(pkg.Namespace, "ubuntu") {
		return true
	}
	return false
}

// vulnerabilityMatches tests a statement's vulnerability identity — its
// name, @id and every alias — against EVERY member of the finding's own
// Identifiers, case-insensitively. EqualFold rather than go-vex's
// case-sensitive comparison is a deliberate divergence (D104's rules doc):
// this project already treats identifiers case-insensitively everywhere else
// (internal/ignore's identifierMatches), and advisory IDs are not
// consistently cased across sources. Name-only would miss the common
// Chainguard shape where the name is a CGA id and the CVE lives only in
// aliases — this checks all three fields against all of Identifiers, not
// just name against the advisory's own ID.
func vulnerabilityMatches(v Vulnerability, identifiers []string) bool {
	names := make([]string, 0, 2+len(v.Aliases))
	if v.Name != "" {
		names = append(names, v.Name)
	}
	if v.ID != "" {
		names = append(names, v.ID)
	}
	names = append(names, v.Aliases...)
	for _, want := range names {
		if want == "" {
			continue
		}
		for _, id := range identifiers {
			if strings.EqualFold(want, id) {
				return true
			}
		}
	}
	return false
}

// liveStatement is one Statement that survived per-statement validation,
// with its products pre-resolved (buildLiveProduct) and its effective
// ordering timestamp resolved (statement timestamp, else document
// timestamp, else zero — resolveTimestamp's own doc comment).
type liveStatement struct {
	// index is the statement's position in Document.Statements, for Apply's
	// count of statements that matched nothing.
	index     int
	stmt      Statement
	products  []liveProduct
	timestamp time.Time
	// author and docID are copied off the owning Document (not carried by
	// Statement itself — OpenVEX has no per-statement author) so reasonFor
	// can build a self-contained reason string from a liveStatement alone.
	author string
	docID  string
	// suppresses is false for a valid, recognized "affected" or
	// "under_investigation" statement — it still enters the
	// latest-statement-wins precedence contest in resolve (rows 25-27), it
	// simply never wins by suppressing anything when it wins. Without this,
	// an "affected" statement dated AFTER a "fixed" one would be dropped
	// entirely here rather than beating it, and the finding would stay
	// wrongly suppressed by the stale "fixed" statement — the exact
	// staleness bug D104's rules call out grype for.
	suppresses bool
}

// liveStatements validates every statement in d once, warning about and
// dropping exactly the ones D104's rules refuse to honour, and resolves the
// rest into liveStatement. This runs once per Apply call, not once per
// finding — a document with 500 statements and 500 findings must produce a
// bounded number of warnings, not 250,000.
func (d *Document) liveStatements(target Target, warn func(string)) ([]liveStatement, Stats) {
	live := make([]liveStatement, 0, len(d.Statements))
	stats := Stats{Statements: len(d.Statements)}
	for i, s := range d.Statements {
		label := statementLabel(s)

		if len(s.Products) == 0 {
			// Row 24. Unlike an encapsulating attestation's product
			// inheritance (which assay has no equivalent of — package-as-
			// product is the only path), a product-less statement here names
			// nothing to suppress and is refused rather than treated as
			// "applies to everything".
			warn(fmt.Sprintf("vex statement %s names no product and is skipped", label))
			stats.Skipped++
			continue
		}

		var suppresses bool
		switch s.Status {
		case "not_affected":
			if s.Justification == "" && s.ImpactStatement == "" {
				// Row 2: assay's reasonless-waiver-refused discipline (D102)
				// applied per-statement — the rest of the document still
				// stands, only this statement is skipped.
				warn(fmt.Sprintf("vex statement %s is not_affected with neither justification nor impact_statement and is skipped", label))
				stats.Skipped++
				continue
			}
			if s.Justification != "" && !justificationEnum[s.Justification] {
				// Row 4: still suppresses — it IS a stated reason — but the
				// value is outside OpenVEX's own five-entry enum, worth
				// flagging as non-standard rather than silently accepted.
				warn(fmt.Sprintf("vex statement %s: justification %q is not one of OpenVEX's standard values", label, s.Justification))
			}
			suppresses = true
		case "fixed":
			// Row 5: no justification required — Chainguard's own feed is
			// fixed-only, and D104's rules are explicit this must not be
			// held to not_affected's reason requirement.
			suppresses = true
		case "affected", "under_investigation":
			// Rows 6/7: a real, recognized status, never a suppression on
			// its own — there is no annotate/augment path (D104's rules are
			// explicit: the finding is reported normally when THIS
			// statement wins). It still becomes live (suppresses stays
			// false) rather than being dropped here, precisely so it can
			// win the precedence contest below against an earlier
			// suppressing statement (rows 25-27's liveStatement.suppresses
			// doc comment).
		default:
			// Row 8: an unrecognized status string ("resolved", "NotAffected",
			// "not affected") must never silently equal not_affected — that
			// would suppress something the document never actually said was
			// safe.
			warn(fmt.Sprintf("vex statement %s has unrecognized status %q and is skipped", label, s.Status))
			stats.Skipped++
			continue
		}

		var (
			products []liveProduct
			scoped   bool // the statement names at least one image
			inScope  bool // and one of them is the target
		)
		for _, p := range s.Products {
			if lp, ok := buildLiveProduct(p, warn); ok {
				products = append(products, lp)
				if lp.image != nil {
					scoped = true
					inScope = inScope || lp.image.matches(target)
				}
			}
		}
		// D121. A statement that names an image speaks for that image as a
		// whole — every product it lists, top-level or subcomponent, is
		// read as "in this image". Docker Hardened Images' documents list
		// each package under the image AND again as a bare, version-less
		// top-level product; applied without this, a DHI statement that its
		// own build mitigates libgssapi-krb5-2 suppresses that package on a
		// stock Debian image. Scoping only the subcomponents would not stop
		// it, because the bare duplicates name no image. Not warned per
		// statement — a DHI document holds thousands — but counted, and the
		// caller's summary line says how many.
		if scoped && !inScope {
			stats.OutOfScope++
			continue
		}
		// A statement whose every product purl was unparseable ends up with
		// zero live products here — it simply matches nothing, which is
		// already exactly right (row 33's "never a wildcard") without a
		// second check.

		ts, hasTS := s.Timestamp, s.HasTimestamp
		if !hasTS {
			if d.HasTimestamp {
				// Row 28: inherits the document's own timestamp for ordering.
				ts, hasTS = d.Timestamp, true
			} else {
				// Row 29: neither carries one. Zero time, which — by
				// resolve's ordering rule below — loses every timestamp
				// contest it enters rather than crashing or winning by
				// default.
				warn(fmt.Sprintf("vex statement %s has no timestamp of its own and the document carries none either; it loses any precedence contest with a dated statement", label))
			}
		}

		live = append(live, liveStatement{
			index: i, stmt: s, products: products, timestamp: ts,
			author: d.Author, docID: d.ID, suppresses: suppresses,
		})
	}
	return live, stats
}

// resolve finds the statement (if any) that exonerates f, applying
// latest-statement-wins precedence across every live statement that matches
// both f's vulnerability identity and its package purl (rows 25-27). Equal
// timestamps break toward the LAST statement in document order — see the
// loop's own comment for how scanning forward makes that fall out for free.
//
// grype instead keeps the FIRST/earliest matching statement it sees, which
// D104's rules call out by name as a bug, not a precedent: a real feed's
// later statement is the vendor's most current judgment, and losing to an
// earlier, superseded one would let it silently un-suppress nothing while
// reporting a finding a vendor has since said is not_affected — or the
// inverse, keep something suppressed a vendor has since retracted.
//
// matched[i] is set for every statement i whose vulnerability and product
// both match f, whether or not it wins — Apply's count of statements that
// matched nothing reads it.
func resolve(live []liveStatement, f matcher.Finding, target Target, matched []bool) (result, bool) {
	pkgPURL := f.Package.PURL
	pkgParsed, pkgErr := pkgmeta.ParsePURL(pkgPURL)
	s := subject{
		raw: pkgPURL, parsed: pkgParsed, ok: pkgPURL != "" && pkgErr == nil,
		pkg: f.Package, codename: target.UbuntuCodename,
	}

	var (
		best     liveStatement
		bestVL   bool
		bestVia  string
		haveBest bool
	)
	for _, ls := range live {
		if !vulnerabilityMatches(ls.stmt.Vulnerability, f.Identifiers) {
			continue
		}
		var (
			hit         bool
			versionless bool
			via         string
		)
		for _, p := range ls.products {
			if m, vl, v := p.matches(s); m {
				hit, versionless, via = true, vl, v
				break
			}
		}
		if !hit {
			continue
		}
		matched[ls.index] = true
		// live is built and walked in document order (liveStatements never
		// reorders), so "not before" rather than strictly "after" is what
		// makes an equal-timestamp statement overwrite the earlier one —
		// last in document order wins the tie (row 27) as a direct
		// consequence of scanning forward, with no separate Order
		// comparison needed.
		if !haveBest || !ls.timestamp.Before(best.timestamp) {
			best, bestVL, bestVia, haveBest = ls, versionless, via, true
		}
	}
	// The winning statement may be a valid "affected"/"under_investigation"
	// one that out-dated an earlier suppressing statement (rows 25-27) — it
	// won the contest, but liveStatement.suppresses says it never exonerates
	// anything, so the finding is reported normally rather than through a
	// stale suppression.
	if !haveBest || !best.suppresses {
		return result{}, false
	}
	return result{reason: reasonFor(best, bestVL, bestVia)}, true
}

// result carries what resolve found, kept separate from liveStatement itself
// so reasonFor's formatting concern stays out of the matching loop above.
type result struct {
	reason string
}

// statementLabel names a statement for a warning message: its vulnerability
// identity if it has one, else its position, so a reader can find the
// offending statement in the document without assay re-emitting the whole
// JSON block.
func statementLabel(s Statement) string {
	switch {
	case s.Vulnerability.Name != "":
		return fmt.Sprintf("%d (%s)", s.Order, s.Vulnerability.Name)
	case s.Vulnerability.ID != "":
		return fmt.Sprintf("%d (%s)", s.Order, s.Vulnerability.ID)
	default:
		return fmt.Sprintf("%d", s.Order)
	}
}
