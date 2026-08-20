package oracle

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// This file is assay's first OVAL parser (D74). OVAL 5.11 splits one
// definition's evidence across four pools -- <definitions>, <tests>,
// <objects>, <states> -- joined by id, and Oracle's archive lays them out in
// that order: the whole <definitions> block (about 46% of the decompressed
// 252 MB, measured 2026-08-19) comes before a single <tests>/<objects>/
// <states> entry exists to join against. So this cannot resolve a definition
// as it is read; every definition is buffered with its raw criteria tree
// until the stream ends, and only then walked against the now-complete
// tests/objects/states maps. That buffering is what also makes the
// cross-definition UEK check (below) affordable: the whole corpus already
// has to be resident to be resolved at all, so indexing it a second way costs
// nothing new.

// rawDefinitionXML is the subset of one <definition> this provider reads.
// Only rpminfo_test/_object/_state are ever joined against (see
// classifyCriterion) -- a module-gate criterion's test_ref points at a
// textfilecontent54_test, which this parser never builds a map for, so it
// falls through as informational rather than being specially excluded. That
// is deliberate: Oracle's real module ambiguity (two streams of one module
// fixing the same package at two different versions within one definition)
// is not filtered by name, it is caught the same way the UEK trains are --
// as two distinct fixed EVRs for one package under one key, which
// dropAmbiguous below drops regardless of what gated either branch.
type rawDefinitionXML struct {
	Metadata struct {
		Title      string `xml:"title"`
		References []struct {
			Source string `xml:"source,attr"`
			RefID  string `xml:"ref_id,attr"`
		} `xml:"reference"`
		Advisory struct {
			Severity string `xml:"severity"`
			CVEs     []struct {
				Text  string `xml:",chardata"`
				CVSS3 string `xml:"cvss3,attr"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria rawCriteria `xml:"criteria"`
}

// rawCriteria is one node of the AND/OR tree. Operator is read but never
// branches this parser's walk: an OR node's alternatives (two arches, two
// module streams, two kernel-uek trains) legitimately contribute the SAME
// fact when they agree and a genuinely DIFFERENT one when they do not, and
// "different fact for the same package under the same key" is exactly the
// signal dropAmbiguous exists to catch. Treating AND and OR alike is what
// makes that catch general rather than special-cased to kernel-uek by name.
type rawCriteria struct {
	Operator  string         `xml:"operator,attr"`
	Criterion []rawCriterion `xml:"criterion"`
	Criteria  []rawCriteria  `xml:"criteria"`
}

type rawCriterion struct {
	TestRef string `xml:"test_ref,attr"`
}

// rawTest is one <rpminfo_test>. Every other test type in the archive
// (textfilecontent54_test for "Module X is enabled", family_test, ...) is
// read as plain tokens and never reaches this struct, so a criterion
// referencing one simply fails the map lookup in classifyCriterion and is
// treated as informational.
type rawTest struct {
	ID     string `xml:"id,attr"`
	Object struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type rawObjectXML struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

// rawState is one <rpminfo_state>. Which child element is populated is what
// tells apart a platform-major test ("Oracle Linux 9 is installed", <version>
// pattern-matched against the "oraclelinux-release" object), a package's
// fixed-EVR test (<evr>, "is earlier than"), an arch test (<arch>) and a
// signing test (<signature_keyid>) -- there is no other structural marker,
// and Oracle's own criterion COMMENT text ("... is earlier than ...") is
// deliberately not what this parser reads: the design calls for a real join
// against tests/objects/states, not a regex over prose that happens to be
// present today.
type rawState struct {
	ID      string      `xml:"id,attr"`
	Version *rawOpValue `xml:"version"`
	Arch    *rawOpValue `xml:"arch"`
	EVR     *rawOpValue `xml:"evr"`
	SigKey  *rawOpValue `xml:"signature_keyid"`
}

type rawOpValue struct {
	Operation string `xml:"operation,attr"`
	Text      string `xml:",chardata"`
}

type rawGenerator struct {
	Timestamp string `xml:"timestamp"`
}

// resolvedDef is one <definition>'s metadata plus the result of walking its
// criteria tree: which package is fixed at which EVR, under which Oracle
// Linux major. perMajor[major][pkgName] is a SET rather than a single string
// because the whole point of building it this way is to let more than one
// distinct EVR land there when the data disagrees with itself -- that set's
// size is what dropAmbiguous inspects.
type resolvedDef struct {
	id           string // "ELSA-2026-55857" or "ELBA-..."
	database     string // "ELSA" or "ELBA" (databaseOf(id))
	title        string
	cves         []string          // Related, deduped, first-seen order
	cvssByCVE    map[string]string // CVE -> "CVSS:3.1/..." vector string
	severityWord string            // raw upstream word, e.g. "IMPORTANT"
	perMajor     map[int]map[string]map[string]bool
}

// stats counts what one parse discarded or found ambiguous, so a sync can
// report it -- the same discipline redhat.stats and amazon.stats exist for
// (both packages' own doc comments): a provider that silently drops part of
// its input looks exactly like one that is broken.
type stats struct {
	Definitions           int // raw <definition> elements seen, decodable or not
	SkippedBadDoc         int // a <definition> that would not decode at all
	SkippedNoID           int // no non-CVE reference to read an ELSA/ELBA id from
	SkippedNoPackages     int // every package this definition named was dropped
	UnrecognizedSeverity  int // a severity word outside IMPORTANT/MODERATE/LOW/CRITICAL (e.g. "N/A")
	NoMajorContext        int // a package-fix criterion with no platform guard above it anywhere in the tree
	SkippedLineageFixes   int // a fixed EVR carrying a Ksplice or FIPS lineage marker, dropped before ambiguity grouping (D79)
	AmbiguousGroups       int // distinct (CVE-or-ELSA, major, package) groups with 2+ fixed EVRs
	SkippedAmbiguousFixes int // individual Affected entries dropped because of an AmbiguousGroups hit
	Advisories            int // advisory.Advisory records emitted
	Affected              int // Affected entries emitted across all of them
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d definitions -> %d advisories, %d affected entries; skipped %d unreadable, "+
			"%d with no ELSA/ELBA id, %d left with no packages after the UEK/module guard; "+
			"%d advisories carried an unrecognized severity word; "+
			"%d package-fix criteria had no platform guard above them (skipped); "+
			"%d lineage (ksplice/fips) fixed versions dropped (D79); "+
			"UEK/module-train guard: %d ambiguous (CVE, major, package) group(s), "+
			"%d affected entr(y/ies) dropped for it",
		s.Definitions, s.Advisories, s.Affected, s.SkippedBadDoc,
		s.SkippedNoID, s.SkippedNoPackages, s.UnrecognizedSeverity, s.NoMajorContext,
		s.SkippedLineageFixes,
		s.AmbiguousGroups, s.SkippedAmbiguousFixes)
}

// parseOVAL streams r (already bzip2-decompressed) and returns every
// definition it could resolve, plus the archive's own generation timestamp
// (D12: freshness is measured from the upstream data). It is the only
// exported entry point besides normalize, deliberately split from Fetch so
// the criteria-walk edge cases can be driven with a plain XML string in
// oval_test.go -- no bzip2 involved at all for those.
func parseOVAL(r io.Reader, st *stats) ([]resolvedDef, time.Time, error) {
	dec := xml.NewDecoder(r)

	var rawDefs []rawDefinitionXML
	tests := map[string]rawTest{}
	objects := map[string]string{} // id -> name
	states := map[string]rawState{}
	var asOf time.Time

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("oracle: decode OVAL stream: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "definition":
			st.Definitions++
			var raw rawDefinitionXML
			if err := dec.DecodeElement(&raw, &se); err != nil {
				st.SkippedBadDoc++
				continue
			}
			rawDefs = append(rawDefs, raw)
		case "rpminfo_test":
			var raw rawTest
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			tests[raw.ID] = raw
		case "rpminfo_object":
			var raw rawObjectXML
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			objects[raw.ID] = raw.Name
		case "rpminfo_state":
			var raw rawState
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			states[raw.ID] = raw
		case "generator":
			var raw rawGenerator
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			if t, err := time.Parse("2006-01-02T15:04:05", raw.Timestamp); err == nil {
				asOf = t.UTC()
			}
		}
	}

	// The zero-definitions guard: an archive that parses to no <definition>
	// elements at all means the feed's shape changed (a different root
	// element, an HTML error page served as if it were the archive) --
	// silently building an empty-of-Oracle database would answer every OL
	// scan with "no advisories for this ecosystem", indistinguishable from
	// clean.
	if st.Definitions == 0 {
		return nil, time.Time{}, fmt.Errorf(
			"oracle: OVAL stream carries zero <definition> elements; the feed's shape may have changed")
	}

	defs := make([]resolvedDef, 0, len(rawDefs))
	for _, raw := range rawDefs {
		d, ok := buildDefinition(raw, st)
		if !ok {
			continue
		}
		d.perMajor = map[int]map[string]map[string]bool{}
		walkCriteria(raw.Criteria, 0, tests, objects, states, d.perMajor, st)
		defs = append(defs, d)
	}
	return defs, asOf, nil
}

// buildDefinition reads the metadata half of one <definition>: its own
// ELSA/ELBA id, the CVEs it references, and its two severity signals (a
// CVSS v3 vector per CVE when present, and the vendor's own word always).
// It does not touch criteria at all.
func buildDefinition(raw rawDefinitionXML, st *stats) (resolvedDef, bool) {
	var id string
	var cves []string
	seenCVE := map[string]bool{}
	for _, ref := range raw.Metadata.References {
		if strings.EqualFold(ref.Source, "CVE") {
			if ref.RefID != "" && !seenCVE[ref.RefID] {
				seenCVE[ref.RefID] = true
				cves = append(cves, ref.RefID)
			}
			continue
		}
		// The definition's own advisory id: source="elsa" on a security
		// advisory, source="elba" on a bug-fix one (6 of 9,796 measured
		// 2026-08-19) -- matched by "not CVE" rather than an exact spelling
		// so a third prefix Oracle starts using later (there is no reason to
		// expect only two) is still read rather than silently dropped.
		if id == "" && ref.RefID != "" {
			id = ref.RefID
		}
	}
	if id == "" {
		st.SkippedNoID++
		return resolvedDef{}, false
	}

	cvssByCVE := map[string]string{}
	for _, c := range raw.Metadata.Advisory.CVEs {
		cve := strings.TrimSpace(c.Text)
		// The CVSS3 emptiness check is a readability short-circuit, not a
		// guard: an empty attribute has no '/' either, so the IndexByte gate
		// below reaches the same answer. Mutating this condition survives the
		// suite for that reason -- a true equivalent, verified 2026-08-20,
		// not an untested branch.
		if cve == "" || c.CVSS3 == "" {
			continue
		}
		// The attribute is "<score>/<vector>" ("5.9/CVSS:3.1/AV:N/..."),
		// never a bare vector -- measured on all 34,513 CVSS v3 entries in
		// the 2026-08-19 archive. severity.Of wants the vector alone; the
		// score is dropped rather than kept, because severity.Of derives its
		// own score from the vector (D13) and a second, independently-read
		// number for the same fact is a value that can drift from it.
		if i := strings.IndexByte(c.CVSS3, '/'); i >= 0 {
			cvssByCVE[cve] = c.CVSS3[i+1:]
		}
	}

	return resolvedDef{
		id:           id,
		database:     databaseOf(id),
		title:        strings.TrimSpace(raw.Metadata.Title),
		cves:         cves,
		cvssByCVE:    cvssByCVE,
		severityWord: strings.TrimSpace(raw.Metadata.Advisory.Severity),
	}, true
}

// databaseOf reads the definition's own namespace off its id ("ELSA-2026-
// 55857" -> "ELSA", "ELBA-2025-20993" -> "ELBA"), the identical convention
// amazon.databaseOf uses for ALAS/ALAS2/ALAS2023 (D25).
func databaseOf(id string) string {
	i := strings.IndexByte(id, '-')
	if i <= 0 {
		return id
	}
	return id[:i]
}

// factKind is what one criterion, resolved through its test/object/state,
// turns out to assert.
type factKind int

const (
	factOther factKind = iota
	factMajor
	factPackageFix
)

// classifyCriterion resolves one criterion's test_ref against the
// tests/objects/states pools and reports what it asserts.
//
// There is no allowlist of criterion shapes to keep in sync. Whatever the
// referenced test's OBJECT and STATE turn out to be is what decides the
// answer: an <evr> child with operation "less than" is a package's
// fixed-version test regardless of what gated it, a <version> child on the
// "oraclelinux-release" object is the platform-major test, and everything
// else (arch, signature_keyid, a test_ref this parser never indexed because
// it was not an rpminfo_test) is informational. This is also why a
// module-enablement criterion needs no special case: its test_ref points at
// a textfilecontent54_test, which never enters `tests`, so the lookup below
// simply misses and the criterion is skipped -- the sibling "package is
// earlier than" criterion under the SAME module-stream branch is still an
// ordinary rpminfo_test and is read normally.
func classifyCriterion(testRef string, tests map[string]rawTest, objects map[string]string, states map[string]rawState) (kind factKind, pkgName string, major int, evr string) {
	t, ok := tests[testRef]
	if !ok {
		return factOther, "", 0, ""
	}
	s, ok := states[t.State.Ref]
	if !ok {
		return factOther, "", 0, ""
	}
	switch {
	case s.EVR != nil && s.EVR.Operation == "less than":
		name := objects[t.Object.Ref]
		if name == "" {
			return factOther, "", 0, ""
		}
		return factPackageFix, name, 0, strings.TrimSpace(s.EVR.Text)
	case s.Version != nil && objects[t.Object.Ref] == "oraclelinux-release":
		m, ok := parseMajorPattern(s.Version.Text)
		if !ok {
			return factOther, "", 0, ""
		}
		return factMajor, "", m, ""
	default:
		// Arch ("Oracle Linux arch is X"), signing ("... is signed with the
		// Oracle Linux N key"), or any other shape this provider does not
		// need. Not an error: these are real, expected parts of the tree.
		return factOther, "", 0, ""
	}
}

// parseMajorPattern reads the leading digits out of a platform-version
// state's pattern-match value ("^9" -> 9). Anchored loosely on purpose: the
// value is always a caret-anchored digit run in every definition measured
// 2026-08-19, but reading only the digits rather than requiring an exact
// "^\d+" match is what keeps a harmless format change (a trailing "$",
// whitespace) from turning into a silently-dropped major instead of a read
// one.
func parseMajorPattern(s string) (int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "^")
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

// oracleLineageMarker duplicates internal/matcher's oracleLineageMarker
// (D79) -- its own comment there has the measurement behind both shapes
// (92 distinct `.ksplice1.` EVRs, one `.ksplice2.`, 33 `_fips`-suffixed,
// every one across the full ELSA OVAL corpus 2026-08-20). This is the same
// deliberate-duplicate pattern csaf.go's isModule and matcher's
// rpmModuleBuild already use rather than importing across the
// provider/matcher boundary for one regexp. The two copies MUST stay in
// agreement: this one decides which fixed EVRs never reach the store at
// all, matcher.go's decides which installed packages get reported
// not-evaluated instead of matched -- if they drifted apart, a lineage
// package could be silently judged against a mainline bound neither
// comment says is sound.
var oracleLineageMarker = regexp.MustCompile(`(?i)\.ksplice[0-9]+\.|_fips$`)

// walkCriteria descends one <criteria> node, carrying the Oracle Linux major
// gating it (0 until a platform-major criterion is seen). It runs in two
// passes over this node's own criterion children rather than one: a
// platform-major criterion can appear anywhere among its siblings (in the
// live archive it is always first, but nothing in the schema promises that),
// and every package-fix sibling in the SAME node has to see the major
// whichever position it was declared in.
func walkCriteria(c rawCriteria, major int, tests map[string]rawTest, objects map[string]string, states map[string]rawState, perMajor map[int]map[string]map[string]bool, st *stats) {
	effMajor := major
	for _, cr := range c.Criterion {
		kind, _, m, _ := classifyCriterion(cr.TestRef, tests, objects, states)
		if kind == factMajor {
			effMajor = m
		}
	}
	for _, cr := range c.Criterion {
		kind, pkg, _, evr := classifyCriterion(cr.TestRef, tests, objects, states)
		if kind != factPackageFix || pkg == "" {
			continue
		}
		if effMajor == 0 {
			// A fixed-version criterion with no "Oracle Linux N is
			// installed" guard anywhere above it in the tree. Never
			// observed in the 2026-08-19 archive (every definition's
			// criteria root carries one), so this is a defensive counter
			// rather than an expected path -- recording the fact here
			// rather than guessing a major (D17's discipline, applied to a
			// missing gate instead of a missing severity) is what keeps a
			// future malformed definition from being silently attributed to
			// the wrong release.
			st.NoMajorContext++
			continue
		}
		if oracleLineageMarker.MatchString(evr) {
			// D79: this fixed EVR is Ksplice- or FIPS-lineage, not
			// mainline. Dropped HERE, before perMajor is built and
			// therefore before dropAmbiguous ever groups it -- a lineage
			// EVR left in would collide there with a mainline fix for the
			// same (CVE, major, package), and D74's guard drops BOTH
			// contributors of a collision, not just the lineage one
			// (measured 2026-08-20: 24.4% of everything dropAmbiguous
			// dropped was exactly this collision, openssl's entire
			// ambiguity among it). Skipping it before that grouping runs is
			// what lets the mainline entry recover. matcher.go's
			// oracleLineageOf is the other half: once this filter runs, an
			// installed lineage package has no mainline record left to be
			// judged against, so it is reported not-evaluated there instead
			// of matched here.
			st.SkippedLineageFixes++
			continue
		}
		if perMajor[effMajor] == nil {
			perMajor[effMajor] = map[string]map[string]bool{}
		}
		if perMajor[effMajor][pkg] == nil {
			perMajor[effMajor][pkg] = map[string]bool{}
		}
		perMajor[effMajor][pkg][evr] = true
	}
	for _, child := range c.Criteria {
		walkCriteria(child, effMajor, tests, objects, states, perMajor, st)
	}
}

// severityWordCanon maps Oracle's own severity word (always upper case in
// the live archive: IMPORTANT, MODERATE, LOW, CRITICAL, and 7 of 9,796
// definitions carry N/A) onto the Title-case spelling
// severity.vendorSeverityWords keys on (D71 decision 2, D72's convention).
// N/A has no entry on purpose: severity.go recognizes no "Negligible"/"N/A"
// band, and coercing it to one of the four real bands would be exactly the
// guess D17 forbids -- those 7 definitions carry no vector either (see the
// package doc comment) and band Unknown until the NVD join rates their CVE.
var severityWordCanon = map[string]string{
	"CRITICAL":  "Critical",
	"IMPORTANT": "Important",
	"MODERATE":  "Moderate",
	"LOW":       "Low",
}

func normalizeSeverityWord(s string) (string, bool) {
	canon, ok := severityWordCanon[strings.ToUpper(strings.TrimSpace(s))]
	return canon, ok
}

// severityFor builds one definition's severity entries: a CVSS_V3 entry per
// distinct vector its CVEs carry (D71 decision 2's "both, not either"), plus
// the vendor word as VENDOR_WORD when it is one of the four recognized
// bands. A v2-only definition (8,825 (def, CVE) entries measured, all
// pre-~2016) gets no synthetic vector at all -- v2's shorthand
// ("2.1/AV:L/AC:L/Au:N/C:P/I:N/A:N") is not a CVSS:3.x or CVSS:4.x string
// severity.Of can score, and inventing one was considered and rejected (D71
// decision 2's own text): its band comes from the VENDOR_WORD entry when the
// word is recognized, and otherwise from the NVD join via the CVE this
// definition already placed in Related.
func severityFor(d resolvedDef, st *stats) []advisory.Severity {
	var sev []advisory.Severity
	seen := map[string]bool{}
	for _, cve := range d.cves {
		v, ok := d.cvssByCVE[cve]
		if !ok || v == "" || seen[v] {
			continue
		}
		seen[v] = true
		sev = append(sev, advisory.Severity{Type: "CVSS_V3", Score: v})
	}
	if canon, ok := normalizeSeverityWord(d.severityWord); ok {
		sev = append(sev, advisory.Severity{Type: "VENDOR_WORD", Score: canon})
	} else if d.severityWord != "" {
		st.UnrecognizedSeverity++
	}
	return sev
}

// dropKey is one (definition, major, package) triple that the UEK/module
// guard has decided must not be emitted.
type dropKey struct {
	defIdx int
	major  int
	pkg    string
}

// ambKey groups fixed-EVR facts across every definition that shares one CVE
// (or, for the 106 definitions with no CVE at all, shares nothing but
// itself -- see the joinKeysFor comment). It is scoped to one Oracle Linux
// major and one package name because kernel-uek accumulates a fixed EVR for
// EVERY CVE it has ever patched; without the CVE in the key, "how many
// distinct EVRs has kernel-uek ever had on OL9" would be answered "hundreds"
// and every kernel-uek entry in the database would be dropped.
type ambKey struct {
	join  string
	major int
	pkg   string
}

// joinKeysFor is what dropAmbiguous groups a definition's own facts under.
// Ordinarily its CVE list: two ELSAs that both patch kernel-uek for
// CVE-2018-1000204 on OL9, at two different trains' EVRs, are exactly the
// measured hazard (857 OL8 / 817 OL9 (CVE, platform) groups, 2026-08-19) and
// only meet each other in the index if they share this key. A definition
// with no CVE reference at all (106 measured) falls back to its own id, so
// it still gets the intra-definition half of the same check -- two branches
// of ITS OWN criteria tree naming the same package at two different EVRs
// under one major -- without ever colliding with an unrelated definition
// that also happens to have no CVE.
func joinKeysFor(d resolvedDef) []string {
	if len(d.cves) > 0 {
		return d.cves
	}
	return []string{d.id}
}

// dropAmbiguous finds every (join key, major, package) that resolves to more
// than one distinct fixed EVR across the whole corpus, and returns which
// (definition, major, package) triples contributed to one -- every
// contributor is dropped, not just the second one seen, because arrival
// order says nothing about which train a real host is on (D25's "never
// resolve a tie by arrival order", applied here to a tie this provider
// cannot break at all rather than one D25 breaks by score).
func dropAmbiguous(defs []resolvedDef, st *stats) map[dropKey]bool {
	evrsOf := map[ambKey]map[string]bool{}
	contributorsOf := map[ambKey]map[int]bool{}
	for di, d := range defs {
		for _, join := range joinKeysFor(d) {
			for major, pkgs := range d.perMajor {
				for pkg, evrSet := range pkgs {
					k := ambKey{join, major, pkg}
					if evrsOf[k] == nil {
						evrsOf[k] = map[string]bool{}
					}
					for evr := range evrSet {
						evrsOf[k][evr] = true
					}
					if contributorsOf[k] == nil {
						contributorsOf[k] = map[int]bool{}
					}
					contributorsOf[k][di] = true
				}
			}
		}
	}

	dropped := map[dropKey]bool{}
	for k, evrSet := range evrsOf {
		if len(evrSet) <= 1 {
			continue
		}
		st.AmbiguousGroups++
		for di := range contributorsOf[k] {
			dropped[dropKey{di, k.major, k.pkg}] = true
		}
	}
	return dropped
}

// normalize turns every resolved definition into advisory.Advisory records,
// one per (definition, major) that still has at least one package left after
// dropAmbiguous -- the shape D74 calls for so each record's Affected list is
// homogeneous in ecosystem, the same property every other provider's
// single-Advisory-per-record shape gets for free.
func normalize(defs []resolvedDef, st *stats) []advisory.Advisory {
	dropped := dropAmbiguous(defs, st)

	var out []advisory.Advisory
	for di, d := range defs {
		sev := severityFor(d, st)
		majors := make([]int, 0, len(d.perMajor))
		for m := range d.perMajor {
			majors = append(majors, m)
		}
		sort.Ints(majors)

		for _, major := range majors {
			pkgNames := make([]string, 0, len(d.perMajor[major]))
			for name := range d.perMajor[major] {
				pkgNames = append(pkgNames, name)
			}
			sort.Strings(pkgNames)

			var affected []advisory.Affected
			for _, name := range pkgNames {
				if dropped[dropKey{di, major, name}] {
					st.SkippedAmbiguousFixes++
					continue
				}
				evrSet := d.perMajor[major][name]
				// dropAmbiguous already removed every (def, major, pkg)
				// whose evrSet had more than one member (whether that
				// ambiguity came from this definition alone or from another
				// one sharing a CVE), so exactly one is left to take here.
				var evr string
				for e := range evrSet {
					evr = e
					break
				}
				affected = append(affected, advisory.Affected{
					Ecosystem: "Oracle Linux:" + strconv.Itoa(major),
					Name:      name,
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: evr},
						},
					}},
				})
			}
			if len(affected) == 0 {
				st.SkippedNoPackages++
				continue
			}
			out = append(out, advisory.Advisory{
				ID:       d.id,
				Database: d.database,
				Related:  d.cves,
				Source:   SourceName,
				Kind:     advisory.KindVulnerability,
				Summary:  d.title,
				Severity: sev,
				Affected: affected,
			})
			st.Advisories++
			st.Affected += len(affected)
		}
	}
	return out
}
