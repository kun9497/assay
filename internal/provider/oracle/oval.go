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
// rpminfo_test/_object/_state are joined against for platform-major and
// package-fix facts (see classifyCriterion); textfilecontent54_test/_object/
// _state are joined against separately (D81, moduleGateStream) for the
// "Module X:Y is enabled" gates that scope a fix to one RPM module stream --
// a second, parallel join over the same tests/objects/states pools, keyed by
// a disjoint set of ids and never confused with the rpminfo ones because
// classifyCriterion and moduleGateStream each look the test_ref up in their
// own map only.
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
// fact when they agree and a genuinely DIFFERENT one when they do not.
// Before D81, "different fact for the same package under the same key" was
// always the signal dropAmbiguous exists to catch, module streams included.
// D81 narrows that for streams specifically: two streams' fixes are no
// longer a collision at all (they are stored as separate Affected entries,
// each scoped to its own stream), so dropAmbiguous's guard now only fires
// within one stream, or across facts this parser still cannot tell apart
// (kernel-uek's trains, arch disagreements that are actually errors). AND
// and OR are still treated alike for reaching that guard -- module streams
// just resolve cleanly before it runs, rather than being caught by it.
type rawCriteria struct {
	Operator  string         `xml:"operator,attr"`
	Criterion []rawCriterion `xml:"criterion"`
	Criteria  []rawCriteria  `xml:"criteria"`
}

// rawCriterion carries its own comment text (D81) alongside the test_ref
// every criterion already had. Comment is read for every criterion, not
// just module gates -- there is no cheap way to know in advance which
// criterion is a gate before resolving test_ref against the textfilecontent54
// pool -- but it is only ever LOOKED at for the ones moduleGateStream
// resolves as a gate; an arch or platform criterion's comment is decoded and
// ignored, same as its unread structured fields already are.
type rawCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

// rawTest is one <rpminfo_test>. Every other test type in the archive
// (family_test, ...) besides rpminfo_test and textfilecontent54_test (D81)
// is read as plain tokens and never reaches a struct at all, so a criterion
// referencing one simply fails both maps' lookups and is treated as
// informational.
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
// deliberately not what this parser reads for THESE facts: the design calls
// for a real join against tests/objects/states, not a regex over prose that
// happens to be present today. Module gates are the one place a comment IS
// read (D81, moduleGateStream) -- and even there only as a cross-check
// against the same structural join, never as the sole source.
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

// rawTFC54Test is one <textfilecontent54_test> -- the OVAL shape a "Module
// X:Y is enabled" gate takes (D81). It carries the same object_ref/state_ref
// join shape as rawTest, but is indexed separately (tfcTests, not tests) so
// a criterion's test_ref is checked against exactly one of the two pools:
// classifyCriterion never sees a module gate, and moduleGateStream never
// sees a platform/package/arch test. Both structural halves of the gate ride
// on this join: the object's filepath names the module ("/etc/dnf/modules.d/
// nodejs.module"), the state's pattern-match text carries the stream
// ("stream\s*=\s*24\b...").
type rawTFC54Test struct {
	ID     string `xml:"id,attr"`
	Object struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

// rawTFC54Object is one <textfilecontent54_object>. Only Filepath is read --
// datatype, pattern and instance siblings exist in the real archive but name
// nothing this provider needs (D81 measured every one of the 763 gates'
// filepath basenames agreeing with its own comment's module name).
type rawTFC54Object struct {
	ID       string `xml:"id,attr"`
	Filepath string `xml:"filepath"`
}

// rawTFC54State is one <textfilecontent54_state>. Text is the state's own
// pattern-match value -- a regex the real OVAL engine evaluates against the
// module file's contents, spelled out as a literal string here (its own
// backslashes are ordinary characters in this struct field, not Go escapes;
// they only mean anything as regex syntax to moduleStreamFromStateText,
// which is the only reader of this field).
type rawTFC54State struct {
	ID   string `xml:"id,attr"`
	Text string `xml:"text"`
}

// resolvedDef is one <definition>'s metadata plus the result of walking its
// criteria tree: which package is fixed at which EVR, under which Oracle
// Linux major and (D81) which module stream, if any.
// perMajor[major][pkgName][moduleStream] is a SET of EVRs, not a single
// string, for the same reason it always was -- letting more than one
// distinct EVR land there is what lets dropAmbiguous see a genuine
// disagreement. moduleStream is "" for an ordinary, non-modular fix; D81
// adds this fourth level so two DIFFERENT streams of one module fixing the
// same package under the same major are two separate sets rather than one
// set dropAmbiguous would see as self-contradictory.
type resolvedDef struct {
	id           string // "ELSA-2026-55857" or "ELBA-..."
	database     string // "ELSA" or "ELBA" (databaseOf(id))
	title        string
	cves         []string          // Related, deduped, first-seen order
	cvssByCVE    map[string]string // CVE -> "CVSS:3.1/..." vector string
	severityWord string            // raw upstream word, e.g. "IMPORTANT"
	perMajor     map[int]map[string]map[string]map[string]bool
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
	AmbiguousGroups       int // distinct (CVE-or-ELSA, major, package, stream) groups with 2+ fixed EVRs (D81 adds stream)
	SkippedAmbiguousFixes int // individual Affected entries dropped because of an AmbiguousGroups hit
	Advisories            int // advisory.Advisory records emitted
	Affected              int // Affected entries emitted across all of them

	// D81: module stream gating.
	ModuleGatedFixesKept              int // Affected entries emitted carrying a non-empty ModuleStream
	DistinctModuleStreams             int // distinct "name:stream" values among ModuleGatedFixesKept
	UngatedModuleFixes                int // distinct, stored (definition, major, package) Affected entries whose EVR is module+el/module_el but stream-less: no in-scope gate resolved a stream for it (150 measured 2026-08-20, deduplicated -- an arch-branch fanout hitting the same fact twice is not double-counted here, unlike SkippedLineageFixes/NoMajorContext above)
	ModuleGateExtractionDisagreements int // a gate whose comment and structural extraction both succeeded but named a different (name, stream); structural kept (0 measured 2026-08-20)
	ModuleGateUnresolved              int // a gate resolved (test_ref hit textfilecontent54_test) but neither comment nor structural extraction could read a (name, stream) from it (0 measured 2026-08-20)
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d definitions -> %d advisories, %d affected entries; skipped %d unreadable, "+
			"%d with no ELSA/ELBA id, %d left with no packages after the UEK/module guard; "+
			"%d advisories carried an unrecognized severity word; "+
			"%d package-fix criteria had no platform guard above them (skipped); "+
			"%d lineage (ksplice/fips) fixed versions dropped (D79); "+
			"UEK/module-train guard: %d ambiguous (CVE, major, package, stream) group(s), "+
			"%d affected entr(y/ies) dropped for it; "+
			"module streams (D81): %d gated fix(es) kept across %d distinct stream(s), "+
			"%d module-tagged fixed version(s) stored stream-less for lack of a resolvable gate, "+
			"%d gate(s) where comment and structural extraction disagreed (structural kept), "+
			"%d gate(s) resolved but unparseable either way",
		s.Definitions, s.Advisories, s.Affected, s.SkippedBadDoc,
		s.SkippedNoID, s.SkippedNoPackages, s.UnrecognizedSeverity, s.NoMajorContext,
		s.SkippedLineageFixes,
		s.AmbiguousGroups, s.SkippedAmbiguousFixes,
		s.ModuleGatedFixesKept, s.DistinctModuleStreams,
		s.UngatedModuleFixes, s.ModuleGateExtractionDisagreements, s.ModuleGateUnresolved)
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
	// D81's second join pool, parallel to tests/objects/states above and
	// never sharing an id with them in the live archive (textfilecontent54_*
	// and rpminfo_* mint ids from disjoint counters). tfcObjects and
	// tfcStates are pre-flattened to the one field each is ever read for
	// (filepath, pattern text) rather than kept as raw structs, the same
	// choice `objects` already makes for rpminfo_object's <name>.
	tfcTests := map[string]rawTFC54Test{}
	tfcObjects := map[string]string{} // id -> filepath
	tfcStates := map[string]string{}  // id -> pattern-match text
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
		case "textfilecontent54_test":
			var raw rawTFC54Test
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			tfcTests[raw.ID] = raw
		case "textfilecontent54_object":
			var raw rawTFC54Object
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			tfcObjects[raw.ID] = raw.Filepath
		case "textfilecontent54_state":
			var raw rawTFC54State
			if err := dec.DecodeElement(&raw, &se); err != nil {
				continue
			}
			tfcStates[raw.ID] = raw.Text
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
		d.perMajor = map[int]map[string]map[string]map[string]bool{}
		walkCriteria(raw.Criteria, 0, "", tests, objects, states, tfcTests, tfcObjects, tfcStates, d.perMajor, st)
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
// it was not an rpminfo_test) is informational. A module-enablement
// criterion's test_ref points at a textfilecontent54_test, which never
// enters `tests` at all, so the lookup below simply misses and this function
// reports factOther for it -- moduleGateStream is what resolves it, against
// the SEPARATE tfcTests/tfcObjects/tfcStates pools (D81), and walkCriteria
// calls both on every criterion rather than either function trying to cover
// the other's pool.
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

// isModuleBuildEVR duplicates internal/matcher's rpmModuleBuild (D80) for
// the same reason oracleLineageMarker above duplicates matcher's lineage
// regexp: this package cannot import the matcher package, and the two
// spellings ("module+el" Red Hat/Rocky, "module_el" AlmaLinux -- Oracle
// itself only ever measured the first, D81's 38,998 gated hits are all
// "module+el") are cheap enough to keep in sync by comment rather than by
// import. Used here only to decide whether a stream-less fixed EVR is an
// ordinary mainline package (nothing to count) or a module build this
// parser could not attach a stream to (st.UngatedModuleFixes).
func isModuleBuildEVR(evr string) bool {
	return strings.Contains(evr, "module+el") || strings.Contains(evr, "module_el")
}

// moduleGateCommentRe matches a module-enablement criterion's own comment,
// "Module <name>:<stream> is enabled" -- the exact text on all 763 gates
// measured against the full archive 2026-08-20.
var moduleGateCommentRe = regexp.MustCompile(`^Module (\S+) is enabled$`)

// moduleStreamFromComment reads (name, stream) out of a criterion's own
// comment text. The name:stream pair is split at the FIRST ':' rather than
// requiring exactly one -- no module name in the corpus contains a colon,
// but a stream that legitimately did (none measured) should still parse
// instead of silently failing into "no gate".
func moduleStreamFromComment(comment string) (name, stream string, ok bool) {
	m := moduleGateCommentRe.FindStringSubmatch(comment)
	if m == nil {
		return "", "", false
	}
	name, stream, cut := strings.Cut(m[1], ":")
	if !cut || name == "" || stream == "" {
		return "", "", false
	}
	return name, stream, true
}

// moduleStreamPattern reads the stream token out of a textfilecontent54_state's
// own pattern-match TEXT -- itself a regex, spelled out literally
// ("\nstream\s*=\s*24\b[\w\W]*..."), not evaluated as one. This pattern
// therefore matches against the LITERAL backslash-letter sequences that
// text contains: `\\s` and `\*` below match the two literal characters
// `\` and `s`, `\` and `*`, exactly as they sit in the source string,
// stopping the (non-greedy) capture at the literal `\b` every measured
// state text uses to close the token. moduleStreamFromStateText then
// unescapes any backslash-escaped regex metacharacter the captured token
// itself carries (only "\." is measured -- "1\.4" for stream "1.4").
var moduleStreamPattern = regexp.MustCompile(`stream\\s\*=\\s\*(.+?)\\b`)

// unescapeRegexLiteral drops the backslash out of any backslash-escaped
// character in s ("1\.4" -> "1.4", "kvm_utils3" unchanged -- no backslash to
// drop). Generic rather than special-cased to '.' on purpose: '.' is the
// only escape measured in the 763-gate archive, but QuoteMeta-style escaping
// can legally produce others, and a stream captured with one still in it
// would silently fail to match Package.ModuleStream's un-escaped spelling
// downstream in the matcher.
func unescapeRegexLiteral(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// moduleStreamFromStateText resolves the structural half of a module gate:
// the stream token captured out of the state's own pattern-match text.
func moduleStreamFromStateText(text string) (stream string, ok bool) {
	m := moduleStreamPattern.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	stream = unescapeRegexLiteral(m[1])
	if stream == "" {
		return "", false
	}
	return stream, true
}

// moduleNameFromFilepath resolves the other structural half: the module
// name out of the gate object's own filepath ("/etc/dnf/modules.d/
// nodejs.module" -> "nodejs"), basename minus the fixed ".module" suffix
// every gate object measured 2026-08-20 carries.
func moduleNameFromFilepath(fp string) (name string, ok bool) {
	const suffix = ".module"
	base := fp
	if i := strings.LastIndexByte(fp, '/'); i >= 0 {
		base = fp[i+1:]
	}
	if !strings.HasSuffix(base, suffix) {
		return "", false
	}
	name = strings.TrimSuffix(base, suffix)
	if name == "" {
		return "", false
	}
	return name, true
}

// moduleGateStream resolves ONE criterion as a module-enablement gate
// (D81). Whether cr IS a gate is decided the same way classifyCriterion
// decides a criterion is a package fix or a platform test: by whether its
// test_ref resolves against the pool this parser indexes for the purpose --
// here, tfcTests rather than tests. A criterion that does not resolve there
// is not a module gate (isGate=false), which covers every other criterion
// this parser reads (platform, arch, signature, package-fix) without a
// separate exclusion list.
//
// A gate that DOES resolve carries its "name:stream" two ways -- the
// criterion's own COMMENT ("Module nodejs:24 is enabled", moduleStreamFrom
// Comment) and STRUCTURALLY (the gate object's filepath basename, the gate
// state's own pattern text, moduleNameFromFilepath/moduleStreamFromStateText).
// They agreed on every one of the 763 gates measured against the full
// archive 2026-08-20. When they disagree the structural pair wins: the
// comment is prose Oracle writes for a human reader, the structural pair is
// what the fields this scanner (and, presumably, Oracle's own OVAL engine)
// actually evaluates. A gate that resolves as a gate but yields neither pair
// (0 measured) returns ok=false: its fixes fall through to the same
// stream-less path an EVR with no gate above it at all takes
// (st.UngatedModuleFixes in the caller), which is also the shape D80's
// matcher already knows how to report skipped rather than guessed.
func moduleGateStream(cr rawCriterion, tfcTests map[string]rawTFC54Test, tfcObjects map[string]string, tfcStates map[string]string, st *stats) (nameStream string, isGate bool) {
	t, ok := tfcTests[cr.TestRef]
	if !ok {
		return "", false
	}

	var structName, structStream string
	var structOK bool
	if fp, ok := tfcObjects[t.Object.Ref]; ok {
		if n, ok := moduleNameFromFilepath(fp); ok {
			if txt, ok := tfcStates[t.State.Ref]; ok {
				if s, ok := moduleStreamFromStateText(txt); ok {
					structName, structStream, structOK = n, s, true
				}
			}
		}
	}
	commentName, commentStream, commentOK := moduleStreamFromComment(cr.Comment)

	switch {
	case structOK && commentOK:
		if structName != commentName || structStream != commentStream {
			st.ModuleGateExtractionDisagreements++
		}
		return structName + ":" + structStream, true
	case structOK:
		return structName + ":" + structStream, true
	case commentOK:
		return commentName + ":" + commentStream, true
	default:
		st.ModuleGateUnresolved++
		return "", true
	}
}

// walkCriteria descends one <criteria> node, carrying the Oracle Linux major
// (D74) and module stream (D81) gating it -- major 0 and stream "" until a
// platform-major or module-gate criterion is seen. It runs in two passes
// over this node's own criterion children rather than one: a platform-major
// or module-gate criterion can appear anywhere among its siblings (in the
// live archive the platform one is always first; module gates always
// precede their fix sibling, but nothing in the schema promises either
// position), and every package-fix sibling in the SAME node has to see both
// whichever position they were declared in.
//
// D81 measured zero nested gates and exactly one module in scope per gated
// fix hit, so propagation needs no more machinery than effMajor already
// has: a sibling OR branch's own gate (or absence of one) only ever affects
// that branch's own subtree, because each recursive call below carries its
// own local effModule downward and siblings never share a stack frame's
// mutation.
func walkCriteria(c rawCriteria, major int, moduleStream string, tests map[string]rawTest, objects map[string]string, states map[string]rawState, tfcTests map[string]rawTFC54Test, tfcObjects map[string]string, tfcStates map[string]string, perMajor map[int]map[string]map[string]map[string]bool, st *stats) {
	effMajor := major
	effModule := moduleStream
	for _, cr := range c.Criterion {
		kind, _, m, _ := classifyCriterion(cr.TestRef, tests, objects, states)
		if kind == factMajor {
			effMajor = m
		}
		if ns, isGate := moduleGateStream(cr, tfcTests, tfcObjects, tfcStates, st); isGate {
			effModule = ns
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
			// same (CVE, major, package[, stream]), and D74's guard drops
			// BOTH contributors of a collision, not just the lineage one
			// (measured 2026-08-20: 24.4% of everything dropAmbiguous
			// dropped was exactly this collision, openssl's entire
			// ambiguity among it). Skipping it before that grouping runs is
			// what lets the mainline entry recover. matcher.go's
			// oracleLineageOf is the other half: once this filter runs, an
			// installed lineage package has no mainline record left to be
			// judged against, so it is reported not-evaluated there instead
			// of matched here. This check runs BEFORE the module-stream
			// attachment below, unchanged from pre-D81 order (D81's own
			// requirement: the lineage count must not move, 12,174 on the
			// live feed).
			st.SkippedLineageFixes++
			continue
		}
		// D81: stream is attached here, but whether it ends up "" for lack
		// of a gate is not counted at THIS granularity -- this loop runs
		// once per CRITERION (an arch-branch fanout hits the same
		// (major, pkg, evr) more than once, exactly the shape
		// TestParseOVAL_ArchBranchesAgreeingIsNotAmbiguous collapses), while
		// perMajor below dedupes into a SET. st.UngatedModuleFixes is
		// counted in normalize(), once per surviving (deduplicated) Affected
		// entry, so it answers "how many stored records", not "how many
		// criteria were seen" -- measured 2026-08-20: 290 raw criterion
		// hits collapse to exactly 150 distinct (definition, major,
		// package, evr) tuples, all four contributing definitions
		// (ELSA-2026-50239, ELSA-2020-5500, ELSA-2021-1809,
		// ELSA-2019-2925) carrying arch-duplicated fix criteria.
		stream := effModule
		if perMajor[effMajor] == nil {
			perMajor[effMajor] = map[string]map[string]map[string]bool{}
		}
		if perMajor[effMajor][pkg] == nil {
			perMajor[effMajor][pkg] = map[string]map[string]bool{}
		}
		if perMajor[effMajor][pkg][stream] == nil {
			perMajor[effMajor][pkg][stream] = map[string]bool{}
		}
		perMajor[effMajor][pkg][stream][evr] = true
	}
	for _, child := range c.Criteria {
		walkCriteria(child, effMajor, effModule, tests, objects, states, tfcTests, tfcObjects, tfcStates, perMajor, st)
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

// dropKey is one (definition, major, package, stream) quadruple that the
// UEK/module guard has decided must not be emitted. D81 adds stream so
// dropping one stream's ambiguous fix for a package never also drops a
// DIFFERENT, unambiguous stream's fix for the same package under the same
// definition and major -- structurally possible even though 0 were measured
// mixing that way (D81's own "zero nested gates" count is about gate
// NESTING, not about whether one definition can gate the same package under
// two different streams in two OR branches, which the intra-definition
// recovery test below shows it can).
type dropKey struct {
	defIdx int
	major  int
	pkg    string
	stream string
}

// ambKey groups fixed-EVR facts across every definition that shares one CVE
// (or, for the 106 definitions with no CVE at all, shares nothing but
// itself -- see the joinKeysFor comment). It is scoped to one Oracle Linux
// major, one package name, and (D81) one module stream, because kernel-uek
// accumulates a fixed EVR for EVERY CVE it has ever patched (without the CVE
// in the key, "how many distinct EVRs has kernel-uek ever had on OL9" would
// be answered "hundreds") and because two module streams of one package are
// never the same fix timeline (D80's own refusal to compare across streams,
// applied here to which EVRs are even allowed to collide in the first
// place): "nodejs:18" and "nodejs:20" fixing the same CVE at different EVRs
// is not a disagreement to catch, it is two vendors' worth of correct
// information, and grouping them under one key would drop both for no
// reason.
type ambKey struct {
	join   string
	major  int
	pkg    string
	stream string
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

// dropAmbiguous finds every (join key, major, package, stream) that resolves
// to more than one distinct fixed EVR across the whole corpus, and returns
// which (definition, major, package, stream) quadruples contributed to one
// -- every contributor is dropped, not just the second one seen, because
// arrival order says nothing about which train (or, D81, which module
// stream) a real host is on (D25's "never resolve a tie by arrival order",
// applied here to a tie this provider cannot break at all rather than one
// D25 breaks by score).
func dropAmbiguous(defs []resolvedDef, st *stats) map[dropKey]bool {
	evrsOf := map[ambKey]map[string]bool{}
	contributorsOf := map[ambKey]map[int]bool{}
	for di, d := range defs {
		for _, join := range joinKeysFor(d) {
			for major, pkgs := range d.perMajor {
				for pkg, streams := range pkgs {
					for stream, evrSet := range streams {
						k := ambKey{join, major, pkg, stream}
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
	}

	dropped := map[dropKey]bool{}
	for k, evrSet := range evrsOf {
		if len(evrSet) <= 1 {
			continue
		}
		st.AmbiguousGroups++
		for di := range contributorsOf[k] {
			dropped[dropKey{di, k.major, k.pkg, k.stream}] = true
		}
	}
	return dropped
}

// normalize turns every resolved definition into advisory.Advisory records,
// one per (definition, major) that still has at least one package left after
// dropAmbiguous -- the shape D74 calls for so each record's Affected list is
// homogeneous in ecosystem, the same property every other provider's
// single-Advisory-per-record shape gets for free. D81 adds a per-stream
// inner loop: one (definition, major, package) can now contribute MORE than
// one Affected entry, one per surviving module stream (plus a stream-less
// one when the package has an ordinary, non-modular fix too, though 0 were
// measured mixing that way) -- each carries its own ModuleStream, the shape
// Red Hat's csaf.go already emits for the identical reason (D80).
func normalize(defs []resolvedDef, st *stats) []advisory.Advisory {
	dropped := dropAmbiguous(defs, st)
	streamsSeen := map[string]bool{}

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
				streamsOf := d.perMajor[major][name]
				streamKeys := make([]string, 0, len(streamsOf))
				for stream := range streamsOf {
					streamKeys = append(streamKeys, stream)
				}
				sort.Strings(streamKeys)

				for _, stream := range streamKeys {
					if dropped[dropKey{di, major, name, stream}] {
						st.SkippedAmbiguousFixes++
						continue
					}
					evrSet := streamsOf[stream]
					// dropAmbiguous already removed every (def, major, pkg,
					// stream) whose evrSet had more than one member (whether
					// that ambiguity came from this definition alone or from
					// another one sharing a CVE), so exactly one is left to
					// take here.
					var evr string
					for e := range evrSet {
						evr = e
						break
					}
					aff := advisory.Affected{
						Ecosystem: "Oracle Linux:" + strconv.Itoa(major),
						Name:      name,
						Ranges: []advisory.Range{{
							Type: advisory.RangeEcosystem,
							Events: []advisory.Event{
								{Introduced: "0"},
								{Fixed: evr},
							},
						}},
					}
					if stream != "" {
						aff.ModuleStream = stream
						st.ModuleGatedFixesKept++
						streamsSeen[stream] = true
					} else if isModuleBuildEVR(evr) {
						// D81: a module-tagged EVR (its release string
						// carries "module+el"/"module_el") with no
						// in-scope module gate -- either no
						// textfilecontent54_test criterion appeared
						// anywhere above it at all (150 distinct
						// (definition, major, package, evr) tuples measured
						// 2026-08-20), or one did but moduleGateStream could
						// not read a (name, stream) from it (0 measured;
						// ModuleGateUnresolved counts that half
						// separately). Either way the stream cannot be
						// recovered from this OVAL tree, so the entry is
						// stored the same as an ordinary stream-less fix.
						// D80's matcher already reports a stream-blind
						// module bound skipped loudly at match time
						// (moduleBuildBound), the same path Rocky and
						// AlmaLinux take until D82. Counted HERE rather
						// than in walkCriteria so an arch-branch fanout
						// (the same criterion seen twice, once per arch)
						// is not double-counted -- this loop runs once per
						// SURVIVING, deduplicated Affected entry, matching
						// ModuleGatedFixesKept's own granularity just
						// above.
						st.UngatedModuleFixes++
					}
					affected = append(affected, aff)
				}
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
	st.DistinctModuleStreams = len(streamsSeen)
	return out
}
