package azurelinux

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// databaseName is every record's Advisory.Database, regardless of which of
// the two files it came from -- a single vendor namespace, the same choice
// redhat.SourceName's own "REDHAT" makes rather than fragmenting by RHEL
// major.
const databaseName = "AZURELINUX"

// notApplicablePatchable is Microsoft's own retraction signal (measured
// 2026-08-28, cbl-mariner-2.0-oval.xml only): <patchable>Not Applicable</patchable>,
// always paired with the description "This CVE either no longer is or was
// never applicable." Dropped at ingestion (D16's discipline: a vendor's own
// "this does not apply" is the same kind of fact as OSV's `withdrawn`, and
// belongs at the same place in the pipeline).
const notApplicablePatchable = "Not Applicable"

// notPatchable is the OTHER patchable value that changes what gets stored:
// <patchable>false</patchable> (measured 2026-08-28, cbl-mariner-2.0-oval.xml
// only, always paired with a last_affected-only range) is the vendor's own
// positive evidence that no fix exists yet, which is exactly what D52
// requires before a fix-less range is stamped FixState = NotFixed rather
// than left Unknown.
const notPatchable = "false"

// recognizedSeverityWords is Azure Linux's and CBL-Mariner's own severity
// vocabulary, measured 2026-08-28 across both live files: Critical, High,
// Medium, Low, and nothing else. Every one of the four already exists as a
// key in severity.vendorSeverityWords (Critical from the base RHSA set,
// Medium from Amazon Linux's own D73 entry, High from Fedora's D75 entry,
// Low from the base RHSA set too) -- this provider needs no new severity
// mapping, only a membership check so a fifth word this codebase has never
// seen is counted (stats.UnrecognizedSeverity) rather than stored as an
// opaque VENDOR_WORD severity.Of would silently fail to score.
var recognizedSeverityWords = map[string]bool{
	"Critical": true,
	"High":     true,
	"Medium":   true,
	"Low":      true,
}

// rawDefinitionXML is the subset of one <definition> this provider reads.
// Unlike Oracle's own rawDefinitionXML (internal/provider/oracle/oval.go),
// there is no <advisory severity="..."><cve cvss3="..."> block to read --
// measured 2026-08-28, neither file carries a CVSS vector anywhere -- and no
// platform-major criterion to resolve, because each file is already scoped
// to one release.
type rawDefinitionXML struct {
	Metadata struct {
		Title      string `xml:"title"`
		Patchable  string `xml:"patchable"`
		AdvisoryID string `xml:"advisory_id"`
		Severity   string `xml:"severity"`
		References []struct {
			Source string `xml:"source,attr"`
			RefID  string `xml:"ref_id,attr"`
		} `xml:"reference"`
	} `xml:"metadata"`
	Criteria rawCriteria `xml:"criteria"`
}

// rawCriteria is one node of the criteria tree. Measured 2026-08-28: every
// definition in both files is a flat `<criteria operator="AND">` with one or
// two direct `<criterion>` children and ZERO nested `<criteria>` anywhere --
// unlike Oracle's archive, there is no AND/OR branching to walk. Criteria is
// still read and recursed (walkCriteria below) rather than assumed absent,
// so a future definition that DOES nest is still resolved instead of
// silently dropped; nesting never observed live is what st.NestedCriteria
// counts, not what the parser refuses to handle.
type rawCriteria struct {
	Criterion []rawCriterion `xml:"criterion"`
	Criteria  []rawCriteria  `xml:"criteria"`
}

type rawCriterion struct {
	TestRef string `xml:"test_ref,attr"`
}

// rawTest is one <rpminfo_test>. Every definition measured resolves through
// this pool alone -- there is no second test type (no module gate, no
// platform gate) the way Oracle's D81 module-stream work needed.
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

// rawState is one <rpminfo_state>. Its <evr> child's operation attribute is
// what tells apart a fixed bound ("less than"), an inclusive last-affected
// bound ("less than or equal", cbl-mariner-2.0-oval.xml only) and a real
// introduced bound ("greater than").
type rawState struct {
	ID  string      `xml:"id,attr"`
	EVR *rawOpValue `xml:"evr"`
}

type rawOpValue struct {
	Operation string `xml:"operation,attr"`
	Text      string `xml:",chardata"`
}

type rawGenerator struct {
	Timestamp string `xml:"timestamp"`
}

// stats counts what one Fetch (both files, one shared counter -- the same
// discipline osv.stats's D82 counter and oracle.stats both follow) discarded
// or found unusual, so the fetch summary can say so rather than silently
// narrowing its input.
type stats struct {
	Definitions int // raw <definition> elements seen, decodable or not
	// SkippedBadDoc counts a <definition> whose subtree DecodeElement could
	// not decode (0 measured live). A raw XML syntax error inside one
	// definition (as opposed to a semantic mismatch, which Go's xml package
	// tolerates silently) leaves the decoder unable to find its place again
	// -- verified experimentally, the very next Token() call fails
	// identically -- so this count is diagnostic only: parseOVAL's own
	// top-level error return fails the whole call either way, and this
	// field is what a caller reading the error can also see was the last
	// thing decoded before it happened.
	SkippedBadDoc int
	Advisories    int // advisory.Advisory records emitted

	SkippedNotApplicable     int // <patchable>Not Applicable</patchable> -- vendor's own retraction (D16)
	SkippedNoCVE             int // no reference with source="CVE" (0 measured)
	SkippedNoAdvisoryID      int // empty <advisory_id> (0 measured)
	SkippedNoPackage         int // no criterion resolved a package name at all (0 measured)
	SkippedMixedPackageNames int // two criteria in one definition named different packages (0 measured)
	SkippedNoUsableBound     int // a package resolved but neither "less than" nor "less than or equal" was found (0 measured)
	UnrecognizedOperation    int // an <evr operation="..."> outside less-than/less-than-or-equal/greater-than (0 measured)
	UnrecognizedSeverity     int // a severity word outside recognizedSeverityWords (0 measured)
	NestedCriteria           int // a <criteria> found nested inside another (0 measured, see rawCriteria's own comment)
	StampedNotFixed          int // fix-less ranges stamped FixState = NotFixed from patchable=false (D52)
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d definitions -> %d advisories; skipped %d unreadable, %d not-applicable (vendor retraction), "+
			"%d with no CVE reference, %d with no advisory id, %d with no resolvable package, "+
			"%d with mismatched package names across criteria, %d with no usable fixed/last-affected bound; "+
			"%d range(s) stamped not-fixed from the vendor's own patchable=false; "+
			"%d unrecognized operation(s), %d unrecognized severity word(s), %d nested criteria node(s)",
		s.Definitions, s.Advisories, s.SkippedBadDoc, s.SkippedNotApplicable,
		s.SkippedNoCVE, s.SkippedNoAdvisoryID, s.SkippedNoPackage,
		s.SkippedMixedPackageNames, s.SkippedNoUsableBound,
		s.StampedNotFixed,
		s.UnrecognizedOperation, s.UnrecognizedSeverity, s.NestedCriteria)
}

// parseOVAL streams r (one release's OVAL document) and returns every
// advisory it could resolve, plus the document's own generator timestamp
// (D12: freshness is measured from the upstream data, not fetch time).
//
// Like oracle.parseOVAL, this cannot resolve a <definition> as it is read:
// OVAL 5.11 lays out the whole <definitions> block before a single
// <tests>/<objects>/<states> entry exists to join against (verified
// 2026-08-28 by byte offset on both live files), so every definition is
// buffered raw until the stream ends and only then walked against the
// now-complete pools.
func parseOVAL(release string, r io.Reader, st *stats) ([]advisory.Advisory, time.Time, error) {
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
			return nil, time.Time{}, fmt.Errorf(
				"decode OVAL stream (Azure Linux:%s): %w", release, err)
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
			if t, err := time.Parse(time.RFC3339Nano, raw.Timestamp); err == nil {
				asOf = t.UTC()
			}
		}
	}

	// The zero-definitions guard: an archive that parses to no <definition>
	// elements at all means the feed's shape changed (a different root
	// element, an HTML error page served as if it were the file) -- the same
	// hard-fail oracle.parseOVAL uses for the identical reason.
	if st.Definitions == 0 {
		return nil, time.Time{}, fmt.Errorf(
			"OVAL stream for Azure Linux:%s carries zero <definition> elements; "+
				"the feed's shape may have changed", release)
	}

	out := make([]advisory.Advisory, 0, len(rawDefs))
	for _, raw := range rawDefs {
		a, ok := buildAdvisory(release, raw, tests, objects, states, st)
		if !ok {
			continue
		}
		out = append(out, a)
		st.Advisories++
	}
	return out, asOf, nil
}

// buildAdvisory turns one resolved <definition> into an advisory.Advisory,
// or reports ok=false for one this provider deliberately does not store.
func buildAdvisory(release string, raw rawDefinitionXML, tests map[string]rawTest, objects map[string]string, states map[string]rawState, st *stats) (advisory.Advisory, bool) {
	if strings.TrimSpace(raw.Metadata.Patchable) == notApplicablePatchable {
		st.SkippedNotApplicable++
		return advisory.Advisory{}, false
	}

	var cve string
	for _, ref := range raw.Metadata.References {
		if strings.EqualFold(ref.Source, "CVE") && ref.RefID != "" {
			cve = ref.RefID
			break
		}
	}
	if cve == "" {
		st.SkippedNoCVE++
		return advisory.Advisory{}, false
	}

	advisoryID := strings.TrimSpace(raw.Metadata.AdvisoryID)
	if advisoryID == "" {
		st.SkippedNoAdvisoryID++
		return advisory.Advisory{}, false
	}

	pkg, introduced, fixed, lastAffected, ok := resolveCriteria(raw.Criteria, tests, objects, states, st)
	if !ok {
		return advisory.Advisory{}, false
	}
	if fixed == "" && lastAffected == "" {
		st.SkippedNoUsableBound++
		return advisory.Advisory{}, false
	}

	rng := advisory.Range{Type: advisory.RangeEcosystem}
	ev := advisory.Event{Introduced: "0"}
	if introduced != "" {
		ev.Introduced = introduced
	}
	rng.Events = append(rng.Events, ev)
	if fixed != "" {
		rng.Events = append(rng.Events, advisory.Event{Fixed: fixed})
	} else {
		rng.Events = append(rng.Events, advisory.Event{LastAffected: lastAffected})
		// D52: positive evidence required before a fix-less range is
		// stamped NotFixed rather than left Unknown -- the vendor's own
		// patchable=false ("No patch is available currently") IS that
		// evidence (measured 2026-08-28: every last_affected range in
		// cbl-mariner-2.0-oval.xml is patchable=false or Not Applicable,
		// and Not Applicable never reaches here at all).
		if strings.TrimSpace(raw.Metadata.Patchable) == notPatchable {
			rng.FixState = advisory.FixStateNotFixed
			st.StampedNotFixed++
		}
	}

	var sev []advisory.Severity
	if word := strings.TrimSpace(raw.Metadata.Severity); word != "" {
		if recognizedSeverityWords[word] {
			sev = append(sev, advisory.Severity{Type: "VENDOR_WORD", Score: word})
		} else {
			st.UnrecognizedSeverity++
		}
	}

	return advisory.Advisory{
		// D90's convention (redhat.csaf's own comment has the full
		// reasoning): a bare CVE as ID collides across records at the
		// store's by-id bucket (last-writer-wins), and here it would ALSO
		// collide within this one provider -- one CVE can span more than one
		// <definition> in the same file (see the package doc comment).
		// advisoryID is unique per definition within its own file (measured
		// 2026-08-28: 0 duplicates in either file, 0 overlap between them),
		// and the release prefix keeps that true even if a future update
		// ever reused a number across the two.
		ID:       fmt.Sprintf("AZURELINUX-%s-%s", release, advisoryID),
		Database: databaseName,
		// Aliases carries the CVE, not Upstream, following D90's own
		// reasoning byte for byte: D25 grouping (matcher.identifiers) reads
		// ID + Aliases, not Upstream, so this is what lets two definitions
		// sharing one CVE -- or an Azure Linux record and an unrelated
		// vendor's record for the same CVE -- join into a single finding.
		Aliases:  []string{cve},
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  strings.TrimSpace(raw.Metadata.Title),
		Severity: sev,
		Affected: []advisory.Affected{{
			Ecosystem: "Azure Linux:" + release,
			Name:      pkg,
			Ranges:    []advisory.Range{rng},
		}},
	}, true
}

// resolveCriteria walks a definition's criteria tree (recursing into any
// nested <criteria>, though none are measured live -- see rawCriteria's own
// comment) and resolves every <criterion> against the tests/objects/states
// pools. AND and OR are treated alike, the same choice oracle.go's own
// walkCriteria makes and for the same reason: there is nothing here that
// branches on the operator, only facts to collect, and a definition never
// mixes facts about two different packages in the live data (mismatch is
// tracked, not guessed past).
func resolveCriteria(c rawCriteria, tests map[string]rawTest, objects map[string]string, states map[string]rawState, st *stats) (pkg, introduced, fixed, lastAffected string, ok bool) {
	var mismatch bool
	var walk func(rawCriteria)
	walk = func(c rawCriteria) {
		for _, cr := range c.Criterion {
			t, tok := tests[cr.TestRef]
			if !tok {
				continue
			}
			s, sok := states[t.State.Ref]
			if !sok || s.EVR == nil {
				continue
			}
			name := objects[t.Object.Ref]
			if name == "" {
				continue
			}
			if pkg == "" {
				pkg = name
			} else if pkg != name {
				mismatch = true
			}
			val := strings.TrimSpace(s.EVR.Text)
			switch s.EVR.Operation {
			case "less than":
				fixed = val
			case "less than or equal":
				lastAffected = val
			case "greater than":
				introduced = val
			default:
				st.UnrecognizedOperation++
			}
		}
		for _, child := range c.Criteria {
			st.NestedCriteria++
			walk(child)
		}
	}
	walk(c)

	if mismatch {
		st.SkippedMixedPackageNames++
		return "", "", "", "", false
	}
	if pkg == "" {
		st.SkippedNoPackage++
		return "", "", "", "", false
	}
	return pkg, introduced, fixed, lastAffected, true
}
