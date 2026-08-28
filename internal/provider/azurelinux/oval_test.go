package azurelinux

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// ovalBuilder assembles a plain (uncompressed) OVAL document for parseOVAL,
// the same role oracle_test.go's own ovalBuilder plays for that package --
// but flatter, because neither live file this provider reads ever needs a
// platform-major criterion, an arch branch or a module gate (see oval.go's
// own doc comments for the 2026-08-28 measurements behind that).
type ovalBuilder struct {
	n                            int
	testsXML, objsXML, statesXML []string
}

func (o *ovalBuilder) id(kind string) string {
	o.n++
	return fmt.Sprintf("oval:com.microsoft.test:%s:%d", kind, o.n)
}

// criterion registers an rpminfo_test/_object/_state trio for one (pkg, op,
// evr) fact and returns the <criterion> XML that resolves to it -- the one
// join shape every real criterion in both live files takes.
func (o *ovalBuilder) criterion(pkg, op, evr string) string {
	tst, obj, ste := o.id("tst"), o.id("obj"), o.id("ste")
	o.testsXML = append(o.testsXML, fmt.Sprintf(
		`<rpminfo_test id=%q><object object_ref=%q/><state state_ref=%q/></rpminfo_test>`, tst, obj, ste))
	o.objsXML = append(o.objsXML, fmt.Sprintf(`<rpminfo_object id=%q><name>%s</name></rpminfo_object>`, obj, pkg))
	o.statesXML = append(o.statesXML, fmt.Sprintf(
		`<rpminfo_state id=%q><evr datatype="evr_string" operation=%q>%s</evr></rpminfo_state>`, ste, op, evr))
	return fmt.Sprintf(`<criterion test_ref=%q/>`, tst)
}

func (o *ovalBuilder) fixedCriterion(pkg, evr string) string {
	return o.criterion(pkg, "less than", evr)
}
func (o *ovalBuilder) lastAffectedCriterion(pkg, evr string) string {
	return o.criterion(pkg, "less than or equal", evr)
}
func (o *ovalBuilder) introducedCriterion(pkg, evr string) string {
	return o.criterion(pkg, "greater than", evr)
}

// nonPackageCriterion returns a <criterion> whose test_ref resolves to a
// state carrying no <evr> at all -- classifyCriterion's own "informational,
// not a package fact" case (an arch or signature test in the real archive;
// none measured here, since neither file has one, but resolveCriteria must
// still ignore one gracefully rather than erroring).
func (o *ovalBuilder) nonPackageCriterion() string {
	tst, obj, ste := o.id("tst"), o.id("obj"), o.id("ste")
	o.testsXML = append(o.testsXML, fmt.Sprintf(
		`<rpminfo_test id=%q><object object_ref=%q/><state state_ref=%q/></rpminfo_test>`, tst, obj, ste))
	o.objsXML = append(o.objsXML, fmt.Sprintf(`<rpminfo_object id=%q><name>irrelevant</name></rpminfo_object>`, obj))
	o.statesXML = append(o.statesXML, fmt.Sprintf(`<rpminfo_state id=%q><arch operation="pattern match">x86_64</arch></rpminfo_state>`, ste))
	return fmt.Sprintf(`<criterion test_ref=%q/>`, tst)
}

// definitionXML renders one <definition>, defaulting patchable to "true" and
// severity to "Medium" when the caller passes "" -- most rows below only
// care about one non-default field.
func definitionXML(advisoryID, title, cve, patchable, severity, criteriaInner string) string {
	if patchable == "" {
		patchable = "true"
	}
	if severity == "" {
		severity = "Medium"
	}
	return fmt.Sprintf(
		`<definition class="vulnerability"><metadata><title>%s</title>`+
			`<reference ref_id=%q source="CVE"/><patchable>%s</patchable>`+
			`<advisory_id>%s</advisory_id><severity>%s</severity></metadata>`+
			`<criteria operator="AND">%s</criteria></definition>`,
		title, cve, patchable, advisoryID, severity, criteriaInner)
}

func (o *ovalBuilder) doc(timestamp string, defsXML ...string) string {
	return fmt.Sprintf(
		`<oval_definitions><generator><oval:timestamp>%s</oval:timestamp></generator>`+
			`<definitions>%s</definitions><tests>%s</tests><objects>%s</objects><states>%s</states></oval_definitions>`,
		timestamp, strings.Join(defsXML, ""), strings.Join(o.testsXML, ""), strings.Join(o.objsXML, ""), strings.Join(o.statesXML, ""))
}

func findAdvisory(advs []advisory.Advisory, id string) (advisory.Advisory, bool) {
	for _, a := range advs {
		if a.ID == id {
			return a, true
		}
	}
	return advisory.Advisory{}, false
}

// TestParseOVAL_FixedBoundNoIntroduced is the baseline shape (7,202 of
// azurelinux-3.0-oval.xml's 7,268 definitions, measured 2026-08-28): one
// criterion, operation "less than", no explicit introduced bound.
func TestParseOVAL_FixedBoundNoIntroduced(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixedCriterion("python-webob", "0:1.8.11-1.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("97575", "python-webob fix", "CVE-2026-54770", "", "Medium", crit))

	var st stats
	advs, asOf, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	a, ok := findAdvisory(advs, "AZURELINUX-3-97575")
	if !ok {
		t.Fatalf("no advisory AZURELINUX-3-97575 among %+v", advs)
	}
	if a.Database != databaseName || a.Source != SourceName {
		t.Errorf("Database/Source = %q/%q, want %q/%q", a.Database, a.Source, databaseName, SourceName)
	}
	if len(a.Aliases) != 1 || a.Aliases[0] != "CVE-2026-54770" {
		t.Errorf("Aliases = %v, want [CVE-2026-54770] -- D25 grouping reads ID+Aliases, not Upstream", a.Aliases)
	}
	if len(a.Affected) != 1 {
		t.Fatalf("Affected = %+v, want exactly one entry", a.Affected)
	}
	aff := a.Affected[0]
	if aff.Ecosystem != "Azure Linux:3" || aff.Name != "python-webob" {
		t.Errorf("Affected = %+v, want Azure Linux:3/python-webob", aff)
	}
	if len(aff.Ranges) != 1 || len(aff.Ranges[0].Events) != 2 {
		t.Fatalf("Ranges = %+v, want one range with two events", aff.Ranges)
	}
	ev := aff.Ranges[0].Events
	if ev[0].Introduced != "0" {
		t.Errorf("Introduced = %q, want the implicit \"0\"", ev[0].Introduced)
	}
	if ev[1].Fixed != "0:1.8.11-1.azl3" {
		t.Errorf("Fixed = %q, want 0:1.8.11-1.azl3 (verbatim, epoch and dist tag kept)", ev[1].Fixed)
	}
	if aff.Ranges[0].FixState != "" {
		t.Errorf("FixState = %q, want unset for a fixed range", aff.Ranges[0].FixState)
	}
	if len(a.Severity) != 1 || a.Severity[0] != (advisory.Severity{Type: "VENDOR_WORD", Score: "Medium"}) {
		t.Errorf("Severity = %+v, want one VENDOR_WORD Medium entry", a.Severity)
	}
	wantAsOf := time.Date(2026, 8, 27, 13, 7, 55, 105138033, time.UTC)
	if !asOf.Equal(wantAsOf) {
		t.Errorf("asOf = %v, want %v (the generator's own timestamp, D12)", asOf, wantAsOf)
	}
}

// TestParseOVAL_RealIntroducedBound pins the 66-of-7,268 (azurelinux-3.0)
// shape: two sibling criteria under one definition, "greater than" (real
// lower bound) and "less than" (fixed), both about the SAME package -- the
// golang 1.25.x/1.26.x-track shape the package doc comment measures.
func TestParseOVAL_RealIntroducedBound(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixedCriterion("golang", "0:1.26.5-1.azl3") + o.introducedCriterion("golang", "0:1.85.0.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("92312-2", "golang fix", "CVE-2026-42505", "", "High", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	a, ok := findAdvisory(advs, "AZURELINUX-3-92312-2")
	if !ok {
		t.Fatalf("no advisory AZURELINUX-3-92312-2 among %+v", advs)
	}
	ev := a.Affected[0].Ranges[0].Events
	if len(ev) != 2 || ev[0].Introduced != "0:1.85.0.azl3" || ev[1].Fixed != "0:1.26.5-1.azl3" {
		t.Errorf("Events = %+v, want [Introduced:0:1.85.0.azl3 Fixed:0:1.26.5-1.azl3]", ev)
	}
}

// TestParseOVAL_TwoDefinitionsShareOneCVEBothSurvive is the direct proof for
// the package doc comment's central design claim: two <definition>s that
// name the SAME CVE (golang's two parallel tracks) must both survive as
// independent Advisory records with DISTINCT ids, not collide or get
// ambiguity-dropped the way Oracle's kernel-uek facts would. Deleting the
// release-scoped advisoryID from Advisory.ID (going back to a bare
// "AZURELINUX-"+cve) would make the second emit silently overwrite the
// first at the store's by-id bucket -- this test does not reach the store,
// but it does prove parseOVAL itself hands back two distinct records rather
// than one, which is the precondition for that not happening.
func TestParseOVAL_TwoDefinitionsShareOneCVEBothSurvive(t *testing.T) {
	o := &ovalBuilder{}
	def1 := definitionXML("92306-1", "golang fix (1.25 track)", "CVE-2026-42505", "", "Medium",
		o.fixedCriterion("golang", "0:1.25.12-1.azl3"))
	def2 := definitionXML("92312-2", "golang fix (1.26 track)", "CVE-2026-42505", "", "Medium",
		o.fixedCriterion("golang", "0:1.26.5-1.azl3"))
	doc := o.doc("2026-08-27T13:07:55.105138033Z", def1, def2)

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 2 {
		t.Fatalf("parseOVAL emitted %d advisories, want 2 (one per definition): %+v", len(advs), advs)
	}
	a1, ok1 := findAdvisory(advs, "AZURELINUX-3-92306-1")
	a2, ok2 := findAdvisory(advs, "AZURELINUX-3-92312-2")
	if !ok1 || !ok2 {
		t.Fatalf("want both AZURELINUX-3-92306-1 and AZURELINUX-3-92312-2 among %+v", advs)
	}
	if a1.Aliases[0] != "CVE-2026-42505" || a2.Aliases[0] != "CVE-2026-42505" {
		t.Errorf("both records must alias the shared CVE for D25 grouping to recombine them at match time: %+v / %+v", a1.Aliases, a2.Aliases)
	}
}

// TestParseOVAL_LastAffectedPatchableFalseStampsNotFixed pins
// cbl-mariner-2.0-oval.xml's own shape (106 of 5,406 measured 2026-08-28): a
// single "less than or equal" criterion (OSV last_affected, inclusive) with
// no fixed bound, paired with <patchable>false</patchable> -- the vendor's
// own positive evidence (D52) that no fix exists yet.
func TestParseOVAL_LastAffectedPatchableFalseStampsNotFixed(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.lastAffectedCriterion("pesign", "0:0.112-32.cm2")
	doc := o.doc("2026-05-06T13:07:20.548723963Z",
		definitionXML("13293", "pesign no patch", "CVE-2022-3560", "false", "Medium", crit))

	var st stats
	advs, _, err := parseOVAL("2", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	a, ok := findAdvisory(advs, "AZURELINUX-2-13293")
	if !ok {
		t.Fatalf("no advisory AZURELINUX-2-13293 among %+v", advs)
	}
	rng := a.Affected[0].Ranges[0]
	if len(rng.Events) != 2 || rng.Events[1].LastAffected != "0:0.112-32.cm2" || rng.Events[1].Fixed != "" {
		t.Errorf("Events = %+v, want a LastAffected event and no Fixed event", rng.Events)
	}
	if rng.FixState != advisory.FixStateNotFixed {
		t.Errorf("FixState = %q, want %q (D52: patchable=false is positive evidence)", rng.FixState, advisory.FixStateNotFixed)
	}
	if st.StampedNotFixed != 1 {
		t.Errorf("stats.StampedNotFixed = %d, want 1", st.StampedNotFixed)
	}
}

// TestParseOVAL_NotApplicableIsDroppedLikeWithdrawn is deliverable D's own
// proof: Microsoft's <patchable>Not Applicable</patchable> ("This CVE either
// no longer is or was never applicable") is this feed's equivalent of OSV's
// `withdrawn` field, and D16 says a retracted record is dropped AT
// INGESTION so no later lookup path can forget the check. Two definitions in
// one document -- one Not Applicable, one ordinary -- so the assertion
// cannot pass by there being nothing to drop.
func TestParseOVAL_NotApplicableIsDroppedLikeWithdrawn(t *testing.T) {
	o := &ovalBuilder{}
	gone := definitionXML("13832", "syslinux no longer applicable", "CVE-2022-3857", "Not Applicable", "Medium",
		o.lastAffectedCriterion("syslinux", "0:6.04-10.cm2"))
	keep := definitionXML("81615", "terraform fix", "CVE-2026-32287", "true", "High",
		o.fixedCriterion("terraform", "0:1.3.2-30.cm2"))
	doc := o.doc("2026-05-06T13:07:20.548723963Z", gone, keep)

	var st stats
	advs, _, err := parseOVAL("2", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 1 || advs[0].ID != "AZURELINUX-2-81615" {
		t.Fatalf("parseOVAL emitted %+v, want only AZURELINUX-2-81615 -- the Not Applicable "+
			"record must be dropped at ingestion (D16), not merely unmatched", advs)
	}
	if st.SkippedNotApplicable != 1 {
		t.Errorf("stats.SkippedNotApplicable = %d, want 1", st.SkippedNotApplicable)
	}
}

// TestParseOVAL_UnrecognizedSeverityWordIsCountedNotStored is D17's
// discipline applied to a word this codebase's vendorSeverityWords table has
// never seen: never coerced to a band, never stored as an opaque entry
// severity.Of would fail to score silently -- counted instead so a
// genuinely new fifth word is visible in the fetch summary.
func TestParseOVAL_UnrecognizedSeverityWordIsCountedNotStored(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixedCriterion("foo", "0:1.0-1.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "foo fix", "CVE-2026-1", "", "Negligible", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	a, ok := findAdvisory(advs, "AZURELINUX-3-1")
	if !ok {
		t.Fatalf("no advisory AZURELINUX-3-1 among %+v", advs)
	}
	if len(a.Severity) != 0 {
		t.Errorf("Severity = %+v, want empty -- \"Negligible\" is not a recognized word", a.Severity)
	}
	if st.UnrecognizedSeverity != 1 {
		t.Errorf("stats.UnrecognizedSeverity = %d, want 1", st.UnrecognizedSeverity)
	}
}

// TestParseOVAL_NoCVEReferenceIsSkipped is defensive (0 measured live): every
// real definition carries exactly one CVE reference, but a definition
// without one has nothing D3's Aliases-based join could ever reach, so it
// must not be stored silently unratable.
func TestParseOVAL_NoCVEReferenceIsSkipped(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixedCriterion("foo", "0:1.0-1.azl3")
	def := fmt.Sprintf(
		`<definition class="vulnerability"><metadata><title>foo fix</title>`+
			`<patchable>true</patchable><advisory_id>1</advisory_id><severity>Medium</severity></metadata>`+
			`<criteria operator="AND">%s</criteria></definition>`, crit)
	doc := o.doc("2026-08-27T13:07:55.105138033Z", def)

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("parseOVAL emitted %+v, want none: no CVE reference to join on", advs)
	}
	if st.SkippedNoCVE != 1 {
		t.Errorf("stats.SkippedNoCVE = %d, want 1", st.SkippedNoCVE)
	}
}

// TestParseOVAL_NoAdvisoryIDIsSkipped is defensive (0 measured live): every
// real definition carries a non-empty <advisory_id>, which is the sole
// source of Advisory.ID's uniqueness (see the package doc comment on why a
// bare CVE cannot be the id). A definition without one has nothing safe to
// build an id from, so it is dropped rather than risking a collision.
func TestParseOVAL_NoAdvisoryIDIsSkipped(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixedCriterion("foo", "0:1.0-1.azl3")
	def := fmt.Sprintf(
		`<definition class="vulnerability"><metadata><title>foo fix</title>`+
			`<reference ref_id="CVE-2026-1" source="CVE"/><patchable>true</patchable>`+
			`<severity>Medium</severity></metadata>`+
			`<criteria operator="AND">%s</criteria></definition>`, crit)
	doc := o.doc("2026-08-27T13:07:55.105138033Z", def)

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("parseOVAL emitted %+v, want none: no advisory_id to build an id from", advs)
	}
	if st.SkippedNoAdvisoryID != 1 {
		t.Errorf("stats.SkippedNoAdvisoryID = %d, want 1", st.SkippedNoAdvisoryID)
	}
}

// TestParseOVAL_NoResolvablePackageIsSkipped is defensive (0 measured live):
// a definition whose only criterion resolves to a non-package fact (the
// nonPackageCriterion shape) never names a package at all, so there is
// nothing for Affected.Name to be.
func TestParseOVAL_NoResolvablePackageIsSkipped(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.nonPackageCriterion()
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "nothing resolvable", "CVE-2026-1", "", "Medium", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("parseOVAL emitted %+v, want none: no criterion resolved a package", advs)
	}
	if st.SkippedNoPackage != 1 {
		t.Errorf("stats.SkippedNoPackage = %d, want 1", st.SkippedNoPackage)
	}
}

// TestParseOVAL_IntroducedOnlyIsSkipped is defensive (0 measured live): a
// definition whose sole criterion is a "greater than" (introduced) bound,
// with no "less than"/"less than or equal" sibling, resolves a package but
// has no usable upper bound at all -- neither fixed nor last-affected --
// so there is nothing sound to report a package as vulnerable UNTIL.
func TestParseOVAL_IntroducedOnlyIsSkipped(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.introducedCriterion("foo", "0:1.0-1.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "introduced only", "CVE-2026-1", "", "Medium", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("parseOVAL emitted %+v, want none: no fixed/last-affected bound", advs)
	}
	if st.SkippedNoUsableBound != 1 {
		t.Errorf("stats.SkippedNoUsableBound = %d, want 1", st.SkippedNoUsableBound)
	}
}

// TestParseOVAL_UnrecognizedOperationIsCounted is defensive (0 measured
// live): an <evr operation="..."> outside the three this provider
// recognizes must be counted rather than silently misread as one of them --
// mistaking, say, a future "equal" operation for "less than" would store a
// fixed bound that is actually an exact-match test.
func TestParseOVAL_UnrecognizedOperationIsCounted(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.criterion("foo", "equal", "0:1.0-1.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "odd operation", "CVE-2026-1", "", "Medium", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	// The package resolves (the criterion's object still names "foo"), but
	// neither fixed nor last-affected was set, so the definition is still
	// dropped -- via the SAME no-usable-bound path, on top of the
	// unrecognized-operation count.
	if len(advs) != 0 {
		t.Fatalf("parseOVAL emitted %+v, want none", advs)
	}
	if st.UnrecognizedOperation != 1 {
		t.Errorf("stats.UnrecognizedOperation = %d, want 1", st.UnrecognizedOperation)
	}
}

// TestParseOVAL_BadDefinitionDocIsCountedBeforeTheOverallFailure is defensive
// (0 measured live): a <definition> subtree with a raw XML syntax error (an
// unescaped "&") is caught by DecodeElement itself and counted in
// SkippedBadDoc -- but, unlike a semantic mismatch, a raw syntax error
// leaves the underlying decoder unable to find its place again (verified
// experimentally: the very next Token() call returns the same syntax
// error), so the overall parseOVAL call still fails. This is the honest
// behavior to pin, not a false claim that one bad definition is silently
// skipped while the rest of a real multi-thousand-definition file parses
// cleanly around it.
func TestParseOVAL_BadDefinitionDocIsCountedBeforeTheOverallFailure(t *testing.T) {
	raw := `<oval_definitions><generator><oval:timestamp>2026-08-27T13:07:55.105138033Z</oval:timestamp></generator>` +
		`<definitions><definition class="vulnerability"><metadata><title>&</title></metadata></definition></definitions>` +
		`<tests></tests><objects></objects><states></states></oval_definitions>`

	var st stats
	_, _, err := parseOVAL("3", strings.NewReader(raw), &st)
	if err == nil {
		t.Fatal("parseOVAL: no error for a document with a raw XML syntax error, want one")
	}
	if st.SkippedBadDoc != 1 {
		t.Errorf("stats.SkippedBadDoc = %d, want 1 -- the bad definition must still be counted "+
			"before the poisoned stream fails the overall parse", st.SkippedBadDoc)
	}
}

// TestParseOVAL_MismatchedPackageNamesIsSkipped is defensive (0 measured
// live): if a future definition's two sibling criteria ever named two
// DIFFERENT packages, this provider has no sound way to say which bound
// belongs to which, and D25's "never resolve a tie by arrival order"
// applies just as much to "which of two package names is the real one" as
// it does to which of two fixed versions is.
func TestParseOVAL_MismatchedPackageNamesIsSkipped(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixedCriterion("pkg-a", "0:1.0-1.azl3") + o.introducedCriterion("pkg-b", "0:0.9-1.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "mismatched", "CVE-2026-1", "", "Medium", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	if len(advs) != 0 {
		t.Fatalf("parseOVAL emitted %+v, want none: criteria named two different packages", advs)
	}
	if st.SkippedMixedPackageNames != 1 {
		t.Errorf("stats.SkippedMixedPackageNames = %d, want 1", st.SkippedMixedPackageNames)
	}
}

// TestParseOVAL_NonPackageCriterionIsIgnored proves a criterion resolving to
// a state with no <evr> (an arch or signature test in the real archive; 0
// measured here, but structurally possible) is ignored rather than treated
// as a package fact -- the definition still resolves from its OTHER,
// genuine fix criterion.
func TestParseOVAL_NonPackageCriterionIsIgnored(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.nonPackageCriterion() + o.fixedCriterion("foo", "0:1.0-1.azl3")
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "foo fix", "CVE-2026-1", "", "Medium", crit))

	var st stats
	advs, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	a, ok := findAdvisory(advs, "AZURELINUX-3-1")
	if !ok {
		t.Fatalf("no advisory AZURELINUX-3-1 among %+v", advs)
	}
	if a.Affected[0].Name != "foo" {
		t.Errorf("Affected[0].Name = %q, want foo", a.Affected[0].Name)
	}
}

// TestParseOVAL_ZeroDefinitionsIsAnError is the shape-change guard: a
// document with no <definition> elements at all (a different root element,
// an HTML error page served as if it were the file) must fail loudly rather
// than build a database with silent zero coverage.
func TestParseOVAL_ZeroDefinitionsIsAnError(t *testing.T) {
	o := &ovalBuilder{}
	doc := o.doc("2026-08-27T13:07:55.105138033Z")

	var st stats
	_, _, err := parseOVAL("3", strings.NewReader(doc), &st)
	if err == nil {
		t.Fatal("parseOVAL: no error for a document with zero <definition> elements")
	}
}

// TestParseOVAL_MalformedXMLIsAnError distinguishes a transport-level
// failure (TestFetch_HTTPErrorPropagates in azurelinux_test.go) from a
// 200 response whose body is not valid XML at all.
func TestParseOVAL_MalformedXMLIsAnError(t *testing.T) {
	var st stats
	_, _, err := parseOVAL("3", strings.NewReader("<not-xml"), &st)
	if err == nil {
		t.Fatal("parseOVAL: no error for malformed XML")
	}
}
