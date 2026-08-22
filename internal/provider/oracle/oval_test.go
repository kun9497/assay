package oracle

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// ovalBuilder assembles a plain (uncompressed) OVAL document for parseOVAL,
// so every criteria-walk edge case below is driven with a Go string rather
// than a bzip2 fixture -- compress/bzip2 has no writer in the standard
// library (the package doc comment explains why that also shapes Fetch), so
// only the couple of tests that prove the HTTP+spool+decompress wiring
// itself (oracle_test.go) need a real .bz2 file at all.
type ovalBuilder struct {
	n         int
	testsXML  []string
	objsXML   []string
	statesXML []string
}

func (o *ovalBuilder) id(kind string) string {
	o.n++
	return fmt.Sprintf("oval:com.oracle.test:%s:%d", kind, o.n)
}

// platformCriterion returns the <criterion> XML for "Oracle Linux N is
// installed", registering the rpminfo_test/_object/_state it resolves
// through -- an object named "oraclelinux-release" whose state carries a
// <version> pattern-match, the exact shape classifyCriterion looks for.
func (o *ovalBuilder) platformCriterion(major int) string {
	tst, obj, ste := o.id("tst"), o.id("obj"), o.id("ste")
	o.testsXML = append(o.testsXML, fmt.Sprintf(
		`<rpminfo_test id=%q comment="Oracle Linux %d is installed"><object object_ref=%q/><state state_ref=%q/></rpminfo_test>`,
		tst, major, obj, ste))
	o.objsXML = append(o.objsXML, fmt.Sprintf(`<rpminfo_object id=%q><name>oraclelinux-release</name></rpminfo_object>`, obj))
	o.statesXML = append(o.statesXML, fmt.Sprintf(`<rpminfo_state id=%q><version operation="pattern match">^%d</version></rpminfo_state>`, ste, major))
	return fmt.Sprintf(`<criterion test_ref=%q comment="Oracle Linux %d is installed"/>`, tst, major)
}

// fixCriterion returns the <criterion> XML for "PKG is earlier than EVR",
// registering an rpminfo_test/_object/_state whose state carries an <evr>
// with operation "less than" -- the shape every real fixed-version test in
// the archive has (215,861/215,861 measured 2026-08-19).
func (o *ovalBuilder) fixCriterion(pkg, evr string) string {
	tst, obj, ste := o.id("tst"), o.id("obj"), o.id("ste")
	o.testsXML = append(o.testsXML, fmt.Sprintf(
		`<rpminfo_test id=%q comment="%s is earlier than %s"><object object_ref=%q/><state state_ref=%q/></rpminfo_test>`,
		tst, pkg, evr, obj, ste))
	o.objsXML = append(o.objsXML, fmt.Sprintf(`<rpminfo_object id=%q><name>%s</name></rpminfo_object>`, obj, pkg))
	o.statesXML = append(o.statesXML, fmt.Sprintf(`<rpminfo_state id=%q><evr datatype="evr_string" operation="less than">%s</evr></rpminfo_state>`, ste, evr))
	return fmt.Sprintf(`<criterion test_ref=%q comment="%s is earlier than %s"/>`, tst, pkg, evr)
}

// archCriterion returns a criterion resolving to an arch test on the SAME
// "oraclelinux-release" object the platform test uses, exactly the real
// shape (ELSA-2026-55857's own tst:...002 reuses obj:...001) -- proving arch
// branching does not get misread as a second platform-major criterion.
func (o *ovalBuilder) archCriterion(arch string) string {
	tst, obj, ste := o.id("tst"), o.id("obj"), o.id("ste")
	o.testsXML = append(o.testsXML, fmt.Sprintf(
		`<rpminfo_test id=%q comment="Oracle Linux arch is %s"><object object_ref=%q/><state state_ref=%q/></rpminfo_test>`,
		tst, arch, obj, ste))
	o.objsXML = append(o.objsXML, fmt.Sprintf(`<rpminfo_object id=%q><name>oraclelinux-release</name></rpminfo_object>`, obj))
	o.statesXML = append(o.statesXML, fmt.Sprintf(`<rpminfo_state id=%q><arch operation="pattern match">%s</arch></rpminfo_state>`, ste, arch))
	return fmt.Sprintf(`<criterion test_ref=%q comment="Oracle Linux arch is %s"/>`, tst, arch)
}

// moduleGateCriterionRaw returns the <criterion> XML for a module-enablement
// gate (D81's real shape), registering a resolvable
// textfilecontent54_test/_object/_state trio so BOTH extraction paths can
// read it -- the criterion's own COMMENT names (commentName, commentStream),
// while the registered gate OBJECT (filepath) and STATE (pattern text)
// structurally name (structName, structStream). Equal for the ordinary case
// (moduleGateCriterion below); deliberately different for
// TestParseOVAL_ModuleGateCommentStructureDisagreementStructuralWins.
// structStream is regexp.QuoteMeta-escaped before being embedded in the
// state's pattern text, mirroring the real archive's "1\.4" spelling for a
// literal dot (moduleStreamFromStateText's own doc comment has the measured
// example) -- callers pass the plain stream value, not an already-escaped
// one.
func (o *ovalBuilder) moduleGateCriterionRaw(commentName, commentStream, structName, structStream string) string {
	tst, obj, ste := o.id("tst"), o.id("obj"), o.id("ste")
	o.testsXML = append(o.testsXML, fmt.Sprintf(
		`<ind-def:textfilecontent54_test id=%q comment="Module %s:%s is enabled" check="all"><ind-def:object object_ref=%q/><ind-def:state state_ref=%q/></ind-def:textfilecontent54_test>`,
		tst, commentName, commentStream, obj, ste))
	o.objsXML = append(o.objsXML, fmt.Sprintf(
		`<ind-def:textfilecontent54_object id=%q><ind-def:filepath datatype="string">/etc/dnf/modules.d/%s.module</ind-def:filepath></ind-def:textfilecontent54_object>`,
		obj, structName))
	o.statesXML = append(o.statesXML, fmt.Sprintf(
		`<ind-def:textfilecontent54_state id=%q><ind-def:text operation="pattern match">stream\s*=\s*%s\b</ind-def:text></ind-def:textfilecontent54_state>`,
		ste, regexp.QuoteMeta(structStream)))
	return fmt.Sprintf(`<criterion test_ref=%q comment="Module %s:%s is enabled"/>`, tst, commentName, commentStream)
}

// moduleGateCriterion is moduleGateCriterionRaw's ordinary case: comment and
// structure agree, the shape measured on all 763 gates in the full archive
// 2026-08-20.
func (o *ovalBuilder) moduleGateCriterion(name, stream string) string {
	return o.moduleGateCriterionRaw(name, stream, name, stream)
}

// unresolvedModuleComment returns a <criterion> whose comment reads exactly
// like a real module gate ("Module X:Y is enabled") but whose test_ref
// points at an id NEVER registered against any textfilecontent54_test --
// pinning moduleGateStream's own rule (D81): a criterion is a module gate
// IFF its test_ref resolves against that pool, never by sniffing its
// comment text alone. If isGate were decided by the comment regex instead,
// TestParseOVAL_UnresolvedModuleCommentIsNotAGate below would wrongly
// attach a stream.
func (o *ovalBuilder) unresolvedModuleComment(nameStream string) string {
	tst := o.id("tst")
	return fmt.Sprintf(`<criterion test_ref=%q comment="Module %s is enabled"/>`, tst, nameStream)
}

type cveFixture struct {
	cve, cvss3 string
}

// definitionXML renders one <definition>. source is "elsa" or "elba";
// criteriaInner is the already-built criterion/criteria XML for this
// definition's <criteria operator="AND"> root.
func definitionXML(id, source, title string, cves []cveFixture, severityWord, criteriaInner string) string {
	var refs strings.Builder
	fmt.Fprintf(&refs, `<reference source=%q ref_id=%q/>`, source, id)
	var cveXML strings.Builder
	for _, c := range cves {
		fmt.Fprintf(&refs, `<reference source="CVE" ref_id=%q/>`, c.cve)
		if c.cvss3 != "" {
			fmt.Fprintf(&cveXML, `<cve cvss3=%q>%s</cve>`, c.cvss3, c.cve)
		} else {
			fmt.Fprintf(&cveXML, `<cve>%s</cve>`, c.cve)
		}
	}
	return fmt.Sprintf(
		`<definition class="patch"><metadata><title>%s</title>%s<advisory><severity>%s</severity>%s</advisory></metadata>`+
			`<criteria operator="AND">%s</criteria></definition>`,
		title, refs.String(), severityWord, cveXML.String(), criteriaInner)
}

func (o *ovalBuilder) doc(defsXML ...string) string {
	return fmt.Sprintf(
		`<oval_definitions><generator><oval:timestamp>2026-08-19T10:33:28</oval:timestamp></generator>`+
			`<definitions>%s</definitions><tests>%s</tests><objects>%s</objects><states>%s</states></oval_definitions>`,
		strings.Join(defsXML, ""), strings.Join(o.testsXML, ""), strings.Join(o.objsXML, ""), strings.Join(o.statesXML, ""))
}

func findAdvisory(advs []advisory.Advisory, id string) (advisory.Advisory, bool) {
	for _, a := range advs {
		if a.ID == id {
			return a, true
		}
	}
	return advisory.Advisory{}, false
}

func affectedFor(a advisory.Advisory, eco, name string) (advisory.Affected, bool) {
	for _, aff := range a.Affected {
		if aff.Ecosystem == eco && aff.Name == name {
			return aff, true
		}
	}
	return advisory.Affected{}, false
}

func fixedOf(aff advisory.Affected) string {
	if len(aff.Ranges) == 0 || len(aff.Ranges[0].Events) < 2 {
		return ""
	}
	return aff.Ranges[0].Events[1].Fixed
}

// TestParseOVAL_SinglePlatformPackageFix is the baseline: one definition, one
// CVE carrying a CVSS v3 vector, one platform, one package. Everything else
// below is a variation on this shape.
func TestParseOVAL_SinglePlatformPackageFix(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(9) + o.fixCriterion("openssh", "0:8.7p1-38.el9_8")
	doc := o.doc(definitionXML("ELSA-2026-0001", "elsa", "openssh security update",
		[]cveFixture{{"CVE-2026-1001", "5.9/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}},
		"IMPORTANT", crit))

	var st stats
	defs, asOf, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-0001")
	if !ok {
		t.Fatalf("no advisory ELSA-2026-0001 among %+v", advs)
	}
	if a.Database != "ELSA" {
		t.Errorf("Database = %q, want ELSA", a.Database)
	}
	if a.Source != SourceName {
		t.Errorf("Source = %q, want %q", a.Source, SourceName)
	}
	if len(a.Related) != 1 || a.Related[0] != "CVE-2026-1001" {
		t.Errorf("Related = %v, want [CVE-2026-1001]", a.Related)
	}
	aff, ok := affectedFor(a, "Oracle Linux:9", "openssh")
	if !ok {
		t.Fatalf("no Affected entry for openssh under Oracle Linux:9: %+v", a.Affected)
	}
	if got := fixedOf(aff); got != "0:8.7p1-38.el9_8" {
		t.Errorf("fixed = %q, want 0:8.7p1-38.el9_8", got)
	}
	// Both severity signals, per D71 decision 2's "both, not either".
	wantCVSS := advisory.Severity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}
	wantWord := advisory.Severity{Type: "VENDOR_WORD", Score: "Important"}
	if len(a.Severity) != 2 || a.Severity[0] != wantCVSS || a.Severity[1] != wantWord {
		t.Errorf("Severity = %+v, want [%+v %+v]", a.Severity, wantCVSS, wantWord)
	}
	wantAsOf := time.Date(2026, 8, 19, 10, 33, 28, 0, time.UTC)
	if !asOf.Equal(wantAsOf) {
		t.Errorf("asOf = %v, want %v (the generator's own timestamp)", asOf, wantAsOf)
	}
}

// TestParseOVAL_MultiPlatformAttributesEachMajorItsOwnFix is the direct
// regression test for the bug the research this slice shipped from measured
// on its own first pass: a flat parse that ignores the criteria-tree guards
// cross-assigns EVRs between platforms, inflating multi-EVR groups from
// 1,184 to 12,540. One definition here covers OL8 and OL9 with DIFFERENT
// fixed EVRs for the SAME package (java-17-openjdk's own real shape,
// ELSA-2026-42887) -- if the platform guard were not honored, each major
// would see both EVRs (this test) or the wrong one (a plain swap bug), and
// dropAmbiguous would silently eat the whole package as "ambiguous" instead
// of correctly emitting two clean per-major advisories.
func TestParseOVAL_MultiPlatformAttributesEachMajorItsOwnFix(t *testing.T) {
	o := &ovalBuilder{}
	branch8 := o.platformCriterion(8) + o.fixCriterion("java-17-openjdk", "1:17.0.20.0.8-1.1.0.1.el8")
	branch9 := o.platformCriterion(9) + o.fixCriterion("java-17-openjdk", "1:17.0.20.0.8-1.1.0.1.el9")
	crit := fmt.Sprintf(`<criteria operator="OR"><criteria operator="AND">%s</criteria><criteria operator="AND">%s</criteria></criteria>`, branch8, branch9)
	doc := o.doc(definitionXML("ELSA-2026-42887", "elsa", "java-17-openjdk security update",
		[]cveFixture{{"CVE-2026-9001", ""}}, "IMPORTANT", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	// One definition, two majors -> two advisories (D74's "one
	// advisory.Advisory per (ELSA, major)").
	var got []advisory.Advisory
	for _, a := range advs {
		if a.ID == "ELSA-2026-42887" {
			got = append(got, a)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d advisories for ELSA-2026-42887, want 2 (one per major): %+v", len(got), got)
	}
	for _, a := range got {
		if len(a.Affected) != 1 {
			t.Fatalf("advisory %+v has %d Affected entries, want exactly 1 (a flat parse would cross-assign a second)", a, len(a.Affected))
		}
	}
	a8, ok8 := findAffectedAmong(got, "Oracle Linux:8", "java-17-openjdk")
	a9, ok9 := findAffectedAmong(got, "Oracle Linux:9", "java-17-openjdk")
	if !ok8 || !ok9 {
		t.Fatalf("missing a per-major Affected entry: OL8 ok=%v OL9 ok=%v, advisories=%+v", ok8, ok9, got)
	}
	if fixedOf(a8) != "1:17.0.20.0.8-1.1.0.1.el8" {
		t.Errorf("OL8 fixed = %q, want the el8 EVR", fixedOf(a8))
	}
	if fixedOf(a9) != "1:17.0.20.0.8-1.1.0.1.el9" {
		t.Errorf("OL9 fixed = %q, want the el9 EVR", fixedOf(a9))
	}
}

func findAffectedAmong(advs []advisory.Advisory, eco, name string) (advisory.Affected, bool) {
	for _, a := range advs {
		if aff, ok := affectedFor(a, eco, name); ok {
			return aff, ok
		}
	}
	return advisory.Affected{}, false
}

// TestParseOVAL_ArchBranchesAgreeingIsNotAmbiguous proves that two arch
// branches naming the SAME package at the SAME EVR (the ordinary shape --
// one RPM build serves every arch) collapse to one Affected entry rather
// than being flagged by the UEK/module guard, which fires only on a genuine
// DISAGREEMENT in the fixed version.
func TestParseOVAL_ArchBranchesAgreeingIsNotAmbiguous(t *testing.T) {
	o := &ovalBuilder{}
	aarch64 := o.archCriterion("aarch64") + o.fixCriterion("curl", "0:8.5.0-1.el9")
	x86 := o.archCriterion("x86_64") + o.fixCriterion("curl", "0:8.5.0-1.el9")
	crit := o.platformCriterion(9) + fmt.Sprintf(
		`<criteria operator="OR"><criteria operator="AND">%s</criteria><criteria operator="AND">%s</criteria></criteria>`, aarch64, x86)
	doc := o.doc(definitionXML("ELSA-2026-0002", "elsa", "curl security update",
		[]cveFixture{{"CVE-2026-1002", ""}}, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-0002")
	if !ok {
		t.Fatalf("no advisory ELSA-2026-0002 among %+v", advs)
	}
	if len(a.Affected) != 1 {
		t.Fatalf("Affected = %+v, want exactly 1 entry (arch branches must collapse)", a.Affected)
	}
	if st.AmbiguousGroups != 0 {
		t.Errorf("AmbiguousGroups = %d, want 0 -- agreeing arch branches are not a train conflict", st.AmbiguousGroups)
	}
}

// TestParseOVAL_UEKCrossDefinitionAmbiguityDropped is the direct proof for
// the measured hazard (857 OL8 / 817 OL9 (CVE, platform) groups, 2026-08-19):
// two SEPARATE ELSA definitions both patch kernel-uek for the SAME CVE on
// the SAME major, at two different kernel trains' EVRs -- exactly
// ELSA-2026-50112 and ELSA-2026-50145's real shape for CVE-2018-1000204 on
// OL9. Neither fixed EVR can be trusted (a host on either train would be
// misjudged against the other's threshold), so both must be dropped, while
// an UNRELATED package the two definitions agree on survives untouched in
// both.
func TestParseOVAL_UEKCrossDefinitionAmbiguityDropped(t *testing.T) {
	o := &ovalBuilder{}
	critA := o.platformCriterion(9) +
		o.fixCriterion("kernel-uek", "0:5.15.0-317.197.5.1.el9uek") +
		o.fixCriterion("kernel-uek-firmware", "0:5.15.0-317.197.5.1.el9uek")
	critB := o.platformCriterion(9) +
		o.fixCriterion("kernel-uek", "0:6.12.0-108.64.6.3.el9uek") +
		o.fixCriterion("kernel-uek-firmware", "0:5.15.0-317.197.5.1.el9uek")
	docA := definitionXML("ELSA-2026-50113", "elsa", "UEK security update",
		[]cveFixture{{"CVE-2018-1000204", ""}}, "IMPORTANT", critA)
	docB := definitionXML("ELSA-2026-50112", "elsa", "UEK security update",
		[]cveFixture{{"CVE-2018-1000204", ""}}, "IMPORTANT", critB)
	doc := o.doc(docA, docB)

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)

	aA, okA := findAdvisory(advs, "ELSA-2026-50113")
	aB, okB := findAdvisory(advs, "ELSA-2026-50112")
	if !okA || !okB {
		t.Fatalf("expected both advisories to still be emitted (for kernel-uek-firmware): %+v", advs)
	}
	if _, ok := affectedFor(aA, "Oracle Linux:9", "kernel-uek"); ok {
		t.Errorf("ELSA-2026-50113 still names kernel-uek; the dual-train fix must be dropped")
	}
	if _, ok := affectedFor(aB, "Oracle Linux:9", "kernel-uek"); ok {
		t.Errorf("ELSA-2026-50112 still names kernel-uek; the dual-train fix must be dropped")
	}
	fwA, okFwA := affectedFor(aA, "Oracle Linux:9", "kernel-uek-firmware")
	fwB, okFwB := affectedFor(aB, "Oracle Linux:9", "kernel-uek-firmware")
	if !okFwA || !okFwB {
		t.Fatalf("kernel-uek-firmware (the package the two definitions AGREE on) must survive in both: A ok=%v B ok=%v", okFwA, okFwB)
	}
	if fixedOf(fwA) != "0:5.15.0-317.197.5.1.el9uek" || fixedOf(fwB) != "0:5.15.0-317.197.5.1.el9uek" {
		t.Errorf("kernel-uek-firmware fixed versions = %q / %q, want the agreed EVR in both", fixedOf(fwA), fixedOf(fwB))
	}
	if st.AmbiguousGroups != 1 {
		t.Errorf("AmbiguousGroups = %d, want 1 (kernel-uek under CVE-2018-1000204/major 9)", st.AmbiguousGroups)
	}
	if st.SkippedAmbiguousFixes != 2 {
		t.Errorf("SkippedAmbiguousFixes = %d, want 2 (one dropped from each contributing definition)", st.SkippedAmbiguousFixes)
	}
}

// TestParseOVAL_LineageFixDroppedRecoversMainline is D79's direct regression
// test: without the lineage filter, this is exactly the UEK shape above --
// two definitions naming the SAME package under the SAME CVE and major at
// two different EVRs, so dropAmbiguous throws both out and the mainline fix
// is lost along with the lineage one, even though only the lineage EVR is
// untrustworthy. ELSA-2026-6001 fixes openssl at a mainline EVR;
// ELSA-2026-6002 "fixes" the same CVE/major/package at a `.ksplice1.` EVR --
// Oracle's own shape (measured 2026-08-20: 92 distinct `.ksplice1.` EVRs
// across the live archive). The filter must drop the ksplice EVR before
// dropAmbiguous ever groups it, so the group never becomes ambiguous at all
// and the mainline advisory survives untouched.
func TestParseOVAL_LineageFixDroppedRecoversMainline(t *testing.T) {
	o := &ovalBuilder{}
	mainlineCrit := o.platformCriterion(9) + o.fixCriterion("openssl", "1:3.0.7-6.el9")
	kspliceCrit := o.platformCriterion(9) + o.fixCriterion("openssl", "1:3.0.7-6.0.1.ksplice1.el9_2")
	docMain := definitionXML("ELSA-2026-6001", "elsa", "openssl security update",
		[]cveFixture{{"CVE-2026-6001", ""}}, "IMPORTANT", mainlineCrit)
	docKsplice := definitionXML("ELSA-2026-6002", "elsa", "openssl ksplice update",
		[]cveFixture{{"CVE-2026-6001", ""}}, "IMPORTANT", kspliceCrit)
	doc := o.doc(docMain, docKsplice)

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)

	a, ok := findAdvisory(advs, "ELSA-2026-6001")
	if !ok {
		t.Fatalf("mainline advisory ELSA-2026-6001 missing -- the ksplice EVR must not have dragged it into the ambiguity guard: %+v", advs)
	}
	aff, ok := affectedFor(a, "Oracle Linux:9", "openssl")
	if !ok {
		t.Fatalf("no Affected entry for openssl under Oracle Linux:9: %+v", a.Affected)
	}
	if got := fixedOf(aff); got != "1:3.0.7-6.el9" {
		t.Errorf("fixed = %q, want the mainline EVR 1:3.0.7-6.el9", got)
	}
	if _, ok := findAdvisory(advs, "ELSA-2026-6002"); ok {
		t.Errorf("ksplice-only definition ELSA-2026-6002 was emitted; openssl was its only package and that package's only fix was lineage")
	}
	if st.SkippedLineageFixes != 1 {
		t.Errorf("SkippedLineageFixes = %d, want 1", st.SkippedLineageFixes)
	}
	if st.AmbiguousGroups != 0 {
		t.Errorf("AmbiguousGroups = %d, want 0 -- the lineage EVR must be dropped BEFORE ambiguity grouping runs, not after", st.AmbiguousGroups)
	}
	if st.SkippedAmbiguousFixes != 0 {
		t.Errorf("SkippedAmbiguousFixes = %d, want 0 -- nothing should ever reach the ambiguity guard here", st.SkippedAmbiguousFixes)
	}
}

// TestParseOVAL_FIPSLineageFixDroppedRecoversMainline is the second marker
// shape through the same caller path: Oracle's FIPS lineage ends the release
// with `_fips` rather than stamping `.ksplice<N>.` into it (measured
// 2026-08-20: 33 distinct `_fips`-suffixed EVRs, every one shaped
// el<major>[_minor]_fips, epoch 10 in the real corpus though the suffix is
// the signal this filter reads, not the epoch). Same collision, same
// recovery: without the filter both ELSA-2026-7001 and ELSA-2026-7002 would
// be dropped by the ambiguity guard; with it, only the FIPS EVR is.
func TestParseOVAL_FIPSLineageFixDroppedRecoversMainline(t *testing.T) {
	o := &ovalBuilder{}
	mainlineCrit := o.platformCriterion(7) + o.fixCriterion("openssl", "1:1.0.2k-19.el7")
	fipsCrit := o.platformCriterion(7) + o.fixCriterion("openssl", "10:1.0.2k-19.el7_9_fips")
	docMain := definitionXML("ELSA-2026-7001", "elsa", "openssl security update",
		[]cveFixture{{"CVE-2026-7001", ""}}, "IMPORTANT", mainlineCrit)
	docFips := definitionXML("ELSA-2026-7002", "elsa", "openssl fips update",
		[]cveFixture{{"CVE-2026-7001", ""}}, "IMPORTANT", fipsCrit)
	doc := o.doc(docMain, docFips)

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)

	a, ok := findAdvisory(advs, "ELSA-2026-7001")
	if !ok {
		t.Fatalf("mainline advisory ELSA-2026-7001 missing -- the FIPS EVR must not have dragged it into the ambiguity guard: %+v", advs)
	}
	aff, ok := affectedFor(a, "Oracle Linux:7", "openssl")
	if !ok {
		t.Fatalf("no Affected entry for openssl under Oracle Linux:7: %+v", a.Affected)
	}
	if got := fixedOf(aff); got != "1:1.0.2k-19.el7" {
		t.Errorf("fixed = %q, want the mainline EVR 1:1.0.2k-19.el7", got)
	}
	if _, ok := findAdvisory(advs, "ELSA-2026-7002"); ok {
		t.Errorf("FIPS-only definition ELSA-2026-7002 was emitted; openssl was its only package and that package's only fix was lineage")
	}
	if st.SkippedLineageFixes != 1 {
		t.Errorf("SkippedLineageFixes = %d, want 1", st.SkippedLineageFixes)
	}
	if st.AmbiguousGroups != 0 {
		t.Errorf("AmbiguousGroups = %d, want 0 -- the FIPS EVR must be dropped BEFORE ambiguity grouping runs, not after", st.AmbiguousGroups)
	}
}

// TestParseOVAL_LineageMarkerLookalikesNotDropped is the negative row: an EVR
// that merely CONTAINS the marker letters at the wrong position must survive.
// "_fipstools" does not end in "_fips" (the suffix must be end-anchored), and
// a package NAMED ksplice-tools with an ordinary EVR carries no `.ksplice<N>.`
// substring in its version at all -- classifyCriterion only ever inspects the
// EVR text, never the package name, so a name collision alone must never
// trip this filter either.
func TestParseOVAL_LineageMarkerLookalikesNotDropped(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(8) +
		o.fixCriterion("libfipstools", "0:1.0-1_fipstools.el8") +
		o.fixCriterion("ksplice-tools", "0:2.4-3.el8")
	doc := o.doc(definitionXML("ELSA-2026-8001", "elsa", "lookalike packages",
		[]cveFixture{{"CVE-2026-8001", ""}}, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-8001")
	if !ok {
		t.Fatalf("advisory ELSA-2026-8001 missing -- lookalikes must not trip the lineage filter: %+v", advs)
	}
	fipsAff, ok := affectedFor(a, "Oracle Linux:8", "libfipstools")
	if !ok {
		t.Fatalf("libfipstools dropped -- its EVR's _fipstools suffix is not the end-anchored _fips marker: %+v", a.Affected)
	}
	if got := fixedOf(fipsAff); got != "0:1.0-1_fipstools.el8" {
		t.Errorf("libfipstools fixed = %q, want 0:1.0-1_fipstools.el8 unchanged", got)
	}
	kspliceAff, ok := affectedFor(a, "Oracle Linux:8", "ksplice-tools")
	if !ok {
		t.Fatalf("ksplice-tools dropped -- the marker is named in its PACKAGE, not its EVR: %+v", a.Affected)
	}
	if got := fixedOf(kspliceAff); got != "0:2.4-3.el8" {
		t.Errorf("ksplice-tools fixed = %q, want 0:2.4-3.el8 unchanged", got)
	}
	if st.SkippedLineageFixes != 0 {
		t.Errorf("SkippedLineageFixes = %d, want 0", st.SkippedLineageFixes)
	}
}

// TestParseOVAL_ModuleStreamsWithinOneDefinitionBothKept is the
// intra-definition half of D81's stream-aware guard: ONE definition
// bundling two REAL module gates (nodejs:18, nodejs:20, each with a
// resolvable textfilecontent54_test/_object/_state trio, moduleGateCriterion)
// that fix the SAME package at two different EVRs. Before D81 -- when this
// fixture registered no resolvable gate at all -- the two collided under
// the stream-blind key and both were dropped; that was this test's own
// assertion under its old name, TestParseOVAL_ModuleStreamAmbiguityCaughtBy
// Guard. With a real stream now attached to each branch, the two never
// share an ambiguity key: BOTH survive as separate Affected entries for the
// same package, each carrying its own stream.
func TestParseOVAL_ModuleStreamsWithinOneDefinitionBothKept(t *testing.T) {
	o := &ovalBuilder{}
	stream18 := o.moduleGateCriterion("nodejs", "18") + o.fixCriterion("nodejs", "1:18.20.4-1.module+el8+1+aaaaaaaa")
	stream20 := o.moduleGateCriterion("nodejs", "20") + o.fixCriterion("nodejs", "1:20.15.1-1.module+el8+2+bbbbbbbb")
	crit := o.platformCriterion(8) + fmt.Sprintf(
		`<criteria operator="OR"><criteria operator="AND">%s</criteria><criteria operator="AND">%s</criteria></criteria>`, stream18, stream20)
	doc := o.doc(definitionXML("ELSA-2026-0003", "elsa", "nodejs security update",
		[]cveFixture{{"CVE-2026-1003", ""}}, "MODERATE", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-0003")
	if !ok {
		t.Fatalf("no advisory ELSA-2026-0003 among %+v", advs)
	}
	if len(a.Affected) != 2 {
		t.Fatalf("Affected = %+v, want 2 entries (one per stream)", a.Affected)
	}
	var got18, got20 *advisory.Affected
	for i := range a.Affected {
		switch a.Affected[i].ModuleStream {
		case "nodejs:18":
			got18 = &a.Affected[i]
		case "nodejs:20":
			got20 = &a.Affected[i]
		}
	}
	if got18 == nil || got20 == nil {
		t.Fatalf("missing a stream's Affected entry: %+v", a.Affected)
	}
	if fixedOf(*got18) != "1:18.20.4-1.module+el8+1+aaaaaaaa" {
		t.Errorf("nodejs:18 fixed = %q, want the 18 EVR", fixedOf(*got18))
	}
	if fixedOf(*got20) != "1:20.15.1-1.module+el8+2+bbbbbbbb" {
		t.Errorf("nodejs:20 fixed = %q, want the 20 EVR", fixedOf(*got20))
	}
	if st.AmbiguousGroups != 0 {
		t.Errorf("AmbiguousGroups = %d, want 0 -- different streams must not collide", st.AmbiguousGroups)
	}
	if st.ModuleGatedFixesKept != 2 {
		t.Errorf("ModuleGatedFixesKept = %d, want 2", st.ModuleGatedFixesKept)
	}
	if st.DistinctModuleStreams != 2 {
		t.Errorf("DistinctModuleStreams = %d, want 2", st.DistinctModuleStreams)
	}
}

// TestParseOVAL_ModuleStreamAmbiguityRecoveredAcrossDefinitions is D81's
// direct regression test -- the reason this slice exists. Two SEPARATE
// definitions patch the SAME CVE, major and package, gated to DIFFERENT
// module streams (nodejs:18, nodejs:20), at different fixed EVRs -- exactly
// the measured shape (38,998 gated fix hits, each with exactly one module in
// scope, full archive 2026-08-20). Before D81 this collided under the
// stream-blind cross-definition ambiguity key (dropAmbiguous joins on
// shared CVE) and BOTH were dropped, even though the two module streams are
// independent, correct facts about independent hosts. With the stream
// folded into the key, they no longer collide: BOTH advisories survive,
// each with its own Affected entry carrying its own stream.
func TestParseOVAL_ModuleStreamAmbiguityRecoveredAcrossDefinitions(t *testing.T) {
	o := &ovalBuilder{}
	// The fixes sit in a DESCENDANT criteria node, not beside the gate —
	// the shape every real module-gated definition takes (the gate is an
	// AND sibling of the OR that holds the per-package fix branches), so
	// this test holds the stream's inheritance into child criteria, not
	// just its application to siblings. A flat fixture here left the
	// inheritance path unheld: severing it stayed green while the live
	// feed lost every one of its 17,930 gated fixes.
	nest := func(fix string) string {
		return `<criteria operator="OR"><criteria operator="AND">` + fix + `</criteria></criteria>`
	}
	critA := o.platformCriterion(9) + o.moduleGateCriterion("nodejs", "18") + nest(o.fixCriterion("nodejs", "1:18.20.4-1.module+el9+1+aaaaaaaa"))
	critB := o.platformCriterion(9) + o.moduleGateCriterion("nodejs", "20") + nest(o.fixCriterion("nodejs", "1:20.15.1-1.module+el9+2+bbbbbbbb"))
	docA := definitionXML("ELSA-2026-9101", "elsa", "nodejs:18 security update",
		[]cveFixture{{"CVE-2026-9101", ""}}, "MODERATE", critA)
	docB := definitionXML("ELSA-2026-9102", "elsa", "nodejs:20 security update",
		[]cveFixture{{"CVE-2026-9101", ""}}, "MODERATE", critB)
	doc := o.doc(docA, docB)

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)

	aA, okA := findAdvisory(advs, "ELSA-2026-9101")
	aB, okB := findAdvisory(advs, "ELSA-2026-9102")
	if !okA || !okB {
		t.Fatalf("expected BOTH advisories to survive (different module streams, not a real collision): %+v", advs)
	}
	affA, okA2 := affectedFor(aA, "Oracle Linux:9", "nodejs")
	affB, okB2 := affectedFor(aB, "Oracle Linux:9", "nodejs")
	if !okA2 || !okB2 {
		t.Fatalf("missing a per-definition Affected entry: A ok=%v B ok=%v", okA2, okB2)
	}
	if affA.ModuleStream != "nodejs:18" {
		t.Errorf("ELSA-2026-9101 ModuleStream = %q, want nodejs:18", affA.ModuleStream)
	}
	if affB.ModuleStream != "nodejs:20" {
		t.Errorf("ELSA-2026-9102 ModuleStream = %q, want nodejs:20", affB.ModuleStream)
	}
	if fixedOf(affA) != "1:18.20.4-1.module+el9+1+aaaaaaaa" {
		t.Errorf("ELSA-2026-9101 fixed = %q, want the 18 EVR", fixedOf(affA))
	}
	if fixedOf(affB) != "1:20.15.1-1.module+el9+2+bbbbbbbb" {
		t.Errorf("ELSA-2026-9102 fixed = %q, want the 20 EVR", fixedOf(affB))
	}
	if st.AmbiguousGroups != 0 {
		t.Errorf("AmbiguousGroups = %d, want 0 -- the whole point of D81 is that this is NOT ambiguous", st.AmbiguousGroups)
	}
	if st.SkippedAmbiguousFixes != 0 {
		t.Errorf("SkippedAmbiguousFixes = %d, want 0", st.SkippedAmbiguousFixes)
	}
}

// TestParseOVAL_ModuleStreamCollisionWithinOneStreamStillDropped proves
// D74's original ambiguity rule still applies WITHIN one stream: two
// definitions both gate nodejs:18 (same CVE, major and package), at
// different fixed EVRs -- an actual disagreement about what nodejs:18 is
// fixed at, which D81 must still catch and drop, exactly as the
// stream-blind guard did before this slice.
func TestParseOVAL_ModuleStreamCollisionWithinOneStreamStillDropped(t *testing.T) {
	o := &ovalBuilder{}
	critA := o.platformCriterion(9) + o.moduleGateCriterion("nodejs", "18") + o.fixCriterion("nodejs", "1:18.20.1-1.module+el9+1+aaaaaaaa")
	critB := o.platformCriterion(9) + o.moduleGateCriterion("nodejs", "18") + o.fixCriterion("nodejs", "1:18.20.2-1.module+el9+2+bbbbbbbb")
	docA := definitionXML("ELSA-2026-9201", "elsa", "nodejs:18 update A",
		[]cveFixture{{"CVE-2026-9201", ""}}, "MODERATE", critA)
	docB := definitionXML("ELSA-2026-9202", "elsa", "nodejs:18 update B",
		[]cveFixture{{"CVE-2026-9201", ""}}, "MODERATE", critB)
	doc := o.doc(docA, docB)

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)

	if _, ok := findAdvisory(advs, "ELSA-2026-9201"); ok {
		t.Errorf("ELSA-2026-9201 survived; both nodejs:18 fixes disagree and must be dropped")
	}
	if _, ok := findAdvisory(advs, "ELSA-2026-9202"); ok {
		t.Errorf("ELSA-2026-9202 survived; both nodejs:18 fixes disagree and must be dropped")
	}
	if st.AmbiguousGroups != 1 {
		t.Errorf("AmbiguousGroups = %d, want 1", st.AmbiguousGroups)
	}
	if st.SkippedAmbiguousFixes != 2 {
		t.Errorf("SkippedAmbiguousFixes = %d, want 2 (one dropped from each contributing definition)", st.SkippedAmbiguousFixes)
	}
}

// TestParseOVAL_ModuleStreamWithADotUnescapesCorrectly is the caller-first
// proof for unescapeRegexLiteral: every module-stream fixture elsewhere in
// this file uses a digits-only stream ("18", "20", "1", "2"), which
// regexp.QuoteMeta leaves unchanged, so none of them ever puts an escaped
// character in front of moduleStreamFromStateText. "kvm_utils3:1.4" is that
// function's own doc-comment example, measured on the live archive:
// moduleGateCriterion (via regexp.QuoteMeta) escapes the dot to "1\.4" in
// the state's pattern text, exactly as the real archive does, and
// unescapeRegexLiteral must strip that backslash back out so the stored
// ModuleStream matches Package.ModuleStream's own un-escaped spelling at
// match time (internal/matcher/matcher.go's stream comparison).
func TestParseOVAL_ModuleStreamWithADotUnescapesCorrectly(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(8) + o.moduleGateCriterion("kvm_utils3", "1.4") +
		o.fixCriterion("kvm_utils3", "1:1.4.0-1.module+el8+1+aaaaaaaa")
	doc := o.doc(definitionXML("ELSA-2026-9401", "elsa", "kvm_utils3:1.4 update",
		[]cveFixture{{"CVE-2026-9401", ""}}, "MODERATE", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-9401")
	if !ok {
		t.Fatalf("advisory ELSA-2026-9401 missing among %+v", advs)
	}
	aff, ok := affectedFor(a, "Oracle Linux:8", "kvm_utils3")
	if !ok {
		t.Fatalf("no Affected entry for kvm_utils3: %+v", a.Affected)
	}
	if aff.ModuleStream != "kvm_utils3:1.4" {
		t.Errorf("ModuleStream = %q, want %q -- the escaped dot in the state's pattern text must be "+
			"unescaped back to a literal one, or a host on kvm_utils3:1.4 never matches this fix",
			aff.ModuleStream, "kvm_utils3:1.4")
	}
}

// TestParseOVAL_NoCVEDefinitionIntraDefinitionAmbiguityStillCaught is the
// caller-first proof for joinKeysFor's no-CVE fallback: a definition with NO
// CVE references at all, whose own criteria tree yields two DIFFERENT fixed
// EVRs for the same (major, package, stream) -- the exact self-contradiction
// dropAmbiguous exists to catch, and joinKeysFor's own doc comment names as
// the reason the fallback returns []string{d.id} rather than an empty set:
// "two branches of ITS OWN criteria tree naming the same package at two
// different EVRs under one major" must still be dropped, even with nothing
// but the definition's own id to key on. TestParseOVAL_NoCVERefsStillEmits
// above is the well-behaved half (one fix, no ambiguity at all); this is the
// unheld other half.
func TestParseOVAL_NoCVEDefinitionIntraDefinitionAmbiguityStillCaught(t *testing.T) {
	o := &ovalBuilder{}
	branchA := o.fixCriterion("bash", "0:5.1.8-9.el9")
	branchB := o.fixCriterion("bash", "0:5.1.8-10.el9")
	crit := o.platformCriterion(9) + fmt.Sprintf(
		`<criteria operator="OR"><criteria operator="AND">%s</criteria><criteria operator="AND">%s</criteria></criteria>`,
		branchA, branchB)
	doc := o.doc(definitionXML("ELSA-2026-0007", "elsa", "bash bug fix and enhancement update", nil, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	if _, ok := findAdvisory(advs, "ELSA-2026-0007"); ok {
		t.Errorf("ELSA-2026-0007 survived; its own two branches disagree on bash's fixed EVR and " +
			"must be dropped even with no CVE to key on")
	}
	if st.AmbiguousGroups != 1 {
		t.Errorf("AmbiguousGroups = %d, want 1", st.AmbiguousGroups)
	}
	if st.SkippedAmbiguousFixes != 1 {
		t.Errorf("SkippedAmbiguousFixes = %d, want 1 -- one (definition, major, package, stream) "+
			"quadruple dropped, not one per branch (both branches belong to the same definition)", st.SkippedAmbiguousFixes)
	}
}

// TestParseOVAL_UngatedModuleEVRStoredStreamless is the measured 150-EVR
// case (full archive, 2026-08-20): a fixed EVR whose release string carries
// the "module+el" marker but has NO textfilecontent54_test criterion
// anywhere above it in the tree -- the stream is genuinely unrecoverable
// from this OVAL document. It must still be stored (not dropped outright),
// but stream-less: D80's matcher already knows how to report a
// stream-blind module bound skipped rather than guessed at match time
// (moduleBuildBound).
func TestParseOVAL_UngatedModuleEVRStoredStreamless(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(8) + o.fixCriterion("389-ds-base", "0:1.4.3.39-26.module+el8.10.0+90990+5ec542c6")
	doc := o.doc(definitionXML("ELSA-2026-9301", "elsa", "389-ds-base update",
		[]cveFixture{{"CVE-2026-9301", ""}}, "MODERATE", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-9301")
	if !ok {
		t.Fatalf("advisory ELSA-2026-9301 missing -- an ungated module EVR must still be stored: %+v", advs)
	}
	aff, ok := affectedFor(a, "Oracle Linux:8", "389-ds-base")
	if !ok {
		t.Fatalf("no Affected entry for 389-ds-base: %+v", a.Affected)
	}
	if aff.ModuleStream != "" {
		t.Errorf("ModuleStream = %q, want empty -- no gate means no stream, not a guess", aff.ModuleStream)
	}
	if got := fixedOf(aff); got != "0:1.4.3.39-26.module+el8.10.0+90990+5ec542c6" {
		t.Errorf("fixed = %q, want the EVR unchanged", got)
	}
	if st.UngatedModuleFixes != 1 {
		t.Errorf("UngatedModuleFixes = %d, want 1", st.UngatedModuleFixes)
	}
	if st.ModuleGatedFixesKept != 0 {
		t.Errorf("ModuleGatedFixesKept = %d, want 0 -- this entry never got a stream", st.ModuleGatedFixesKept)
	}
}

// TestParseOVAL_ModuleGateCommentStructureDisagreementStructuralWins is the
// synthetic disagreement case (0 measured on the live 2026-08-20 archive,
// where the two extraction paths agreed on all 763 gates): the criterion's
// own comment names "foo:1" while the gate object's filepath and state
// pattern structurally name "bar:2". moduleGateStream's own doc comment
// says why structural wins -- the comment is prose for a human reader, the
// structural fields are what the OVAL engine (and this parser) actually
// evaluate.
func TestParseOVAL_ModuleGateCommentStructureDisagreementStructuralWins(t *testing.T) {
	o := &ovalBuilder{}
	gate := o.moduleGateCriterionRaw("foo", "1", "bar", "2")
	crit := o.platformCriterion(9) + gate + o.fixCriterion("bar", "1:2.0-1.module+el9+1+cccccccc")
	doc := o.doc(definitionXML("ELSA-2026-9401", "elsa", "disagreement fixture",
		[]cveFixture{{"CVE-2026-9401", ""}}, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-9401")
	if !ok {
		t.Fatalf("advisory ELSA-2026-9401 missing: %+v", advs)
	}
	aff, ok := affectedFor(a, "Oracle Linux:9", "bar")
	if !ok {
		t.Fatalf("no Affected entry for bar: %+v", a.Affected)
	}
	if aff.ModuleStream != "bar:2" {
		t.Errorf("ModuleStream = %q, want bar:2 (structural, not foo:1 the comment names)", aff.ModuleStream)
	}
	if st.ModuleGateExtractionDisagreements != 1 {
		t.Errorf("ModuleGateExtractionDisagreements = %d, want 1", st.ModuleGateExtractionDisagreements)
	}
}

// TestParseOVAL_UnresolvedModuleCommentIsNotAGate pins D81's own rule
// (moduleGateStream's doc comment): a criterion is a module gate iff its
// test_ref resolves against the textfilecontent54_test pool, never by
// sniffing comment text alone. This criterion's comment reads exactly like
// a real gate ("Module nodejs:18 is enabled") but its test_ref was never
// registered against any textfilecontent54_test -- if isGate were decided
// by the comment regex instead of the test_ref join, this would wrongly
// attach a stream to the sibling fix below.
func TestParseOVAL_UnresolvedModuleCommentIsNotAGate(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(9) + o.unresolvedModuleComment("nodejs:18") + o.fixCriterion("nodejs", "1:18.20.4-1.module+el9+1+aaaaaaaa")
	doc := o.doc(definitionXML("ELSA-2026-9501", "elsa", "unresolved comment fixture",
		[]cveFixture{{"CVE-2026-9501", ""}}, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-9501")
	if !ok {
		t.Fatalf("advisory ELSA-2026-9501 missing: %+v", advs)
	}
	aff, ok := affectedFor(a, "Oracle Linux:9", "nodejs")
	if !ok {
		t.Fatalf("no Affected entry for nodejs: %+v", a.Affected)
	}
	if aff.ModuleStream != "" {
		t.Errorf("ModuleStream = %q, want empty -- an unresolvable test_ref must never be treated as a gate", aff.ModuleStream)
	}
	if st.ModuleGatedFixesKept != 0 {
		t.Errorf("ModuleGatedFixesKept = %d, want 0", st.ModuleGatedFixesKept)
	}
	if st.UngatedModuleFixes != 1 {
		t.Errorf("UngatedModuleFixes = %d, want 1 -- the EVR is module-tagged but no real gate was found", st.UngatedModuleFixes)
	}
}

// TestParseOVAL_NoMajorContextIsSkippedNotGuessed is the defensive case: a
// package-fix criterion with no "Oracle Linux N is installed" guard anywhere
// above it. Never observed in the real archive (every definition's criteria
// root carries one), but D17's discipline -- never coerce an absence into a
// plausible default -- applies to a missing platform gate exactly as it does
// to a missing severity, so this must be counted and dropped, not attributed
// to whichever major happens to be first.
func TestParseOVAL_NoMajorContextIsSkippedNotGuessed(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.fixCriterion("orphan-pkg", "0:1.0-1")
	doc := o.doc(definitionXML("ELSA-2026-0004", "elsa", "malformed definition",
		[]cveFixture{{"CVE-2026-1004", ""}}, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	if _, ok := findAdvisory(advs, "ELSA-2026-0004"); ok {
		t.Errorf("advisory emitted with no platform guard at all: %+v", advs)
	}
	if st.NoMajorContext != 1 {
		t.Errorf("NoMajorContext = %d, want 1", st.NoMajorContext)
	}
}

// TestParseOVAL_V2OnlyGetsNoSyntheticVector pins D71 decision 2's explicit
// rejection: a CVE with no cvss3 attribute at all (the pre-~2016 v2-only
// shape, 8,825 measured entries) must NOT get a fabricated CVSS_V3 entry --
// its severity comes from the vendor word alone here, and from the NVD join
// via the CVE this definition still places in Related.
func TestParseOVAL_V2OnlyGetsNoSyntheticVector(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(6) + o.fixCriterion("openssl", "0:1.0.1e-16.el6")
	doc := o.doc(definitionXML("ELSA-2013-0001", "elsa", "openssl security update",
		[]cveFixture{{"CVE-2012-3430", ""}}, "IMPORTANT", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2013-0001")
	if !ok {
		t.Fatalf("no advisory ELSA-2013-0001 among %+v", advs)
	}
	if len(a.Related) != 1 || a.Related[0] != "CVE-2012-3430" {
		t.Errorf("Related = %v, want [CVE-2012-3430] (the NVD join's only route in)", a.Related)
	}
	for _, s := range a.Severity {
		if s.Type == "CVSS_V3" {
			t.Errorf("Severity carries a CVSS_V3 entry %+v for a v2-only definition; none was ever measured", s)
		}
	}
	if len(a.Severity) != 1 || a.Severity[0] != (advisory.Severity{Type: "VENDOR_WORD", Score: "Important"}) {
		t.Errorf("Severity = %+v, want exactly one VENDOR_WORD/Important entry", a.Severity)
	}
}

// TestParseOVAL_UnrecognizedSeverityWordIsCountedNotStored pins the N/A case
// (7 of 9,796 definitions measured 2026-08-19): severity.go recognizes no
// "Negligible"/"N/A" band, so storing one would either be silently dropped
// downstream or -- worse -- collide with a word severity.Of does recognize
// if this table is ever "helpfully" widened without checking.
func TestParseOVAL_UnrecognizedSeverityWordIsCountedNotStored(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(9) + o.fixCriterion("some-doc-pkg", "0:1.0-1.el9")
	doc := o.doc(definitionXML("ELSA-2026-0005", "elsa", "doc update", nil, "N/A", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-0005")
	if !ok {
		t.Fatalf("no advisory ELSA-2026-0005 among %+v", advs)
	}
	if len(a.Severity) != 0 {
		t.Errorf("Severity = %+v, want none -- N/A must not become a stored word", a.Severity)
	}
	if st.UnrecognizedSeverity != 1 {
		t.Errorf("UnrecognizedSeverity = %d, want 1", st.UnrecognizedSeverity)
	}
}

// TestParseOVAL_NoCVERefsStillEmits pins the 106-definition hazard (measured
// 2026-08-19, ELSA id only, zero CVE references): D25's grouping needs the
// ELSA id stored even with nothing to relate it to, so the advisory must
// still be emitted, reachable by its own id.
func TestParseOVAL_NoCVERefsStillEmits(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(9) + o.fixCriterion("bash", "0:5.1.8-9.el9")
	doc := o.doc(definitionXML("ELSA-2026-0006", "elsa", "bash bug fix and enhancement update", nil, "LOW", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELSA-2026-0006")
	if !ok {
		t.Fatalf("no advisory ELSA-2026-0006 among %+v", advs)
	}
	if len(a.Related) != 0 {
		t.Errorf("Related = %v, want empty", a.Related)
	}
}

// TestParseOVAL_ELBADatabaseNaming pins databaseOf's other spelling: a
// bug-fix advisory's own reference source is "elba", not "elsa" (6
// definitions measured 2026-08-19), and Database must read ELBA rather than
// defaulting to ELSA or an empty string.
func TestParseOVAL_ELBADatabaseNaming(t *testing.T) {
	o := &ovalBuilder{}
	crit := o.platformCriterion(10) + o.fixCriterion("dotnet-sdk-10.0", "0:10.0.100-1.el10")
	doc := o.doc(definitionXML("ELBA-2025-20993", "elba", ".NET bug fix and enhancement update",
		[]cveFixture{{"CVE-2025-55247", ""}}, "IMPORTANT", crit))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	a, ok := findAdvisory(advs, "ELBA-2025-20993")
	if !ok {
		t.Fatalf("no advisory ELBA-2025-20993 among %+v", advs)
	}
	if a.Database != "ELBA" {
		t.Errorf("Database = %q, want ELBA", a.Database)
	}
}

// TestParseOVAL_NoIDDefinitionIsSkippedNotFatal proves one definition with no
// ELSA/ELBA reference at all (metadata carrying only CVE references) does
// not kill the whole parse -- it is counted and dropped, and every other
// definition in the same archive still comes through.
func TestParseOVAL_NoIDDefinitionIsSkippedNotFatal(t *testing.T) {
	o := &ovalBuilder{}
	badCrit := o.platformCriterion(9) + o.fixCriterion("broken-pkg", "0:1.0-1.el9")
	bad := fmt.Sprintf(
		`<definition class="patch"><metadata><title>no id</title><reference source="CVE" ref_id="CVE-2026-9999"/>`+
			`<advisory><severity>LOW</severity></advisory></metadata><criteria operator="AND">%s</criteria></definition>`,
		badCrit)
	goodCrit := o.platformCriterion(9) + o.fixCriterion("good-pkg", "0:2.0-1.el9")
	good := definitionXML("ELSA-2026-0007", "elsa", "good definition", nil, "LOW", goodCrit)
	doc := o.doc(bad, good)

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	if _, ok := findAdvisory(advs, "ELSA-2026-0007"); !ok {
		t.Fatalf("the well-formed sibling definition did not survive: %+v", advs)
	}
	if st.SkippedNoID != 1 {
		t.Errorf("SkippedNoID = %d, want 1", st.SkippedNoID)
	}
}

// TestParseOVAL_ZeroDefinitionsErrors is the zero-definitions guard: an OVAL
// stream with an empty <definitions> block must fail the fetch rather than
// build a database that silently holds no Oracle Linux data at all.
func TestParseOVAL_ZeroDefinitionsErrors(t *testing.T) {
	doc := `<oval_definitions><generator><oval:timestamp>2026-08-19T10:33:28</oval:timestamp></generator>` +
		`<definitions></definitions><tests></tests><objects></objects><states></states></oval_definitions>`
	var st stats
	_, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err == nil {
		t.Fatal("parseOVAL: no error, want one for zero <definition> elements")
	}
	if !strings.Contains(err.Error(), "definition") {
		t.Errorf("error %q does not name the problem", err)
	}
}
