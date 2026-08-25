package suse

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// Every product name, package id and purl below was taken from the live
// archive (fetched 2026-08-19/2026-08-20 from
// https://ftp.suse.com/pub/projects/security/csaf-vex/), not invented.

func TestFoldKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		why  string
		ok   bool
	}{
		// SLES below 16: the "N SPm" shape, folded to "SLES:N.SPm".
		{"SUSE Linux Enterprise Server 15 SP6", "SLES:15.SP6", "the bare mainline product", true},
		{"SUSE Linux Enterprise Server 15", "SLES:15", "the pre-SP1 release carries no SP wording at all", true},
		{"SUSE Linux Enterprise Server 12 SP5", "SLES:12.SP5", "", true},
		{"SUSE Linux Enterprise Server 11 SP4", "SLES:11.SP4", "", true},
		// The module spread: ~20 of these per SP, all folding to the SAME key
		// as the bare mainline product above.
		{"SUSE Linux Enterprise Module for Basesystem 15 SP6", "SLES:15.SP6", "", true},
		{"SUSE Linux Enterprise Module for Python 3 15 SP6", "SLES:15.SP6", "", true},
		{"SUSE Linux Enterprise Module for Server Applications 15 SP4", "SLES:15.SP4", "", true},
		{"SUSE Linux Enterprise Module for Public Cloud 15 SP1", "SLES:15.SP1", "", true},
		// SLES 16 and up: the feed's own product names already drop the "SPn"
		// wording, sampled live -- carried through verbatim.
		{"SUSE Linux Enterprise Server 16.0", "SLES:16.0", "", true},
		{"SUSE Linux Enterprise Server 16.1", "SLES:16.1", "", true},
		// openSUSE Leap: 1:1, no fold.
		{"openSUSE Leap 15.6", "openSUSE Leap:15.6", "", true},
		{"openSUSE Leap 16.0", "openSUSE Leap:16.0", "", true},

		// Refused: Tumbleweed by name, rolling with no release axis.
		{"openSUSE Tumbleweed", "", "rolling, no stable release to key on", false},

		// D91: the plain "-LTSS" support channel on SLES's bare mainline
		// product name folds to the SAME key as its bare/module twin --
		// SLES 15 SP6 going EOL (2025-12-31) means its post-EOL fixes exist
		// ONLY under this product name, so refusing it (as this function
		// did before D91) reports every one of them as "no fix available"
		// on a patched image.
		{"SUSE Linux Enterprise Server 15 SP6-LTSS", "SLES:15.SP6", "the shape this slice exists for -- SP6's post-EOL LTSS fixes", true},
		{"SUSE Linux Enterprise Server 12-LTSS", "SLES:12", "LTSS on a bare, pre-SP1-style major with no SP suffix", true},
		{"SUSE Linux Enterprise Server 15-LTSS", "SLES:15", "LTSS on the bare 15 release", true},
		{"SUSE Linux Enterprise Server 11 SP4-LTSS", "SLES:11.SP4", "", true},

		// The rows that make the ANCHORS load-bearing -- every one of these
		// is a REAL product name sampled from the live archive that shares
		// SLES's or SUSE's namespace but must not fold into a SLES/Leap key,
		// because none of them ships the same package set for the release.
		{"SUSE Linux Enterprise Server for SAP Applications 15 SP4", "", "a different support channel/product (SAP)", false},
		{"SUSE Linux Enterprise Server for SAP applications 16.0", "", "the lowercase-a variant seen live on 16.x", false},
		{"SUSE Linux Enterprise Server 12 SP2-BCL", "", "a different support channel (BCL)", false},
		{"SUSE Linux Enterprise Server 15 SP4-ESPOS", "", "a different support channel (ESPOS)", false},
		{"SUSE Linux Enterprise Server Teradata 12 SP3", "", "Teradata is inserted before the version, not after", false},
		{"SUSE Linux Enterprise Server 11 SP1 for Teradata", "", "trailing text after the SP number", false},
		{"SUSE Linux Enterprise Server Business Critical Linux 15 SP1", "", "a different product", false},
		{"SUSE Linux Enterprise High Performance Computing 15 SP5", "", "HPC is not SLES", false},
		{"SUSE Linux Enterprise High Availability Extension 16.0", "", "HA extension is not SLES 16 itself", false},
		{"SUSE Linux Enterprise Desktop 15 SP6", "", "Desktop is not Server", false},
		{"SUSE Linux Enterprise Micro 5.5", "", "SLE Micro is a different, image-based product", false},
		{"SUSE Linux Micro 6.1", "", "the renamed SLE Micro line, still not SLES", false},
		{"SUSE Enterprise Storage 7.1", "", "Ceph-based storage appliance, not SLES", false},
		{"SUSE Manager Server 4.3", "", "the fleet manager, not a package target", false},
		{"SUSE Liberty Linux 9", "", "SUSE's RHEL-compatible support product", false},
		{"Public Cloud Module for SUSE Linux Enterprise 11", "", "reversed word order, a DIFFERENT product from SLES's own \"Module for Public Cloud\"", false},
		{"SUSE Real Time Module 15 SP6", "", "\"Real Time Module\" does not match \"Module for X\"", false},
		{"SUSE OpenStack Cloud 9", "", "not an OS release at all", false},
		// The trailing-content anchor: without it, a mutation that dropped
		// the $ would let a suffix like "-LTSS" through on the SAME prefix
		// TestFoldKey's SLES rows already exercise.
		{"SUSE Linux Enterprise Server 15 SP6 EXTREME CORE", "", "trailing text after the SP number", false},

		// D91's OWN anchors -- ltssSP is anchored the same way bareSP is,
		// and every one of these is a REAL LTSS-family product name (of the
		// 29 the live census counts) that must still refuse even though the
		// plain shape above now folds, because none of them ships SLES's
		// package set for the release either.
		{"SLES-LTSS-TERADATA 15 SP2", "", "a different prefix entirely, not \"SUSE Linux Enterprise Server\"", false},
		{"SUSE Linux Enterprise Server 12 SP3-LTSS-TERADATA", "", "trailing text after a perfectly good -LTSS suffix", false},
		{"SUSE Linux Enterprise Server 12 SP5-LTSS Extended Security", "", "trailing text after a perfectly good -LTSS suffix", false},
		{"SUSE Linux Enterprise High Performance Computing 15 SP5-LTSS", "", "HPC-LTSS is not SLES-LTSS", false},
	} {
		got, ok := foldKey(tc.name)
		if got != tc.want || ok != tc.ok {
			t.Errorf("foldKey(%q) = %q, %v; want %q, %v -- %s", tc.name, got, ok, tc.want, tc.ok, tc.why)
		}
	}
}

func TestSlesKey(t *testing.T) {
	for _, tc := range []struct{ major, sp, want string }{
		{"15", "", "SLES:15"},
		{"15", "0", "SLES:15"},
		{"15", "6", "SLES:15.SP6"},
		{"12", "5", "SLES:12.SP5"},
	} {
		if got := slesKey(tc.major, tc.sp); got != tc.want {
			t.Errorf("slesKey(%q, %q) = %q, want %q", tc.major, tc.sp, got, tc.want)
		}
	}
}

func TestPackageOf(t *testing.T) {
	for _, tc := range []struct {
		purl      string
		name, ver string
		ok        bool
		why       string
	}{
		{"pkg:rpm/suse/xz@5.6.2-1.1?upstream=xz-5.6.2-1.1.src.rpm", "xz", "5.6.2-1.1", true, ""},
		{"pkg:rpm/suse/xz@?upstream=xz.src.rpm", "xz", "", true, "a bare package: affected at every version"},
		{"pkg:rpm/suse/liblzma5-x86-64-v3@5.8.1-160000.2.2?upstream=xz-5.8.1-160000.2.2.src.rpm",
			"liblzma5-x86-64-v3", "5.8.1-160000.2.2", true, "a hyphenated package name that would defeat a hyphen-split heuristic"},
		{"", "", "", false, "no purl at all (the java-1_7_0-openjdk gap, D77 research)"},
		{"pkg:deb/debian/xz@5.6.2-1", "", "", false, "a different ecosystem's purl shape"},
		{"not-a-purl-at-all", "", "", false, ""},
	} {
		name, ver, ok := packageOf(tc.purl)
		if name != tc.name || ver != tc.ver || ok != tc.ok {
			t.Errorf("packageOf(%q) = (%q, %q, %v), want (%q, %q, %v) -- %s",
				tc.purl, name, ver, ok, tc.name, tc.ver, tc.ok, tc.why)
		}
	}
}

// buildDoc assembles a CSAF document in the shape SUSE actually publishes:
// a single flat product_family branch holding every platform and package
// node side by side (verified live -- SUSE's tree is NOT nested the way
// Red Hat's repository branches are), plus product_status/remediations.
func buildDoc(t *testing.T, cve string, platforms []string, packages map[string]string,
	recommended, knownAffected []string, remediations []map[string]any) *document {
	t.Helper()

	var kids []map[string]any
	for _, name := range platforms {
		kids = append(kids, map[string]any{
			"category": "product_name",
			"name":     name,
			"product": map[string]any{
				"product_id": name,
			},
		})
	}
	for id, purl := range packages {
		kids = append(kids, map[string]any{
			"category": "product_version",
			"name":     id,
			"product": map[string]any{
				"product_id":                    id,
				"product_identification_helper": map[string]any{"purl": purl},
			},
		})
	}

	raw := map[string]any{
		"document": map[string]any{
			"title":    "a test advisory",
			"tracking": map[string]any{"id": cve},
		},
		"product_tree": map[string]any{
			"branches": []any{map[string]any{
				"category": "vendor", "name": "SUSE",
				"branches": []any{map[string]any{
					"category": "product_family", "name": "SUSE Linux Enterprise", "branches": kids,
				}},
			}},
		},
		"vulnerabilities": []any{map[string]any{
			"cve": cve,
			"product_status": map[string]any{
				"recommended":    recommended,
				"known_affected": knownAffected,
				// The biggest bucket in a real document, and never read --
				// mirrors redhat_test.go's identical inclusion of
				// known_not_affected to prove it is ignored rather than
				// merely absent from the fixture.
				"known_not_affected": []string{"SUSE Linux Enterprise Server 15 SP6:something"},
			},
			"remediations": remediations,
			"scores": []any{map[string]any{
				"cvss_v3": map[string]any{"vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			}},
		}},
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func affectedByName(adv advisory.Advisory) map[string]advisory.Affected {
	m := map[string]advisory.Affected{}
	for _, a := range adv.Affected {
		m[a.Ecosystem+"/"+a.Name] = a
	}
	return m
}

// The conversion, end to end, over one document carrying every shape at
// once: a fix on the mainline platform, a fix on a module (folding to the
// SAME key), and an unfixed package on openSUSE Leap.
func TestConvert(t *testing.T) {
	d := buildDoc(t, "CVE-2024-3094",
		[]string{
			"SUSE Linux Enterprise Server 16.0",
			"SUSE Linux Enterprise Module for Basesystem 15 SP6",
			"openSUSE Leap 15.6",
			"openSUSE Tumbleweed",
		},
		map[string]string{
			"xz-5.8.1-160000.2.2": "pkg:rpm/suse/xz@5.8.1-160000.2.2?upstream=xz-5.8.1-160000.2.2.src.rpm",
			"liblzma5-5.6.2-1.1":  "pkg:rpm/suse/liblzma5@5.6.2-1.1?upstream=xz-5.6.2-1.1.src.rpm",
			"libfoo":              "pkg:rpm/suse/libfoo@?upstream=libfoo.src.rpm",
			"xz-5.6.2-1.1":        "pkg:rpm/suse/xz@5.6.2-1.1?upstream=xz-5.6.2-1.1.src.rpm",
		},
		[]string{
			// A fix on the bare mainline SLES 16.0 product.
			"SUSE Linux Enterprise Server 16.0:xz-5.8.1-160000.2.2",
			// A fix on a module product for 15 SP6 -- must collapse to the
			// SAME key as the bare "SUSE Linux Enterprise Server 15 SP6"
			// would (not present in THIS document, but the module alone
			// still resolves the key correctly).
			"SUSE Linux Enterprise Module for Basesystem 15 SP6:liblzma5-5.6.2-1.1",
			// A product this parser never declared as a platform at all.
			"Unknown Platform 9:xz-5.6.2-1.1",
		},
		[]string{
			// The statement this provider exists for: affected, no fix, on
			// openSUSE Leap.
			"openSUSE Leap 15.6:libfoo",
			// Referencing Tumbleweed directly, which must never resolve a
			// key even though it IS a declared platform in this document.
			"openSUSE Tumbleweed:xz-5.6.2-1.1",
		}, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document that names SLES/Leap packages")
	}
	// D90: the ID is SUSE-prefixed so it never collides with Red Hat's record
	// for the same CVE in the store's by-id bucket. The exact ID is asserted
	// (not a Contains check) because "SUSE-CVE-2024-3094" contains
	// "CVE-2024-3094" as a substring — CLAUDE.md's substring-assertion trap.
	if adv.ID != "SUSE-CVE-2024-3094" || adv.Database != "SUSE" || adv.Source != SourceName {
		t.Errorf("identity = %q/%q/%q", adv.ID, adv.Database, adv.Source)
	}
	// D25 grouping runs on ID+aliases, not upstream: the bare CVE has to be
	// here for a Red Hat record naming the same CVE to join this one.
	if len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2024-3094" {
		t.Errorf("Aliases = %v, want the CVE", adv.Aliases)
	}
	if len(adv.Upstream) != 0 {
		t.Errorf("Upstream = %v, want empty -- the CVE now lives in Aliases (D90)", adv.Upstream)
	}
	if len(adv.Severity) != 1 || !strings.HasPrefix(adv.Severity[0].Score, "CVSS:3.1/") {
		t.Errorf("Severity = %+v, want the document's CVSS v3 vector", adv.Severity)
	}

	by := affectedByName(adv)
	if len(by) != 3 {
		t.Fatalf("produced %d affected entries, want 3 (xz on SLES 16.0, liblzma5 folded onto SLES "+
			"15.SP6, libfoo on openSUSE Leap 15.6): %+v", len(by), adv.Affected)
	}

	fix := by["SLES:16.0/xz"]
	if len(fix.Ranges) != 1 {
		t.Fatalf("xz on SLES 16.0 has %d ranges, want 1", len(fix.Ranges))
	}
	ev := fix.Ranges[0].Events
	if len(ev) != 2 || ev[0].Introduced != "0" || ev[1].Fixed != "5.8.1-160000.2.2" {
		t.Errorf("xz events = %+v, want introduced 0 then fixed 5.8.1-160000.2.2", ev)
	}

	moduleFix, ok := by["SLES:15.SP6/liblzma5"]
	if !ok {
		t.Fatal("the module-only fix did not fold onto SLES:15.SP6")
	}
	if len(moduleFix.Ranges) != 1 || moduleFix.Ranges[0].Events[1].Fixed != "5.6.2-1.1" {
		t.Errorf("liblzma5 (module) = %+v, want a single fixed range at 5.6.2-1.1", moduleFix.Ranges)
	}

	unfixed := by["openSUSE Leap:15.6/libfoo"]
	if len(unfixed.Ranges) != 1 || len(unfixed.Ranges[0].Events) != 1 ||
		unfixed.Ranges[0].Events[0].Introduced != "0" || unfixed.Ranges[0].Events[0].Fixed != "" {
		t.Errorf("libfoo events = %+v, want exactly one introduced-0 event and no fixed event", unfixed.Ranges)
	}

	// Every discard is counted.
	if st.SkippedUnknownPlatform != 1 {
		t.Errorf("SkippedUnknownPlatform = %d, want 1 (the undeclared platform)", st.SkippedUnknownPlatform)
	}
	if st.SkippedTumbleweedRef != 1 {
		t.Errorf("SkippedTumbleweedRef = %d, want 1", st.SkippedTumbleweedRef)
	}
	if st.PlatformsTumbleweed != 1 {
		t.Errorf("PlatformsTumbleweed = %d, want 1 (the declared Tumbleweed platform node)", st.PlatformsTumbleweed)
	}
	if st.Unfixable != 1 {
		t.Errorf("Unfixable = %d, want 1", st.Unfixable)
	}
	if st.Affected != 3 {
		t.Errorf("Affected = %d, want 3", st.Affected)
	}
}

// A package fixed on one release and unfixed on another is BOTH, and the
// record has to say so -- mirrors redhat_test.go's
// TestConvert_FixedAndUnfixedTogether exactly, on SUSE's shape.
func TestConvert_FixedAndUnfixedTogether(t *testing.T) {
	d := buildDoc(t, "CVE-2024-0001",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 12 SP5"},
		map[string]string{
			"curl-8.0.0-1.1": "pkg:rpm/suse/curl@8.0.0-1.1?upstream=curl-8.0.0-1.1.src.rpm",
			"curl":           "pkg:rpm/suse/curl@?upstream=curl.src.rpm",
		},
		[]string{"SUSE Linux Enterprise Server 15 SP6:curl-8.0.0-1.1"},
		[]string{"SUSE Linux Enterprise Server 12 SP5:curl"}, nil)

	var st stats
	adv, _ := convert(d, &st)
	by := affectedByName(adv)
	if got := by["SLES:15.SP6/curl"]; len(got.Ranges) != 1 || got.Ranges[0].Events[1].Fixed == "" {
		t.Errorf("SLES 15 SP6 curl = %+v, want a fixed range", got.Ranges)
	}
	if got := by["SLES:12.SP5/curl"]; len(got.Ranges) != 1 || len(got.Ranges[0].Events) != 1 {
		t.Errorf("SLES 12 SP5 curl = %+v, want one unfixed range", got.Ranges)
	}
}

// Two fixed versions for one (release, package): both are kept, mirroring
// redhat_test.go's TestConvert_TwoFixedVersionsKeepBoth.
func TestConvert_TwoFixedVersionsKeepBoth(t *testing.T) {
	d := buildDoc(t, "CVE-2024-0002",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Module for Basesystem 15 SP6"},
		map[string]string{
			"zlib-1.2.11-40.1": "pkg:rpm/suse/zlib@1.2.11-40.1?upstream=zlib-1.2.11-40.1.src.rpm",
			"zlib-1.2.11-41.1": "pkg:rpm/suse/zlib@1.2.11-41.1?upstream=zlib-1.2.11-41.1.src.rpm",
		},
		[]string{
			"SUSE Linux Enterprise Server 15 SP6:zlib-1.2.11-40.1",
			"SUSE Linux Enterprise Module for Basesystem 15 SP6:zlib-1.2.11-41.1",
		}, nil, nil)

	var st stats
	adv, _ := convert(d, &st)
	a := affectedByName(adv)["SLES:15.SP6/zlib"]
	if len(a.Ranges) != 2 {
		t.Fatalf("zlib has %d ranges, want 2: %+v", len(a.Ranges), a.Ranges)
	}
	if a.Ranges[0].Events[1].Fixed != "1.2.11-40.1" || a.Ranges[1].Events[1].Fixed != "1.2.11-41.1" {
		t.Errorf("ranges are not in a stable order: %+v", a.Ranges)
	}
}

// D91: SLES 15 SP6 going EOL (2025-12-31, under LTSS to 2028-12-31) means its
// post-EOL fixes exist ONLY under the "-LTSS" product name in the real feed
// -- curl CVE-2026-10536, fixed 8.14.1-150600.4.46.1, is exactly this shape,
// verified live. With no bare or module entry anywhere in the document, the
// LTSS entry is the sole source and must fold onto SLES:15.SP6 exactly like
// a mainline entry would, not be refused as "no fix available" the way it
// was before D91.
func TestConvert_LTSSOnlyFixFoldsToMainlineKey(t *testing.T) {
	d := buildDoc(t, "CVE-2026-10536",
		[]string{"SUSE Linux Enterprise Server 15 SP6-LTSS"},
		map[string]string{
			"curl-8.14.1-150600.4.46.1": "pkg:rpm/suse/curl@8.14.1-150600.4.46.1?upstream=curl-8.14.1-150600.4.46.1.src.rpm",
		},
		[]string{"SUSE Linux Enterprise Server 15 SP6-LTSS:curl-8.14.1-150600.4.46.1"},
		nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document whose only fix is an LTSS-only entry")
	}
	fix, found := affectedByName(adv)["SLES:15.SP6/curl"]
	if !found {
		t.Fatal("the LTSS-only fix did not fold onto SLES:15.SP6 -- this is the SP6 post-EOL case D91 exists for")
	}
	if len(fix.Ranges) != 1 || len(fix.Ranges[0].Events) != 2 ||
		fix.Ranges[0].Events[0].Introduced != "0" || fix.Ranges[0].Events[1].Fixed != "8.14.1-150600.4.46.1" {
		t.Errorf("curl events = %+v, want introduced 0 then fixed 8.14.1-150600.4.46.1", fix.Ranges)
	}
	if st.SkippedLTSSShadowedByMainline != 0 {
		t.Errorf("SkippedLTSSShadowedByMainline = %d, want 0 -- nothing in this document shadows this fix", st.SkippedLTSSShadowedByMainline)
	}
}

// D91's tie-break: a document carrying BOTH a bare-SP6 fix and its SP6-LTSS
// twin for the SAME package -- the real measured shape (kernel-default
// 6.4.0-150600.21.3 mainline vs. 6.4.0-150600.23.84.1 LTSS, CVE-2023-42752,
// one of 9,308 same-document pairs measured with differing fixed versions)
// -- keeps only the MAINLINE entry and drops the LTSS twin, counted. Without
// this, both fold onto the SAME key and the record would carry two EVRs for
// one CVE and package, exactly the collision D25/D74 forbid.
func TestConvert_LTSSShadowedByMainlineSameDocument(t *testing.T) {
	d := buildDoc(t, "CVE-2023-42752",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise Server 15 SP6-LTSS"},
		map[string]string{
			"kernel-default-6.4.0-150600.21.3":    "pkg:rpm/suse/kernel-default@6.4.0-150600.21.3?upstream=kernel-source-6.4.0-150600.21.3.src.rpm",
			"kernel-default-6.4.0-150600.23.84.1": "pkg:rpm/suse/kernel-default@6.4.0-150600.23.84.1?upstream=kernel-source-6.4.0-150600.23.84.1.src.rpm",
		},
		[]string{
			"SUSE Linux Enterprise Server 15 SP6:kernel-default-6.4.0-150600.21.3",
			"SUSE Linux Enterprise Server 15 SP6-LTSS:kernel-default-6.4.0-150600.23.84.1",
		}, nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming an SLES package")
	}
	got := affectedByName(adv)["SLES:15.SP6/kernel-default"]
	if len(got.Ranges) != 1 {
		t.Fatalf("kernel-default has %d ranges, want exactly 1 -- the LTSS twin must be DROPPED, not "+
			"kept as a second range for the same key and package: %+v", len(got.Ranges), got.Ranges)
	}
	if got.Ranges[0].Events[1].Fixed != "6.4.0-150600.21.3" {
		t.Errorf("kernel-default fixed version = %q, want the MAINLINE EVR 6.4.0-150600.21.3, not the LTSS one",
			got.Ranges[0].Events[1].Fixed)
	}
	if st.SkippedLTSSShadowedByMainline != 1 {
		t.Errorf("SkippedLTSSShadowedByMainline = %d, want 1", st.SkippedLTSSShadowedByMainline)
	}
}

// D91 applies the identical rule to known_affected/no-fix entries: an
// LTSS-only no-fix statement (with its remediation reason) folds onto the
// mainline key exactly like a fixed one does.
func TestConvert_LTSSOnlyKnownAffectedFoldsWithFixState(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2026-2001",
		[]string{"SUSE Linux Enterprise Server 15 SP6-LTSS"},
		map[string]string{"libltssnofix": "pkg:rpm/suse/libltssnofix@?upstream=libltssnofix.src.rpm"},
		nil, []string{"SUSE Linux Enterprise Server 15 SP6-LTSS:libltssnofix"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6-LTSS:libltssnofix"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming an SLES 15 SP6-LTSS package")
	}
	a := affectedByName(adv)["SLES:15.SP6/libltssnofix"]
	if len(a.Ranges) != 1 {
		t.Fatalf("libltssnofix has %d ranges, want 1: %+v", len(a.Ranges), a.Ranges)
	}
	if a.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q (no_fix_planned, folded from the LTSS-only entry)",
			a.Ranges[0].FixState, advisory.FixStateWontFix)
	}
	if st.UnfixableWontFix != 1 {
		t.Errorf("UnfixableWontFix = %d, want 1", st.UnfixableWontFix)
	}
	if st.SkippedLTSSShadowedByMainline != 0 {
		t.Errorf("SkippedLTSSShadowedByMainline = %d, want 0 -- nothing in this document shadows this entry", st.SkippedLTSSShadowedByMainline)
	}
}

// A document naming nothing this provider ingests produces no record at all.
func TestConvert_DropsDocumentsWithNothingToStore(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cve         string
		platforms   []string
		packages    map[string]string
		recommended []string
	}{
		{"only unfoldable platforms", "CVE-2024-0003",
			[]string{"SUSE Linux Enterprise High Performance Computing 15 SP5"},
			map[string]string{"pkg-1.0-1.1": "pkg:rpm/suse/pkg@1.0-1.1?upstream=pkg-1.0-1.1.src.rpm"},
			[]string{"SUSE Linux Enterprise High Performance Computing 15 SP5:pkg-1.0-1.1"}},
		{"only Tumbleweed", "CVE-2024-0004",
			[]string{"openSUSE Tumbleweed"},
			map[string]string{"pkg-1.0-1.1": "pkg:rpm/suse/pkg@1.0-1.1?upstream=pkg-1.0-1.1.src.rpm"},
			[]string{"openSUSE Tumbleweed:pkg-1.0-1.1"}},
		{"not a CVE id", "SUSE-SU-2024:0001-1",
			[]string{"SUSE Linux Enterprise Server 15 SP6"},
			map[string]string{"pkg-1.0-1.1": "pkg:rpm/suse/pkg@1.0-1.1?upstream=pkg-1.0-1.1.src.rpm"},
			[]string{"SUSE Linux Enterprise Server 15 SP6:pkg-1.0-1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var st stats
			if _, ok := convert(buildDoc(t, tc.cve, tc.platforms, tc.packages, tc.recommended, nil, nil), &st); ok {
				t.Error("a document with nothing storable produced an advisory")
			}
		})
	}
}

// buildDocWithRemediations is buildDoc with explicit remediations, matching
// redhat_test.go's identical split (buildDoc vs buildDocWithRemediations) so
// the D52 tests below do not force every OTHER test to pass a nil parameter.
func buildDocWithRemediations(t *testing.T, cve string, platforms []string, packages map[string]string,
	recommended, knownAffected []string, remediations []map[string]any) *document {
	return buildDoc(t, cve, platforms, packages, recommended, knownAffected, remediations)
}

// D52: a known_affected package named by a no_fix_planned remediation is
// "won't fix" -- mirrors redhat_test.go's TestConvert_RemediationNoFixPlanned.
func TestConvert_RemediationNoFixPlanned(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1001",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{"libwontfix": "pkg:rpm/suse/libwontfix@?upstream=libwontfix.src.rpm"},
		nil, []string{"SUSE Linux Enterprise Server 15 SP6:libwontfix"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libwontfix"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming an SLES package")
	}
	a := affectedByName(adv)["SLES:15.SP6/libwontfix"]
	if len(a.Ranges) != 1 {
		t.Fatalf("libwontfix has %d ranges, want 1: %+v", len(a.Ranges), a.Ranges)
	}
	if a.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q (no_fix_planned)", a.Ranges[0].FixState, advisory.FixStateWontFix)
	}
	if st.UnfixableWontFix != 1 {
		t.Errorf("UnfixableWontFix = %d, want 1", st.UnfixableWontFix)
	}
}

// The other half of the same distinction: none_available is "no fix yet".
// SUSE's own feed has been measured to never use this category (D77
// research), but the machinery still has to honour it if the feed ever
// starts -- mirrors redhat_test.go's TestConvert_RemediationNoneAvailable.
func TestConvert_RemediationNoneAvailable(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1002",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{"libnotfixedyet": "pkg:rpm/suse/libnotfixedyet@?upstream=libnotfixedyet.src.rpm"},
		nil, []string{"SUSE Linux Enterprise Server 15 SP6:libnotfixedyet"},
		[]map[string]any{
			{"category": "none_available", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libnotfixedyet"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming an SLES package")
	}
	a := affectedByName(adv)["SLES:15.SP6/libnotfixedyet"]
	if len(a.Ranges) != 1 {
		t.Fatalf("libnotfixedyet has %d ranges, want 1: %+v", len(a.Ranges), a.Ranges)
	}
	if a.Ranges[0].FixState != advisory.FixStateNotFixed {
		t.Errorf("FixState = %q, want %q (none_available)", a.Ranges[0].FixState, advisory.FixStateNotFixed)
	}
	if st.UnfixableNotFixed != 1 {
		t.Errorf("UnfixableNotFixed = %d, want 1", st.UnfixableNotFixed)
	}
}

// Both reasons named for one package: the tie breaks toward wont-fix, and
// both the resolved state and the overlap counter are asserted -- mirrors
// redhat_test.go's TestConvert_RemediationBothReasons.
func TestConvert_RemediationBothReasons(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1003",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{"libbothreasons": "pkg:rpm/suse/libbothreasons@?upstream=libbothreasons.src.rpm"},
		nil, []string{"SUSE Linux Enterprise Server 15 SP6:libbothreasons"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libbothreasons"}},
			{"category": "none_available", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libbothreasons"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming an SLES package")
	}
	a := affectedByName(adv)["SLES:15.SP6/libbothreasons"]
	if len(a.Ranges) != 1 || a.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("Ranges = %+v, want a single range resolved to %q", a.Ranges, advisory.FixStateWontFix)
	}
	if st.UnfixableBothReasons != 1 {
		t.Errorf("UnfixableBothReasons = %d, want 1", st.UnfixableBothReasons)
	}
	if st.UnfixableWontFix != 1 || st.UnfixableNotFixed != 0 {
		t.Errorf("UnfixableWontFix/UnfixableNotFixed = %d/%d, want 1/0", st.UnfixableWontFix, st.UnfixableNotFixed)
	}
}

// A package the product_status calls affected but no remediation explains
// comes out unstated rather than guessed at -- mirrors redhat_test.go's
// TestConvert_RemediationUnstated.
func TestConvert_RemediationUnstated(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1004",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{
			"libnoremedy":      "pkg:rpm/suse/libnoremedy@?upstream=libnoremedy.src.rpm",
			"libvendorfixonly": "pkg:rpm/suse/libvendorfixonly@?upstream=libvendorfixonly.src.rpm",
		},
		nil, []string{
			"SUSE Linux Enterprise Server 15 SP6:libnoremedy",
			"SUSE Linux Enterprise Server 15 SP6:libvendorfixonly",
		},
		[]map[string]any{
			{"category": "vendor_fix", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libvendorfixonly"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming SLES packages")
	}
	by := affectedByName(adv)
	for _, name := range []string{"libnoremedy", "libvendorfixonly"} {
		a := by["SLES:15.SP6/"+name]
		if len(a.Ranges) != 1 {
			t.Fatalf("%s has %d ranges, want 1: %+v", name, len(a.Ranges), a.Ranges)
		}
		if got := a.Ranges[0].FixState.String(); got != advisory.FixStateUnknown.String() {
			t.Errorf("%s FixState.String() = %q, want %q", name, got, advisory.FixStateUnknown.String())
		}
	}
	if st.UnfixableUnstated != 2 {
		t.Errorf("UnfixableUnstated = %d, want 2", st.UnfixableUnstated)
	}
}

// A remediation naming a product outside the SLES/Leap key fold is not a
// discard at all -- mirrors redhat_test.go's
// TestConvert_RemediationOutsideMainlineDoesNotInflateSkipped.
func TestConvert_RemediationOutsideFoldDoesNotInflateSkipped(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1005",
		[]string{"SUSE Linux Enterprise Server 15 SP6", "SUSE Linux Enterprise High Performance Computing 15 SP5"},
		map[string]string{
			"libreal": "pkg:rpm/suse/libreal@?upstream=libreal.src.rpm",
			"libhpc":  "pkg:rpm/suse/libhpc@?upstream=libhpc.src.rpm",
		},
		nil, []string{"SUSE Linux Enterprise Server 15 SP6:libreal"},
		[]map[string]any{
			// A platform this fold does not cover.
			{"category": "no_fix_planned", "product_ids": []string{"SUSE Linux Enterprise High Performance Computing 15 SP5:libhpc"}},
			// A platform this document never declared.
			{"category": "no_fix_planned", "product_ids": []string{"Undeclared Platform 9:libundeclared"}},
			// Tumbleweed, referenced directly.
			{"category": "no_fix_planned", "product_ids": []string{"openSUSE Tumbleweed:libreal"}},
		})
	var st stats
	if _, ok := convert(d, &st); !ok {
		t.Fatal("convert dropped a document naming an SLES package")
	}
	if st.SkippedUnfoldablePlatform != 0 {
		t.Errorf("SkippedUnfoldablePlatform = %d, want 0 -- only product_status discards are counted", st.SkippedUnfoldablePlatform)
	}
	if st.SkippedUnknownPlatform != 0 {
		t.Errorf("SkippedUnknownPlatform = %d, want 0", st.SkippedUnknownPlatform)
	}
	if st.SkippedTumbleweedRef != 0 {
		t.Errorf("SkippedTumbleweedRef = %d, want 0", st.SkippedTumbleweedRef)
	}
}

// The three D52 counters are disjoint and sum to Unfixable -- mirrors
// redhat_test.go's TestConvert_UnfixableCountersSumToTotal.
func TestConvert_UnfixableCountersSumToTotal(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1008",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{
			"libsumwont":     "pkg:rpm/suse/libsumwont@?upstream=libsumwont.src.rpm",
			"libsumnotfixed": "pkg:rpm/suse/libsumnotfixed@?upstream=libsumnotfixed.src.rpm",
			"libsumunstated": "pkg:rpm/suse/libsumunstated@?upstream=libsumunstated.src.rpm",
		},
		nil, []string{
			"SUSE Linux Enterprise Server 15 SP6:libsumwont",
			"SUSE Linux Enterprise Server 15 SP6:libsumnotfixed",
			"SUSE Linux Enterprise Server 15 SP6:libsumunstated",
		},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libsumwont"}},
			{"category": "none_available", "product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:libsumnotfixed"}},
		})
	var st stats
	if _, ok := convert(d, &st); !ok {
		t.Fatal("convert dropped a document naming SLES packages")
	}
	if st.Unfixable != 3 {
		t.Fatalf("Unfixable = %d, want 3", st.Unfixable)
	}
	if sum := st.UnfixableWontFix + st.UnfixableNotFixed + st.UnfixableUnstated; sum != st.Unfixable {
		t.Errorf("UnfixableWontFix(%d) + UnfixableNotFixed(%d) + UnfixableUnstated(%d) = %d, want Unfixable(%d)",
			st.UnfixableWontFix, st.UnfixableNotFixed, st.UnfixableUnstated, sum, st.Unfixable)
	}
}

// A package with no readable purl is counted and skipped rather than
// resolved from the raw id string.
func TestConvert_NoPurlIsCountedAndSkipped(t *testing.T) {
	d := buildDoc(t, "CVE-2013-3813",
		[]string{"SUSE Linux Enterprise Server 12 SP5"},
		map[string]string{
			// No purl at all -- the java-1_7_0-openjdk shape measured live.
			"java-1_7_0-openjdk-1.7.0.85-30.1": "",
			"curl-8.0.0-1.1":                   "pkg:rpm/suse/curl@8.0.0-1.1?upstream=curl-8.0.0-1.1.src.rpm",
		},
		[]string{
			"SUSE Linux Enterprise Server 12 SP5:java-1_7_0-openjdk-1.7.0.85-30.1",
			"SUSE Linux Enterprise Server 12 SP5:curl-8.0.0-1.1",
		}, nil, nil)
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming an SLES package")
	}
	if len(adv.Affected) != 1 || adv.Affected[0].Name != "curl" {
		t.Errorf("Affected = %+v, want only curl -- the no-purl entry must not be guessed at", adv.Affected)
	}
	if st.SkippedNoPurl != 1 {
		t.Errorf("SkippedNoPurl = %d, want 1", st.SkippedNoPurl)
	}
	if st.SkippedUnknownPackage != 1 {
		t.Errorf("SkippedUnknownPackage = %d, want 1 -- the product_status entry referencing the no-purl leaf", st.SkippedUnknownPackage)
	}
}
