package redhat

// D47, revised 2026-11-06: Red Hat's corpus regeneration labels the
// whole-product ids `red_hat_enterprise_linux_4..7` cpe:/o:redhat:rhel_els:N.
// A statement under an ELS platform resolves to the major; a versioned fixed
// build under one is dropped and counted on its own.
//
// Caller first (CLAUDE.md): the document-level test drives convert and the
// matcher, and the direct resolveProduct rows below cover the branches a
// document cannot reach one at a time.

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// The regenerated shape of 2026-11-05, as cve-2026-9983/9998/9999 and
// cve-2026-99999 carry it: bare no-fix statements on red_hat_enterprise_linux_6
// under rhel_els:6 beside versioned ELS fixed builds on 7Server-ELS, with a
// mainline RHEL 7 fix and a live RHEL 9 statement in the same document.
func elsDoc(t *testing.T) *document {
	t.Helper()
	return buildDocWithRemediations(t, "CVE-2026-9983",
		map[string]string{
			"red_hat_enterprise_linux_6": "cpe:/o:redhat:rhel_els:6",
			"red_hat_enterprise_linux_9": "cpe:/a:redhat:enterprise_linux:9",
			"6Server-ELS":                "cpe:/o:redhat:rhel_els:6",
			"7Server-ELS":                "cpe:/o:redhat:rhel_els:7",
			"7Server-7.9.Z":              "cpe:/o:redhat:enterprise_linux:7::server",
		},
		[]string{
			// A fix the ELS channel shipped: dropped and counted, not keyed
			// to Red Hat:7 (D47's reason for EUS). Two architectures, one id
			// after stripArch, so the count is per entry as every other
			// product_status counter is.
			"7Server-ELS:webkitgtk4-0:2.48.5-1.el7_9.x86_64",
			"7Server-ELS:webkitgtk4-0:2.48.5-1.el7_9.i686",
			// A mainline RHEL 7 fix in the same document: unchanged.
			"7Server-7.9.Z:openssl-1:1.0.2k-26.el7_9.x86_64",
			// A `fixed` id under ELS with NO version is the same statement
			// convert reads it as on mainline, not a build to drop.
			"6Server-ELS:openssl098e",
		},
		[]string{
			// The statement this revision exists for.
			"red_hat_enterprise_linux_6:kernel",
			"red_hat_enterprise_linux_9:kernel",
		},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"red_hat_enterprise_linux_6:kernel"}},
			{"category": "vendor_fix", "product_ids": []string{"7Server-ELS:webkitgtk4-0:2.48.5-1.el7_9.x86_64"}},
		})
}

func TestConvert_ELSStatementsResolveToTheMajorAndELSFixesAreDropped(t *testing.T) {
	var st stats
	adv, ok := convert(elsDoc(t), &st)
	if !ok {
		t.Fatal("convert dropped a document whose RHEL 6 statements live under rhel_els:6")
	}
	by := affectedByName(adv)

	kernel6, ok := by["Red Hat:6/kernel"]
	if !ok {
		t.Fatalf("no Red Hat:6/kernel entry: the regenerated whole-product statement was dropped; got %v", keysOf(by))
	}
	if len(kernel6.Ranges) != 1 || len(kernel6.Ranges[0].Events) != 1 || kernel6.Ranges[0].Events[0].Introduced != "0" {
		t.Errorf("Red Hat:6/kernel ranges = %+v, want one introduced-0 range with no fixed event", kernel6.Ranges)
	} else if got := kernel6.Ranges[0].FixState; got != advisory.FixStateWontFix {
		t.Errorf("Red Hat:6/kernel fix state = %q, want wont-fix: the no_fix_planned remediation names the same ELS id", got)
	}
	if _, ok := by["Red Hat:7/webkitgtk4"]; ok {
		t.Error("Red Hat:7/webkitgtk4 was emitted: a fix the ELS channel shipped was keyed to the major")
	}
	if a, ok := by["Red Hat:7/openssl"]; !ok || len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 || a.Ranges[0].Events[1].Fixed != "1:1.0.2k-26.el7_9" {
		t.Errorf("Red Hat:7/openssl = %+v, want the mainline fix 1:1.0.2k-26.el7_9 untouched", a)
	}
	if a, ok := by["Red Hat:6/openssl098e"]; !ok || len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 1 {
		t.Errorf("Red Hat:6/openssl098e = %+v, want one open range: a version-less fixed id under ELS is a statement, not a dropped build", a)
	}
	if _, ok := by["Red Hat:9/kernel"]; !ok {
		t.Error("Red Hat:9/kernel missing: a live key's statement changed in a document that also names ELS")
	}
	if st.SkippedELSFixed != 2 {
		t.Errorf("SkippedELSFixed = %d, want 2 (the two webkitgtk4 architectures)", st.SkippedELSFixed)
	}
	if st.SkippedNonRHEL != 0 {
		t.Errorf("SkippedNonRHEL = %d, want 0: an ELS platform is RHEL and must not be counted as a non-mainline product", st.SkippedNonRHEL)
	}
	if st.SkippedModule != 0 || st.SkippedBadProduct != 0 {
		t.Errorf("SkippedModule = %d, SkippedBadProduct = %d, want 0 and 0", st.SkippedModule, st.SkippedBadProduct)
	}

	// Through the real store and matcher: a RHEL 6 kernel is told it is
	// affected with no fix, and a RHEL 7 webkitgtk4 below the ELS build is
	// told nothing by this document (the ELS fix is not quoted at it).
	got := verdictsOf(t, adv,
		pkgmeta.Package{Name: "kernel", Version: "0:2.6.32-754.35.1.el6", Ecosystem: "Red Hat:6"},
		pkgmeta.Package{Name: "webkitgtk4", Version: "0:2.48.4-1.el7_9", Ecosystem: "Red Hat:7"},
		pkgmeta.Package{Name: "openssl", Version: "1:1.0.2k-25.el7_9", Ecosystem: "Red Hat:7"})
	if v := got["Red Hat:6/kernel@0:2.6.32-754.35.1.el6"]; v != affectedNoFix {
		t.Errorf("Red Hat:6 kernel verdict = %q, want %q", v, affectedNoFix)
	}
	if v := got["Red Hat:7/webkitgtk4@0:2.48.4-1.el7_9"]; v != "" {
		t.Errorf("Red Hat:7 webkitgtk4 verdict = %q, want no finding from an ELS-only fix", v)
	}
	if v := got["Red Hat:7/openssl@1:1.0.2k-25.el7_9"]; v != "1:1.0.2k-26.el7_9" {
		t.Errorf("Red Hat:7 openssl verdict = %q, want the mainline fix", v)
	}
}

// The ELS fixed build under an ELS platform carrying a module context: the
// drop happens before the module guards, so SkippedModule's documented zero
// is not fed by a channel this provider does not key on.
func TestResolveProduct_ELS(t *testing.T) {
	cpe := map[string]string{
		"6Server-ELS":                "cpe:/o:redhat:rhel_els:6",
		"AppStream-8-ELS":            "cpe:/a:redhat:rhel_els:8::appstream",
		"red_hat_enterprise_linux_7": "cpe:/o:redhat:rhel_els:7",
		"7Server-7.9.Z":              "cpe:/o:redhat:enterprise_linux:7::server",
	}
	for _, tc := range []struct {
		id      string
		isFixed bool
		wantWhy skipReason
		wantEco string
		wantEVR string
		why     string
	}{
		{"6Server-ELS:polkit-0:0.96-11.el6_10.2.x86_64", true, skipELSFixed, "", "", "a versioned fixed build under ELS"},
		{"6Server-ELS:polkit-0:0.96-11.el6_10.2.x86_64", false, skipNone, "Red Hat:6", "0:0.96-11.el6_10.2", "the same id as a statement (known_affected, or a remediation's target) resolves"},
		{"6Server-ELS:polkit", true, skipNone, "Red Hat:6", "", "a version-less fixed id is a statement on ELS as on mainline"},
		{"red_hat_enterprise_linux_7:kernel", false, skipNone, "Red Hat:7", "", "the regenerated whole-product statement"},
		{"AppStream-8-ELS:nodejs-1:22.0.0-1.module+el8.10.0+77777+abcdef03.x86_64", true, skipELSFixed, "", "", "an ELS build with a module tag and no context is an ELS drop, not SkippedModule's zero"},
		{"7Server-7.9.Z:openssl-1:1.0.2k-26.el7_9.x86_64", true, skipNone, "Red Hat:7", "1:1.0.2k-26.el7_9", "mainline is untouched by the flag"},
	} {
		k, evr, why := resolveProduct(tc.id, tc.isFixed, cpe, nil)
		if why != tc.wantWhy {
			t.Errorf("resolveProduct(%q, fixed=%v) skipReason = %v, want %v -- %s", tc.id, tc.isFixed, why, tc.wantWhy, tc.why)
			continue
		}
		if k.eco != tc.wantEco || evr != tc.wantEVR {
			t.Errorf("resolveProduct(%q, fixed=%v) = (%+v, %q), want eco=%q evr=%q -- %s", tc.id, tc.isFixed, k, evr, tc.wantEco, tc.wantEVR, tc.why)
		}
	}
}

func TestStatsString_ReportsELSFixedBuildsOnTheirOwn(t *testing.T) {
	got := stats{SkippedNonRHEL: 5, SkippedELSFixed: 71, SkippedImage: 2}.String()
	want := "5 non-mainline products, 71 fixed builds on an ELS channel (D47), 2 container images"
	if !strings.Contains(got, want) {
		t.Errorf("stats.String() = %q, want it to contain %q", got, want)
	}
}

func keysOf(m map[string]advisory.Affected) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
