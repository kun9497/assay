package scancmd

import (
	"fmt"
	"strings"
	"testing"
)

// Review of v0.18.5 (2026-11-18). A generic display name ("linux") lends no
// codename, but the codename it states is still a statement: with no version
// of its own to be held to, a version-less declaration's noble had been
// erased before the document-wide merge met the target's jammy, and the
// JAMMY waiver was granted -- where the same declaration named "ubuntu", ""
// or "Ubuntu Core" refused it. Sibling and nested placement, both orders.
func TestRun_CDXVersionlessGenericOSCannotEraseCodenameConflict(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	vf := writeVEX(t, stmt("CVE-2031-9110", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))
	const apt = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	topOS := func(codename string) string {
		props := `{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"22.04"}`
		if codename != "" {
			props += `,{"name":"syft:distro:versionCodename","value":"` + codename + `"}`
		}
		return `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[` + props + `]}`
	}
	second := func(name, codename string, nested bool) string {
		os := fmt.Sprintf(`{"type":"operating-system","name":%q,"properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionCodename","value":%q}]}`, name, codename)
		if nested {
			return `{"type":"library","purl":"pkg:npm/is-number@7.0.0","components":[` + os + `]}`
		}
		return os
	}
	scan := func(t *testing.T, top, other string, reverse bool) (exit, findings, suppressed, evaluated int) {
		t.Helper()
		components := top + "," + apt + "," + other
		if reverse {
			components = other + "," + apt + "," + top
		}
		rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+components+`]}`, vf)
		return rc, len(rep.Findings), len(rep.Suppressed), rep.Summary.Evaluated
	}
	for _, name := range []string{"ubuntu", "", "Ubuntu Core", "linux", "Linux"} {
		for _, nested := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%q/nested=%t/reverse=%t", name, nested, reverse), func(t *testing.T) {
					// The version-less declaration says noble, the target jammy.
					if rc, findings, suppressed, evaluated := scan(t, topOS("jammy"), second(name, "noble", nested), reverse); rc != 1 || findings != 1 || suppressed != 0 || evaluated != 1 {
						t.Errorf("noble beside jammy: exit %d, findings %d, suppressed %d, evaluated %d; want 1, 1, 0, 1", rc, findings, suppressed, evaluated)
					}
					// Control: one that agrees takes nothing away, so the
					// refusal above is the contradiction's and not the
					// declaration's presence.
					if rc, findings, suppressed, evaluated := scan(t, topOS("jammy"), second(name, "jammy", nested), reverse); rc != 0 || findings != 0 || suppressed != 1 || evaluated != 1 {
						t.Errorf("jammy beside jammy: exit %d, findings %d, suppressed %d, evaluated %d; want 0, 0, 1, 1", rc, findings, suppressed, evaluated)
					}
					// A generic name still lends nothing: its jammy beside a
					// target that states no codename grants no waiver, where
					// a declaration naming Ubuntu lends it.
					wantExit, wantSuppressed := 0, 1
					if strings.EqualFold(name, "linux") {
						wantExit, wantSuppressed = 1, 0
					}
					if rc, findings, suppressed, evaluated := scan(t, topOS(""), second(name, "jammy", nested), reverse); rc != wantExit || suppressed != wantSuppressed || findings != 1-wantSuppressed || evaluated != 1 {
						t.Errorf("jammy beside no codename: exit %d, findings %d, suppressed %d, evaluated %d; want %d, %d, %d, 1", rc, findings, suppressed, evaluated, wantExit, 1-wantSuppressed, wantSuppressed)
					}
				})
			}
		}
	}
	// The set-aside codename is under the version-less rule like any other:
	// beside an OS of another vendor the document cannot say whose
	// declaration it is, and it gives nothing -- no contradiction either,
	// under a generic name as under Ubuntu's own.
	const debian = `{"type":"library","purl":"pkg:npm/is-odd@3.0.1","components":[{"type":"operating-system","name":"debian","version":"12"}]}`
	for _, name := range []string{"ubuntu", "linux"} {
		for _, reverse := range []bool{false, true} {
			if rc, findings, suppressed, evaluated := scan(t, topOS("jammy"), second(name, "noble", true)+","+debian, reverse); rc != 0 || findings != 0 || suppressed != 1 || evaluated != 1 {
				t.Errorf("%q noble beside jammy and a Debian branch, reverse=%t: exit %d, findings %d, suppressed %d, evaluated %d; want 0, 0, 1, 1", name, reverse, rc, findings, suppressed, evaluated)
			}
		}
	}
}

// Review of v0.18.5 (2026-11-18). With no operating-system component, a
// listing that states no release and its twin whose `distro=` names a
// release no advisory key exists for are one install listed twice -- as the
// same bare listing joins a debian-12 twin, and a sid twin when an OS
// component declares sid. The qualifier-only release identity (6c975a3) had
// counted it as two packages and two skips.
func TestRun_CDXBareListingJoinsItsQualifierOnlyUncoveredTwin(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"QA-12", "CVE-2031-9110", "apt", "3.0.4"})
	lib := func(qualifiers string) string {
		purl := "pkg:deb/debian/apt@3.0.3"
		if qualifiers != "" {
			purl += "?" + qualifiers
		}
		return `{"type":"library","purl":"` + purl + `"}`
	}
	doc := func(top []string, subject string) string {
		return `{"bomFormat":"CycloneDX","components":[` + strings.Join(top, ",") + `],"metadata":{"component":` + subject + `}}`
	}
	const sidOS = `{"type":"operating-system","name":"debian","version":"sid"}`
	for _, tc := range []struct {
		name                           string
		top                            []string
		subject                        string
		components, evaluated, skipped int
	}{
		{"bare top, sid subject", []string{lib("")}, lib("distro=debian-sid"), 1, 0, 1},
		{"sid top, bare subject", []string{lib("distro=debian-sid")}, lib(""), 1, 0, 1},
		{"bare top, sid amd64 subject", []string{lib("")}, lib("arch=amd64&distro=debian-sid"), 1, 0, 1},
		{"sid amd64 top, bare subject", []string{lib("arch=amd64&distro=debian-sid")}, lib(""), 1, 0, 1},
		// The neighbours the join is consistent with.
		{"bare top, debian-12 subject", []string{lib("")}, lib("distro=debian-12"), 1, 1, 0},
		{"debian-12 top, bare subject", []string{lib("distro=debian-12")}, lib(""), 1, 1, 0},
		{"sid OS, bare top, sid subject", []string{sidOS, lib("")}, lib("distro=debian-sid"), 1, 0, 1},
		// A bare listing joins only when the document names one release for
		// it. Beside a twin of another release it could be either, and stays
		// a package of its own.
		{"bare and debian-12 top, sid subject", []string{lib(""), lib("distro=debian-12")}, lib("distro=debian-sid"), 3, 1, 2},
		{"debian-12 and bare top, sid subject", []string{lib("distro=debian-12"), lib("")}, lib("distro=debian-sid"), 3, 1, 2},
		{"bare top, sid subject over an experimental child", []string{lib("")},
			strings.TrimSuffix(lib("distro=debian-sid"), "}") + `,"components":[` + lib("distro=debian-experimental") + `]}`, 3, 0, 3},
		// Every bare listing of the name and version is that install, as
		// all of them were one identity before the qualifier-only release.
		{"bare top, sid subject over a bare child", []string{lib("")},
			strings.TrimSuffix(lib("distro=debian-sid"), "}") + `,"components":[` + lib("") + `]}`, 1, 0, 1},
		{"bare and sid top, bare subject", []string{lib(""), lib("distro=debian-sid")}, lib(""), 2, 0, 2},
		// A release an OS declaration gives its branch is that branch's,
		// not a qualifier's: the bare listing outside it stays apart, as it
		// did.
		{"bare top, bare child of a sid OS subject", []string{lib("")},
			strings.TrimSuffix(sidOS, "}") + `,"components":[` + lib("") + `]}`, 2, 0, 2},
		// Two listings that each name a release are never one (the 6c975a3
		// rule this must not undo).
		{"sid top, debian-12 subject", []string{lib("distro=debian-sid")}, lib("distro=debian-12"), 2, 1, 1},
		{"debian-12 top, sid subject", []string{lib("distro=debian-12")}, lib("distro=debian-sid"), 2, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, _ := scanOSRegression(t, db, doc(tc.top, tc.subject))
			if rep.Summary.Components != tc.components || rep.Summary.Evaluated != tc.evaluated || len(rep.Skipped) != tc.skipped {
				t.Fatalf("components %d, evaluated %d, skipped %d; want %d, %d, %d\nskips %+v",
					rep.Summary.Components, rep.Summary.Evaluated, len(rep.Skipped), tc.components, tc.evaluated, tc.skipped, rep.Skipped)
			}
		})
	}
}

// Guards in the operating-system reading that no test held (review of
// v0.18.5, 2026-11-18): each line could be deleted with the suite green
// while the scan's answer changed.
func TestRun_CDXOSIdentityGuards(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"QA-22", "CVE-2031-9110", "apt", "2.4.99"})
	vf := writeVEX(t, stmt("CVE-2031-9110", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))
	const top = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:versionCodename","value":"jammy"}]}`
	const apt = `{"type":"library","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	osDecl := func(name, version string, props ...[2]string) string {
		var ps []string
		for _, p := range props {
			ps = append(ps, fmt.Sprintf(`{"name":%q,"value":%q}`, p[0], p[1]))
		}
		return fmt.Sprintf(`{"type":"operating-system","name":%q,"version":%q,"properties":[%s]}`, name, version, strings.Join(ps, ","))
	}
	branch := func(os string) string {
		return `{"type":"library","purl":"pkg:npm/is-number@7.0.0","components":[` + os + `]}`
	}
	id := func(v string) [2]string { return [2]string{"syft:distro:id", v} }
	codename := func(v string) [2]string { return [2]string{"syft:distro:versionCodename", v} }
	pretty := func(v string) [2]string { return [2]string{"syft:distro:prettyName", v} }
	for _, tc := range []struct {
		name, components                      string
		vex                                   bool
		exit, evaluated, findings, suppressed int
	}{
		// A generic-named declaration whose ids contradict each other is
		// still an Ubuntu declaration contradicting itself, in either order
		// of its ids, and voids the document's codename. The quiet side:
		// read as not Ubuntu it only stops being counted, and the waiver is
		// granted.
		{"ids debian then ubuntu void the codename", top + "," + apt + "," + branch(osDecl("linux", "22.04", id("debian"), id("ubuntu"))), true, 1, 1, 1, 0},
		{"ids ubuntu then debian void the codename", top + "," + apt + "," + branch(osDecl("linux", "22.04", id("ubuntu"), id("debian"))), true, 1, 1, 1, 0},
		// Control: the same declaration naming Debian alone says nothing
		// about an Ubuntu codename.
		{"id debian alone voids nothing", top + "," + apt + "," + branch(osDecl("linux", "22.04", id("debian"))), true, 0, 1, 0, 1},
		// "Ubuntu Core" is Ubuntu's own name for itself, not a generic one:
		// its codename is evidence. ("linux" in its place lends none --
		// TestRun_CDXGenericOSNameCannotEraseCodenameConflict.)
		{"Ubuntu Core lends its codename", osDecl("Ubuntu Core", "22.04", id("ubuntu"), codename("jammy")) + "," + apt, true, 0, 1, 0, 1},
		// An empty syft id falls back to the component name, so a second id
		// that differs from the name contradicts it even when this build
		// does not know that id: the declaration keys nothing and the purl's
		// own distro= does. Read as the unknown id alone, the declaration
		// would be an OS of no key and switch the qualifier off.
		{"empty id beside an unknown one contradicts the name", osDecl("ubuntu", "22.04", id(""), id("weirdos")) + "," + apt, false, 1, 1, 1, 0},
		{"unknown id beside an empty one contradicts the name", osDecl("ubuntu", "22.04", id("weirdos"), id("")) + "," + apt, false, 1, 1, 1, 0},
		{"an unknown id alone is the declaration's identity", osDecl("ubuntu", "22.04", id("weirdos")) + "," + apt, false, 2, 0, 0, 0},
		// The syft id is the identity when it does not contradict the name:
		// a declaration named ubuntu whose id is another distro's is not an
		// Ubuntu declaration, so its noble contradicts no Ubuntu codename
		// and its pretty names are not held to Ubuntu's LTS rule.
		{"name ubuntu under another id states no Ubuntu codename", top + "," + apt + "," + branch(osDecl("ubuntu", "22.04", id("pop"), codename("noble"))), true, 0, 1, 0, 1},
		{"name ubuntu under another id is not held to the LTS rule", top + "," + apt + "," + branch(osDecl("ubuntu", "22.04", id("pop"), pretty("Pop 22.04 LTS"), pretty("Pop 22.04"))), true, 0, 1, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var vex []string
			if tc.vex {
				vex = []string{vf}
			}
			rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+tc.components+`]}`, vex...)
			if rc != tc.exit || rep.Summary.Evaluated != tc.evaluated || len(rep.Findings) != tc.findings || len(rep.Suppressed) != tc.suppressed {
				t.Fatalf("exit %d, evaluated %d, findings %d, suppressed %d; want %d, %d, %d, %d\nskips %+v",
					rc, rep.Summary.Evaluated, len(rep.Findings), len(rep.Suppressed), tc.exit, tc.evaluated, tc.findings, tc.suppressed, rep.Skipped)
			}
		})
	}
}

// A `distro=` naming a vendor this build does not know identifies no
// release, so its listing is still the unkeyed twin of the subject's keyed
// one -- one package, judged. Read as a release identity of its own (the
// qualifier-only rule without its known-vendor check) it would stay a second
// package and a spurious skip. The sid listing beside it is the control: a
// known vendor's uncovered release IS its own install.
func TestRun_CDXUnknownVendorQualifierIsNotAReleaseIdentity(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"QA-12", "CVE-2031-9110", "apt", "3.0.4"})
	for _, tc := range []struct {
		qualifier                      string
		components, evaluated, skipped int
	}{
		{"weirdos-1", 1, 1, 0},
		{"debian-sid", 2, 1, 1},
	} {
		for _, reverse := range []bool{false, true} {
			a, b := `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?distro=`+tc.qualifier+`"}`, `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?distro=debian-12"}`
			if reverse {
				a, b = b, a
			}
			rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+a+`],"metadata":{"component":`+b+`}}`)
			if rc != 1 || rep.Summary.Components != tc.components || rep.Summary.Evaluated != tc.evaluated || len(rep.Findings) != 1 || len(rep.Skipped) != tc.skipped {
				t.Errorf("distro=%s reverse=%t: exit %d, summary %+v, findings %d, skipped %+v", tc.qualifier, reverse, rc, rep.Summary, len(rep.Findings), rep.Skipped)
			}
		}
	}
}

// A release the siblings declare without a key (Debian sid) is still named
// by a package's own `distro=` when another sibling contradicts itself or is
// of another vendor: the listing is the sid install, uncovered, and not a
// package the contradiction leaves without a release. The bare listing
// beside the same declarations is the control -- nothing says which it is.
func TestRun_CDXUncoveredSiblingReleaseSurvivesAConflictingSibling(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"QA-12", "CVE-2031-9110", "apt", "3.0.4"})
	const sid = `{"type":"operating-system","name":"debian","version":"sid"}`
	const qualified = `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?distro=debian-sid"}`
	const bare = `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3"}`
	for _, tc := range []struct{ name, other, reason string }{
		{"self-contradicting sibling", `{"type":"operating-system","name":"debian","version":"12","properties":[{"name":"syft:distro:versionID","value":"11"}]}`, "contradicts itself"},
		{"sibling of another vendor", `{"type":"operating-system","name":"ubuntu","version":"22.04"}`, "multiple OS families or releases"},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", tc.name, reverse), func(t *testing.T) {
				oses := sid + "," + tc.other
				if reverse {
					oses = tc.other + "," + sid
				}
				rep, rc := scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+oses+","+qualified+`]}`)
				if rc != 2 || len(rep.Skipped) != 1 || rep.Summary.TargetIncomplete != 0 || rep.Skipped[0].Cause != "coverage" {
					t.Errorf("qualified: exit %d, summary %+v, skipped %+v; want the sid install reported uncovered", rc, rep.Summary, rep.Skipped)
				}
				rep, rc = scanOSRegression(t, db, `{"bomFormat":"CycloneDX","components":[`+oses+","+bare+`]}`)
				if rc != 2 || len(rep.Skipped) != 1 || rep.Summary.TargetIncomplete != 1 || !strings.Contains(rep.Skipped[0].Reason, tc.reason) {
					t.Errorf("bare: exit %d, summary %+v, skipped %+v; want a target skip naming %q", rc, rep.Summary, rep.Skipped, tc.reason)
				}
			})
		}
	}
}
