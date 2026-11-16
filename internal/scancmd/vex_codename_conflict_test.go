package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// 2026-11-16 QA, through Run, in the shapes the QA built from syft's Ubuntu
// 22.04 SBOM: an operating-system declaration that contradicts itself (two
// versions, two ids, a standard version against syft's), or states a version
// that names no release, gives no codename evidence, in either property
// order; a version-less declaration is held to the release of its nearest
// context, so one under a 24.04 parent neither cancels the top-level 22.04's
// jammy nor lends a numeric-only 22.04 one. The same value repeated and an
// ordinary 22.04 jammy still apply.
func TestRun_VEXUbuntuCodenameFromConflictingDeclarations(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0110", "CVE-2031-9110", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9110"}
	type prop struct{ name, value string }
	osc := func(version string, props []prop, children ...string) string {
		var ps []string
		for _, p := range props {
			ps = append(ps, `{"name":"`+p.name+`","value":"`+p.value+`"}`)
		}
		out := `{"type":"operating-system","name":"ubuntu","version":"` + version + `","properties":[` + strings.Join(ps, ",") + `]`
		if len(children) > 0 {
			out += `,"components":[` + strings.Join(children, ",") + `]`
		}
		return out + `}`
	}
	id := prop{"syft:distro:id", "ubuntu"}
	v := func(s string) prop { return prop{"syft:distro:versionID", s} }
	cn := func(s string) prop { return prop{"syft:distro:versionCodename", s} }
	const apt = `{"type":"library","name":"apt","version":"2.4.14","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"}`
	branch := func(children ...string) string {
		return `{"type":"library","name":"is-number","version":"7.0.0","purl":"pkg:npm/is-number@7.0.0","components":[` + strings.Join(children, ",") + `]}`
	}
	debian12 := func(children ...string) string {
		return `{"type":"operating-system","name":"debian","version":"12","properties":[{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"12"}],"components":[` + strings.Join(children, ",") + `]}`
	}
	debianAny := func(children ...string) string {
		out := `{"type":"operating-system","name":"debian","properties":[{"name":"syft:distro:id","value":"debian"}]`
		if len(children) > 0 {
			out += `,"components":[` + strings.Join(children, ",") + `]`
		}
		return out + `}`
	}
	top22 := osc("22.04", []prop{id, v("22.04")})
	top22j := osc("22.04", []prop{id, v("22.04"), cn("jammy")})
	for _, tc := range []struct {
		name, components string
		suppressed       bool
	}{
		{"two versionIDs 24.04 then 22.04", top22 + "," + apt + "," + branch(osc("", []prop{id, v("24.04"), v("22.04"), cn("jammy")})), false},
		{"two versionIDs 22.04 then 24.04", top22 + "," + apt + "," + branch(osc("", []prop{id, v("22.04"), v("24.04"), cn("jammy")})), false},
		{"standard version 24.04, syft 22.04", top22 + "," + apt + "," + branch(osc("24.04", []prop{id, v("22.04"), cn("jammy")})), false},
		{"ids debian then ubuntu", top22 + "," + apt + "," + branch(osc("", []prop{{"syft:distro:id", "debian"}, id, v("22.04"), cn("jammy")})), false},
		{"ids ubuntu then debian", top22 + "," + apt + "," + branch(osc("", []prop{id, {"syft:distro:id", "debian"}, v("22.04"), cn("jammy")})), false},
		{"unreadable version 24", top22 + "," + apt + "," + branch(osc("", []prop{id, v("24"), cn("jammy")})), false},
		// Beside a 22.04 sibling the level is two releases, so only the
		// unreadable parent's own sentinel keeps its child from the
		// inherited 22.04.
		{"unreadable version, version-less child", top22 + "," + apt + "," + branch(osc("22.04", []prop{id, v("22.04")}), osc("", []prop{id, v("24"), cn("noble")}, osc("", []prop{id, cn("jammy")}))), false},
		// A versioned parent binds its child even where its own level is
		// two releases; a version-less declaration beside two releases
		// belongs to neither.
		{"version-less jammy under 24.04 beside a 22.04 sibling", top22 + "," + apt + "," + branch(osc("22.04", []prop{id, v("22.04")}), osc("24.04", []prop{id, v("24.04"), cn("noble")}, osc("", []prop{id, cn("jammy")}))), false},
		// Review of the branch: a codename-less version-less parent beside
		// two releases, a self-contradicting parent, and another vendor's
		// versioned OS each leave what they hold out of the outer 22.04.
		{"jammy under a version-less parent beside two releases", top22 + "," + apt + "," + branch(osc("22.04", []prop{id, v("22.04")}), osc("24.04", []prop{id, v("24.04"), cn("noble")}), osc("", []prop{id}, osc("", []prop{id, cn("jammy")}))), false},
		{"jammy under a self-contradicting parent", top22 + "," + apt + "," + branch(osc("", []prop{id, v("24.04"), v("22.04")}, osc("", []prop{id, cn("jammy")}))), false},
		{"numeric top, version-less jammy under Debian 12", top22 + "," + apt + "," + branch(debian12(osc("", []prop{id, cn("jammy")}))), false},
		// Second review: another vendor's OS as a sibling, and one with no
		// version, are contexts too.
		{"numeric top, version-less jammy beside Debian 12", top22 + "," + apt + "," + branch(debian12(), osc("", []prop{id, cn("jammy")})), false},
		{"numeric top, version-less jammy beside 22.04 and Debian 12", top22 + "," + apt + "," + branch(osc("22.04", []prop{id, v("22.04")}), debian12(), osc("", []prop{id, cn("jammy")})), false},
		{"numeric top, version-less jammy under a version-less Debian", top22 + "," + apt + "," + branch(debianAny(osc("", []prop{id, cn("jammy")}))), false},
		{"numeric top, version-less jammy beside a version-less Debian", top22 + "," + apt + "," + branch(debianAny(), osc("", []prop{id, cn("jammy")})), false},
		{"top jammy, version-less noble under Debian 12", top22j + "," + apt + "," + branch(debian12(osc("", []prop{id, cn("noble")}))), true},
		{"version-less jammy beside 22.04 and 24.04 siblings", top22 + "," + apt + "," + branch(osc("22.04", []prop{id, v("22.04")}), osc("24.04", []prop{id, v("24.04"), cn("noble")}), osc("", []prop{id, cn("jammy")})), false},
		// Controls: the same value twice, an ordinary declaration, a
		// standard version its VERSION_ID refines.
		{"versionID 22.04 twice", top22 + "," + apt + "," + branch(osc("", []prop{id, v("22.04"), v("22.04"), cn("jammy")})), true},
		{"ordinary top-level 22.04 jammy", top22j + "," + apt, true},
		{"standard version 22.04.5, syft 22.04", osc("22.04.5", []prop{id, v("22.04"), cn("jammy")}) + "," + apt, true},
		// Issue 2: a version-less declaration under a 24.04 parent, the parent
		// in a branch as the QA built it (beside the top OS it would make the
		// top context two releases, D166).
		{"top jammy, version-less noble under 24.04 noble", top22j + "," + apt + "," + branch(osc("24.04", []prop{id, v("24.04"), cn("noble")}, osc("", []prop{id, cn("noble")}))), true},
		{"top jammy, explicit 24.04 noble under 24.04 noble", top22j + "," + apt + "," + branch(osc("24.04", []prop{id, v("24.04"), cn("noble")}, osc("24.04", []prop{id, v("24.04"), cn("noble")}))), true},
		{"top numeric, version-less jammy under 24.04 noble", top22 + "," + apt + "," + branch(osc("24.04", []prop{id, v("24.04"), cn("noble")}, osc("", []prop{id, cn("jammy")}))), false},
		{"top numeric, explicit 24.04 jammy under 24.04 noble", top22 + "," + apt + "," + branch(osc("24.04", []prop{id, v("24.04"), cn("noble")}, osc("24.04", []prop{id, v("24.04"), cn("jammy")}))), false},
		{"top jammy, version-less noble beside a 24.04 sibling in a branch", top22j + "," + apt + "," + branch(osc("24.04", []prop{id, v("24.04"), cn("noble")}), osc("", []prop{id, cn("noble")})), true},
		{"top jammy, version-less noble under a 22.04 parent", top22j + "," + apt + "," + osc("22.04", []prop{id, v("22.04")}, osc("", []prop{id, cn("noble")})), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + tc.components + `]}`
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9110", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY")))}}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(rep), pairsOf(rep.Findings)
			wantCode := 1
			if tc.suppressed {
				wantCode = 0
			}
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed || code != wantCode {
				t.Fatalf("suppressed = %v, kept = %v, exit %d; want suppressed %v, exit %d\nstderr: %s",
					sup[want], kept[want], code, tc.suppressed, wantCode, errOut.String())
			}
		})
	}
}
