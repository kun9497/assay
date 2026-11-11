package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-11, end to end, the CycloneDX items. One database: a Debian 11
// glibc record, an Alpine 3.19 busybox record and an Alpine 3.20 one.
func qa1111DB(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []advisory.Advisory{
		{ID: "DEBIAN-CVE-2026-4046", Kind: advisory.KindVulnerability, Database: "DEBIAN", Upstream: []string{"CVE-2026-4046"},
			Affected: []advisory.Affected{{Ecosystem: "Debian:11", Name: "glibc",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.31-13+deb11u14"}}}}}}},
		{ID: "ALPINE319-CVE-2024-58251", Kind: advisory.KindVulnerability, Database: "ALPINE", Upstream: []string{"CVE-2024-58251"},
			Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r21"}}}}}}},
		{ID: "ALPINE320-CVE-2025-46394", Kind: advisory.KindVulnerability, Database: "ALPINE", Upstream: []string{"CVE-2025-46394"},
			Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.20", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r30"}}}}}}},
		{ID: "DEBIAN-CVE-2099-0001", Kind: advisory.KindVulnerability, Database: "DEBIAN", Upstream: []string{"CVE-2099-0001"},
			Affected: []advisory.Affected{{Ecosystem: "Debian:11", Name: "busybox",
				Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1:9.9"}}}}}}},
	} {
		if err := w.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "Alpine:v3.20", "Debian:11", "npm"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return db
}

type qa1111Scan struct {
	code     int
	findings map[string]string // advisory id -> "ecosystem path,path"
	doc      report.Document
}

func qa1111Run(t *testing.T, db, body string, opts Options) qa1111Scan {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.Output = "json"
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, p, opts, &out, &errOut)
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, errOut.String())
	}
	m := map[string]string{}
	for _, f := range doc.Findings {
		var paths []string
		for _, l := range f.Package.Locations {
			paths = append(paths, l.Path)
		}
		sort.Strings(paths)
		m[f.Advisory.ID] = f.Package.Ecosystem + " " + strings.Join(paths, ",")
	}
	return qa1111Scan{code, m, doc}
}

const qa1111Start = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,`

// Item 1: three listings of one libc6, one keyed to Debian 11 and two
// stating the equivalent glibc source version as `0:2.31-13+deb11u13` and
// `2.31-13+deb11u13`. The key is adopted before the versions are compared,
// so both orders judge the package: 25 findings became 0, exit 0 under
// --fail-on low, when the keyed listing came last. A real epoch difference
// still contradicts.
func TestRun_QA1111_SourceVersionsAreComparedUnderTheKeyWhicheverOrder(t *testing.T) {
	db := qa1111DB(t)
	const (
		top    = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&upstream=glibc%402.31-13%2Bdeb11u13"}`
		keyed  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
		epoch0 = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&upstream=glibc%400%3A2.31-13%2Bdeb11u13"}`
		// The same listing stating no architecture: it meets the keyed
		// listing's release through the arch-less identity.
		epoch0NoArch = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?upstream=glibc%400%3A2.31-13%2Bdeb11u13"}`
		epoch1       = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&upstream=glibc%401%3A2.31-13%2Bdeb11u13"}`
		ctrl         = `{"type":"library","name":"assay-qa-inventory-control","version":"1.0.0","purl":"pkg:npm/assay-qa-inventory-control@1.0.0"}`
	)
	doc := func(subject ...string) string {
		return qa1111Start + `"components":[` + top + `,` + ctrl + `],"metadata":{"component":{"type":"container","name":"image","components":[` + strings.Join(subject, ",") + `]}}}`
	}
	for _, order := range [][]string{{keyed, epoch0}, {epoch0, keyed}, {keyed, epoch0NoArch}, {epoch0NoArch, keyed}} {
		r := qa1111Run(t, db, doc(order...), Options{FailOn: &bandLow, FailOnUnknown: true})
		if r.code != 1 || r.findings["DEBIAN-CVE-2026-4046"] != "Debian:11 sbom" || r.doc.Summary.NotEvaluated != 0 || r.doc.Summary.TargetIncomplete != 0 || r.doc.Summary.Components != 2 {
			t.Errorf("order %v: exit=%d findings=%v notEvaluated=%d incomplete=%d components=%d, want 1, the Debian finding, 0, 0, 2",
				order, r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components)
		}
	}
	for _, order := range [][]string{{keyed, epoch1}, {epoch1, keyed}} {
		r := qa1111Run(t, db, doc(order...), Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true})
		if r.code != 2 || len(r.findings) != 0 || r.doc.Summary.TargetIncomplete != 1 {
			t.Errorf("real epoch, order %v: exit=%d findings=%v incomplete=%d, want 2, none, 1", order, r.code, r.findings, r.doc.Summary.TargetIncomplete)
		}
	}
}

// PR #277 review: the key a merge adopts comes from the subject tree, never
// from a second top-level listing. Two top-level busybox listings, one
// unkeyed (A) and one keyed to Alpine 3.19 (B), are two packages; an
// unkeyed third under the subject (C) merges into A and must not bring B's
// key with it: A stays not evaluated, B is the one finding.
func TestRun_QA1111_ASiblingsKeyIsNotAdopted(t *testing.T) {
	db := qa1111DB(t)
	const (
		a = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20","properties":[{"name":"syft:location:0:path","value":"/top/a"}]}`
		b = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/top/b"}]}`
		c = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20","properties":[{"name":"syft:location:0:path","value":"/subject/c"}]}`
	)
	for _, subject := range []string{"", c} {
		r := qa1111Run(t, db, qa1111Start+`"components":[`+a+`,`+b+`],"metadata":{"component":{"type":"container","name":"demo","components":[`+subject+`]}}}`, Options{FailOnIncomplete: true})
		if r.code != 2 || r.doc.Summary.NotEvaluated != 1 || len(r.findings) != 1 || r.findings["ALPINE319-CVE-2024-58251"] != "Alpine:v3.19 /top/b" {
			t.Errorf("subject=%q: exit=%d notEvaluated=%d findings=%v; want 2, 1 and the one finding on /top/b", subject, r.code, r.doc.Summary.NotEvaluated, r.findings)
		}
	}
}

// Item 3: two listings of one busybox version stating different
// architectures are two installs. The aarch64 one, unkeyed under a subject
// declaring two Alpine releases, stays its own package (not evaluated, exit
// 2 under --fail-on-incomplete) and its path lands on no x86_64 finding; the
// same listing stating x86_64 is the one package.
func TestRun_QA1111_DifferentArchitecturesAreNotOneInstall(t *testing.T) {
	db := qa1111DB(t)
	const (
		x86   = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
		os319 = `{"type":"operating-system","name":"alpine","version":"3.19"}`
		os320 = `{"type":"operating-system","name":"alpine","version":"3.20"}`
	)
	child := func(arch string) string {
		return `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=` + arch + `","properties":[{"name":"syft:location:0:path","value":"/child/` + arch + `/lib/apk/db/installed"}]}`
	}
	doc := func(arch string) string {
		return qa1111Start + `"components":[` + x86 + `],"metadata":{"component":{"type":"container","name":"demo","components":[` + os319 + `,` + os320 + `,` + child(arch) + `]}}}`
	}
	strict := Options{FailOnIncomplete: true}
	r := qa1111Run(t, db, doc("aarch64"), strict)
	if r.code != 2 || r.doc.Summary.Components != 2 || r.doc.Summary.NotEvaluated != 1 || r.findings["ALPINE319-CVE-2024-58251"] != "Alpine:v3.19 /image/x86/lib/apk/db/installed" {
		t.Errorf("different arch: exit=%d components=%d notEvaluated=%d findings=%v; want 2, 2, 1 and the x86_64 path alone", r.code, r.doc.Summary.Components, r.doc.Summary.NotEvaluated, r.findings)
	}
	// Two keyed twins of different architectures, each its own release: the
	// unkeyed aarch64 child is the aarch64 twin's second listing, keyed by
	// it, not refused as ambiguous.
	arm := `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.20","properties":[{"name":"syft:location:0:path","value":"/image/arm/lib/apk/db/installed"}]}`
	r = qa1111Run(t, db, qa1111Start+`"components":[`+x86+`,`+arm+`],"metadata":{"component":{"type":"container","name":"demo","components":[`+os319+`,`+os320+`,`+child("aarch64")+`]}}}`, strict)
	if r.code != 0 || r.doc.Summary.Components != 2 || r.doc.Summary.NotEvaluated != 0 || r.findings["ALPINE320-CVE-2025-46394"] != "Alpine:v3.20 /child/aarch64/lib/apk/db/installed,/image/arm/lib/apk/db/installed" || r.findings["ALPINE319-CVE-2024-58251"] != "Alpine:v3.19 /image/x86/lib/apk/db/installed" {
		t.Errorf("two arches, two releases: exit=%d components=%d notEvaluated=%d findings=%v; want the aarch64 child on the aarch64 twin alone", r.code, r.doc.Summary.Components, r.doc.Summary.NotEvaluated, r.findings)
	}
	// The mirror of that (PR #277 review): a bare listing at the top meeting
	// keyed twins of two architectures AND two releases under the subject
	// belongs to neither, in either order.
	bare := `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20","properties":[{"name":"syft:location:0:path","value":"/top/bare/lib/apk/db/installed"}]}`
	for _, order := range [][2]string{{x86, arm}, {arm, x86}} {
		r = qa1111Run(t, db, qa1111Start+`"components":[`+bare+`],"metadata":{"component":{"type":"container","name":"demo","components":[`+order[0]+`,`+order[1]+`]}}}`, strict)
		onFinding := strings.Contains(r.findings["ALPINE319-CVE-2024-58251"], "/top/bare") || strings.Contains(r.findings["ALPINE320-CVE-2025-46394"], "/top/bare")
		if r.code != 2 || r.doc.Summary.Components != 3 || r.doc.Summary.NotEvaluated != 1 || onFinding {
			t.Errorf("bare top, two arches at two releases, order %v: exit=%d components=%d notEvaluated=%d findings=%v; want 2, 3, 1 and /top/bare on no finding", order, r.code, r.doc.Summary.Components, r.doc.Summary.NotEvaluated, r.findings)
		}
	}
	r = qa1111Run(t, db, doc("x86_64"), strict)
	if r.code != 0 || r.doc.Summary.Components != 1 || r.doc.Summary.NotEvaluated != 0 || r.findings["ALPINE319-CVE-2024-58251"] != "Alpine:v3.19 /child/x86_64/lib/apk/db/installed,/image/x86/lib/apk/db/installed" {
		t.Errorf("same arch: exit=%d components=%d notEvaluated=%d findings=%v; want 0, 1, 0 and both paths", r.code, r.doc.Summary.Components, r.doc.Summary.NotEvaluated, r.findings)
	}
}

// Items 5 and 7.2: an OS declared with no release at all. A known family
// (alpine) keys nothing itself but refuses an inherited context of another
// family, so the purl's own distro qualifier identifies the package: Alpine
// with no version as the subject, Debian 11 at the top and busybox with
// `distro=alpine-3.19` read 51 Debian findings; a version-less Alpine or a
// generic `linux` beside the qualified busybox read it not evaluated. A
// release no key is built from ("edge") is still the document's identity
// and wins over the qualifier, as before.
func TestRun_QA1111_AFamilyWithNoReleaseLeavesTheQualifier(t *testing.T) {
	db := qa1111DB(t)
	const (
		debian = `{"type":"operating-system","name":"debian","version":"11"}`
		os319  = `{"type":"operating-system","name":"alpine","version":"3.19"}`
		q      = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19"}`
		bare   = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}`
	)
	osParent := func(name, version, children string) string {
		v := ""
		if version != "" {
			v = `,"version":"` + version + `"`
		}
		return `{"type":"operating-system","name":"` + name + `"` + v + `,"components":[` + children + `]}`
	}
	container := func(children string) string {
		return `{"type":"container","name":"image","components":[` + children + `]}`
	}
	alpine := "Alpine:v3.19 sbom"
	for _, tc := range []struct {
		name, top, subject string
		want               string // the ALPINE319 finding's "ecosystem path", "" for not evaluated
		debianFindings     bool
	}{
		{"alpine parent with no version, Debian at the top", debian, osParent("alpine", "", q), alpine, false},
		{"alpine parent with no version, nothing at the top", "", osParent("alpine", "", q), alpine, false},
		{"alpine parent with a version, Debian at the top", debian, osParent("alpine", "3.19.9", q), alpine, false},
		{"linux parent, qualified child", "", osParent("linux", "", q), alpine, false},
		{"linux parent under Alpine 3.19 at the top, bare child", os319, osParent("linux", "", bare), alpine, false},
		{"alpine sibling with no version, qualified", "", container(`{"type":"operating-system","name":"alpine"},` + q), alpine, false},
		{"linux sibling with no version, qualified", "", container(`{"type":"operating-system","name":"linux"},` + q), alpine, false},
		{"alpine sibling with no version under Debian at the top, bare child", debian, container(`{"type":"operating-system","name":"alpine"},` + bare), "", false},
		{"alpine edge sibling wins over the qualifier (as before)", "", container(`{"type":"operating-system","name":"alpine","version":"edge"},` + q), "", false},
		{"alpine edge parent wins over the qualifier too", "", osParent("alpine", "edge", q), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qa1111Run(t, db, qa1111Start+`"components":[`+tc.top+`],"metadata":{"component":`+tc.subject+`}}`, Options{FailOnIncomplete: true})
			got := r.findings["ALPINE319-CVE-2024-58251"]
			_, debianHit := r.findings["DEBIAN-CVE-2099-0001"]
			if got != tc.want || debianHit != tc.debianFindings || (tc.want == "" && (r.doc.Summary.NotEvaluated != 1 || r.code != 2)) || (tc.want != "" && r.doc.Summary.NotEvaluated != 0) {
				t.Errorf("findings=%v notEvaluated=%d exit=%d, want ALPINE319=%q debian=%v", r.findings, r.doc.Summary.NotEvaluated, r.code, tc.want, tc.debianFindings)
			}
		})
	}
}
