package scancmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// Release check 2026-11-11 (main 42b0c09), the CycloneDX items, end to end.
// qa1111DB plus one Wolfi openssl record: Wolfi keys from its ID alone.
func rc1111DB(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range append(qa1111Advisories(), advisory.Advisory{ID: "WOLFI-CVE-2026-9000", Kind: advisory.KindVulnerability, Database: "WOLFI", Upstream: []string{"CVE-2026-9000"},
		Affected: []advisory.Affected{{Ecosystem: "Wolfi", Name: "openssl",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.5.2-r0"}}}}}}}) {
		if err := w.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "Alpine:v3.20", "Debian:11", "Wolfi", "npm"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return db
}

// Blocker 1: an OS whose ecosystem keys from the ID alone (Wolfi) declared
// with no version beside its packages keys them, as it does as their parent
// or with a version: openssl read 0 of its 84 findings as a sibling, exit 0.
func TestRun_RC1111_ReleaselessEcosystemSiblingKeys(t *testing.T) {
	db := rc1111DB(t)
	const (
		openssl = `{"type":"library","name":"openssl","version":"3.5.1-r0","purl":"pkg:apk/wolfi/openssl@3.5.1-r0?arch=x86_64"}`
		ctrl    = `{"type":"library","name":"assay-qa-inventory-control","version":"1.0.0","purl":"pkg:npm/assay-qa-inventory-control@1.0.0"}`
	)
	for _, tc := range []struct{ name, components string }{
		{"sibling with no version", `{"type":"operating-system","name":"wolfi"},` + openssl + `,` + ctrl},
		{"parent with no version", `{"type":"operating-system","name":"wolfi","components":[` + openssl + `]},` + ctrl},
		{"sibling with a version", `{"type":"operating-system","name":"wolfi","version":"20230201"},` + openssl + `,` + ctrl},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qa1111Run(t, db, qa1111Start+`"components":[`+tc.components+`]}`, Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true})
			if r.code != 1 || r.findings["WOLFI-CVE-2026-9000"] != "Wolfi sbom" || r.doc.Summary.NotEvaluated != 0 || r.doc.Distro == nil || r.doc.Distro.ID != "wolfi" {
				t.Errorf("exit=%d findings=%v notEvaluated=%d distro=%+v; want 1, the Wolfi finding, 0, wolfi", r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Distro)
			}
		})
	}
}

// Blocker 2: two known families declared with no release beside a keyed OS
// refuse the context whichever was declared last. `debian 11`, `alpine`,
// `debian` keyed busybox to Debian (51 findings) while `debian 11`, `debian`,
// `alpine` left it to its `distro=alpine-3.19` qualifier (2): now both orders
// read the qualifier, and both orders leave a busybox with no qualifier not
// evaluated.
func TestRun_RC1111_TwoFamiliesRefuseTheContextInEitherOrder(t *testing.T) {
	db := rc1111DB(t)
	const (
		debian11  = `{"type":"operating-system","name":"debian","version":"11"}`
		debian    = `{"type":"operating-system","name":"debian"}`
		alpine    = `{"type":"operating-system","name":"alpine"}`
		qualified = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19"}`
		bare      = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}`
	)
	strict := Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true}
	for _, order := range [][]string{{debian11, debian, alpine}, {debian11, alpine, debian}} {
		doc := func(busybox string) string {
			return qa1111Start + `"components":[` + strings.Join(order, ",") + `,` + busybox + `],"metadata":{"component":{"type":"container","name":"image"}}}`
		}
		r := qa1111Run(t, db, doc(qualified), strict)
		if _, debianHit := r.findings["DEBIAN-CVE-2099-0001"]; r.code != 1 || debianHit || r.findings["ALPINE319-CVE-2024-58251"] != "Alpine:v3.19 sbom" || r.doc.Summary.NotEvaluated != 0 || r.doc.Distro != nil {
			t.Errorf("qualified, order %v: exit=%d findings=%v notEvaluated=%d distro=%+v; want 1, the Alpine finding alone, 0, no distro", order, r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Distro)
		}
		r = qa1111Run(t, db, doc(bare), strict)
		if r.code != 2 || len(r.findings) != 0 || r.doc.Summary.NotEvaluated != 1 {
			t.Errorf("bare, order %v: exit=%d findings=%v notEvaluated=%d; want 2, none, 1", order, r.code, r.findings, r.doc.Summary.NotEvaluated)
		}
	}
}

// Residual: the QA 2026-11-11 item 1 shape with the architecture left off the
// keyed record. The two amd64 listings have no keyed amd64 twin, so their
// key is what the document says of the name and version without one: 25
// findings in either order (the keyed record last had read 0, incomplete 1).
func TestRun_RC1111_ArchlessKeyedRecordKeysItsArchTwins(t *testing.T) {
	db := rc1111DB(t)
	const (
		top    = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&upstream=glibc%402.31-13%2Bdeb11u13"}`
		keyed  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
		epoch0 = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&upstream=glibc%400%3A2.31-13%2Bdeb11u13"}`
		ctrl   = `{"type":"library","name":"assay-qa-inventory-control","version":"1.0.0","purl":"pkg:npm/assay-qa-inventory-control@1.0.0"}`
	)
	for _, order := range [][]string{{keyed, epoch0}, {epoch0, keyed}} {
		doc := qa1111Start + `"components":[` + top + `,` + ctrl + `],"metadata":{"component":{"type":"container","name":"image","components":[` + strings.Join(order, ",") + `]}}}`
		r := qa1111Run(t, db, doc, Options{FailOn: &bandLow, FailOnUnknown: true})
		if r.code != 1 || r.findings["DEBIAN-CVE-2026-4046"] != "Debian:11 sbom" || r.doc.Summary.NotEvaluated != 0 || r.doc.Summary.TargetIncomplete != 0 || r.doc.Summary.Components != 2 {
			t.Errorf("order %v: exit=%d findings=%v notEvaluated=%d incomplete=%d components=%d, want 1, the Debian finding, 0, 0, 2",
				order, r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components)
		}
	}
}

// Residual: a bare top-level listing beside an x86_64 and an aarch64 install
// of ONE release is one of them, not both: it takes the architecture of the
// first it joins, and the other stays its own install -- 2 components and
// both findings, as without the bare listing (were 1 and one finding).
func TestRun_RC1111_BareListingJoinsOneSameReleaseInstallNotBoth(t *testing.T) {
	db := rc1111DB(t)
	const (
		bare = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20","properties":[{"name":"syft:location:0:path","value":"/top-unknown"}]}`
		x86  = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
		arm  = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/child/aarch64/lib/apk/db/installed"}]}`
	)
	r := qa1111Run(t, db, qa1111Start+`"components":[`+bare+`],"metadata":{"component":{"type":"container","name":"demo","components":[`+x86+`,`+arm+`]}}}`, Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true})
	var paths []string
	for _, f := range r.doc.Findings {
		for _, l := range f.Package.Locations {
			paths = append(paths, l.Path)
		}
	}
	if r.code != 1 || r.doc.Summary.Components != 2 || r.doc.Summary.NotEvaluated != 0 || len(r.doc.Findings) != 2 || strings.Count(strings.Join(paths, ","), "/top-unknown") != 1 ||
		!strings.Contains(strings.Join(paths, ","), "/image/x86/") || !strings.Contains(strings.Join(paths, ","), "/child/aarch64/") {
		t.Errorf("exit=%d components=%d notEvaluated=%d findings=%d paths=%v; want 1, 2, 0, 2 findings, /top-unknown on exactly one", r.code, r.doc.Summary.Components, r.doc.Summary.NotEvaluated, len(r.doc.Findings), paths)
	}
}
