package spdx

import (
	"strings"
	"testing"
)

// QA 2026-11-20. A package naming two purls counted once as a component and
// twice as cataloged, so it cancelled one component that was not evaluated.
func TestParse_SeveralPurlsOnOnePackageDoNotCancelAnUnreadOne(t *testing.T) {
	ref := func(p string) string {
		return `{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + p + `"}`
	}
	doc := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	 {"SPDXID":"SPDXRef-a","name":"a","externalRefs":[` + ref("pkg:npm/a@1.0.0") + `,` + ref("pkg:npm/b@2.0.0") + `,` + ref("pkg:npm/a@1.0.0") + `]},
	 {"SPDXID":"SPDXRef-c","name":"c"}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 2 || stats.Components != 3 || stats.Cataloged != 2 || stats.SkippedNoPURL != 1 {
		t.Errorf("%d packages, stats %+v; want 2 packages, 3 components, 2 cataloged, 1 without a purl", len(target.Packages), stats)
	}
}
