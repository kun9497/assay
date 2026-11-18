package cyclonedx

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// The rendered PURL is also consumed outside Assay. A source supplied only
// by a vendorless listing must not be rewritten as that vendor's claim,
// even though advisory matching can retain the source as ordinary evidence.
func TestParse_MergedPURLDoesNotAttributeAnotherVendorsSource(t *testing.T) {
	for _, namespace := range []string{"", "ubuntu/", "debian/"} {
		a := "pkg:deb/ubuntu/libapt@2.4.14?distro=ubuntu-22.04"
		b := "pkg:deb/" + namespace + "libapt@2.4.14?distro=ubuntu-22.04&upstream=apt"
		for _, pair := range [][2]string{{a, b}, {b, a}} {
			doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","components":[{"type":"library","purl":%q}],"metadata":{"component":{"type":"library","purl":%q}}}`, pair[0], pair[1])
			target, _, err := Parse(strings.NewReader(doc))
			if err != nil {
				t.Fatal(err)
			}
			if len(target.Packages) != 1 {
				t.Fatalf("packages %+v", target.Packages)
			}
			p, err := pkgmeta.ParsePURL(target.Packages[0].PURL)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			// The first explicit vendor is retained; a vendorless PURL
			// never outranks an explicit one.
			if namespace == "ubuntu/" || (namespace == "debian/" && pair[0] == b) {
				want = "apt"
			}
			if p.Qualifiers["upstream"] != want {
				t.Fatalf("pair %v: purl %s, want upstream %q", pair, p.String(), want)
			}
		}
	}
}
