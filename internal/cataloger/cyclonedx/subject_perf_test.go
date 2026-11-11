package cyclonedx

import (
	"fmt"
	"strings"
	"testing"
)

// subjectTreeDoc is a document whose inventory sits under
// metadata.component: n distinct npm packages, the shape a generator writes
// an application's SBOM in.
func subjectTreeDoc(n int) string {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[],"metadata":{"component":{"type":"application","name":"app","components":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"library","name":"qa-app-%d","version":"1.0.0","purl":"pkg:npm/qa-app-%d@1.0.0"}`, i, i)
	}
	b.WriteString(`]}}}`)
	return b.String()
}

// The subject walk is linear in the inventory. Counting the subject tree's
// keyed releases once per identity made it quadratic: a 1,000-package
// subject allocated 3.0 million times (490 MB) and took 540 ms where it
// takes 15 thousand (3.4 MB) and 4 ms (release check 2026-11-11). The bound
// is a third of the way between: a quadratic walk is two orders of
// magnitude over it, a linear one two orders under.
func TestParse_SubjectTreeIsLinear(t *testing.T) {
	doc := subjectTreeDoc(1000)
	allocs := testing.AllocsPerRun(2, func() {
		target, stats, err := Parse(strings.NewReader(doc))
		if err != nil || stats.Cataloged != 1000 || len(target.Packages) != 1000 {
			t.Fatalf("Parse: %v, cataloged %d, packages %d", err, stats.Cataloged, len(target.Packages))
		}
	})
	if allocs > 200_000 {
		t.Errorf("Parse of a 1,000-package subject tree allocated %.0f times; a linear walk allocates about 15,000", allocs)
	}
}

func BenchmarkParse_SubjectTree(b *testing.B) {
	for _, n := range []int{125, 250, 500, 1000} {
		doc := subjectTreeDoc(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, stats, err := Parse(strings.NewReader(doc)); err != nil || stats.Cataloged != n {
					b.Fatalf("%v, %d", err, stats.Cataloged)
				}
			}
		})
	}
}
