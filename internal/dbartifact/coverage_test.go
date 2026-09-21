package dbartifact

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func TestCoverageAnnotations_RoundTripAndRejectInvalidValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	want := Meta{SchemaVersion: 9, RatingCount: 3, RatingCounts: map[string]int{"NVD": 2, "KEV": 1}, Advisories: &AdvisoryCoverage{Total: 10, Counts: map[string]int{"Go": 9, "npm": 2}, Ecosystems: []string{"Go", "npm"}, Providers: []string{"osv"}}}
	img, err := Pack(path, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Advisories, want.Advisories) || !reflect.DeepEqual(got.RatingCounts, want.RatingCounts) {
		t.Fatalf("metadata lost: %+v", got)
	}
	for _, tc := range []struct{ annotation, value string }{
		{AnnotationAdvisories, `null`}, {AnnotationAdvisories, `{broken`}, {AnnotationAdvisories, `{"total":-1,"counts":{}}`}, {AnnotationAdvisories, `{"total":1,"counts":{"Go":2}}`},
		{AnnotationRatingCounts, `null`}, {AnnotationRatingCounts, `{"NVD":-1}`},
	} {
		t.Run(tc.annotation+tc.value, func(t *testing.T) {
			bad := mutate.Annotations(img, map[string]string{tc.annotation: tc.value}).(v1.Image)
			if _, err := MetaOf(bad); err == nil {
				t.Fatal("malformed guard metadata accepted")
			}
		})
	}
}
