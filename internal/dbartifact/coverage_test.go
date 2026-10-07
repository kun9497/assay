package dbartifact

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// D115: the rename declaration rides in the advisory-coverage annotation,
// because the publish guard reads the candidate's annotation, never the
// provider's code. An artifact published before the field reads as nil --
// nothing declared -- which is the guard's existing missing-key refusal.
func TestCoverageAnnotations_RenamedRoundTripsAndIsNilOnOlderArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	renamed := map[string]string{"Echo:PyPi": "Echo:PyPI", "Old:Spelling": "New:Spelling"}
	img, err := Pack(path, Meta{SchemaVersion: 9, Advisories: &AdvisoryCoverage{Total: 3, Counts: map[string]int{"Echo:PyPI": 3}, Ecosystems: []string{"Echo:PyPI"}, Providers: []string{"osv"}, Renamed: renamed}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := MetaOf(img)
	if err != nil {
		t.Fatal(err)
	}
	if got.Advisories == nil || !reflect.DeepEqual(got.Advisories.Renamed, renamed) {
		t.Fatalf("Renamed lost in the round trip: %+v", got.Advisories)
	}

	older := mutate.Annotations(img, map[string]string{AnnotationAdvisories: `{"total":3,"counts":{"Echo:PyPI":3},"ecosystems":["Echo:PyPI"],"providers":["osv"]}`}).(v1.Image)
	got, err = MetaOf(older)
	if err != nil {
		t.Fatal(err)
	}
	if got.Advisories == nil || got.Advisories.Renamed != nil {
		t.Fatalf("an annotation without renamed decoded as %+v, want Renamed nil", got.Advisories)
	}

	// And an artifact with nothing declared writes no renamed key at all, so
	// its annotation is byte-identical to one from before the field.
	plain, err := Pack(path, Meta{SchemaVersion: 9, Advisories: &AdvisoryCoverage{Total: 1, Counts: map[string]int{"Go": 1}, Ecosystems: []string{"Go"}, Providers: []string{"osv"}}})
	if err != nil {
		t.Fatal(err)
	}
	mf, err := plain.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mf.Annotations[AnnotationAdvisories], `"renamed"`) {
		t.Errorf("an empty declaration was annotated: %s", mf.Annotations[AnnotationAdvisories])
	}
}
