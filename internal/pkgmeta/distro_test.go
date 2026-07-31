package pkgmeta

import (
	"errors"
	"strings"
	"testing"
)

func TestDistroEcosystem(t *testing.T) {
	tests := []struct {
		name   string
		distro Distro
		want   string
	}{
		{"syft reports a patch release", Distro{ID: "alpine", VersionID: "3.19.9"}, "Alpine:v3.19"},
		{"already major.minor", Distro{ID: "alpine", VersionID: "3.19"}, "Alpine:v3.19"},
		{"two-digit minor", Distro{ID: "alpine", VersionID: "3.20.1"}, "Alpine:v3.20"},
		{"oldest release in the bucket", Distro{ID: "alpine", VersionID: "3.2.0"}, "Alpine:v3.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.distro.Ecosystem()
			if err != nil {
				t.Fatalf("Ecosystem() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Ecosystem() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Each of these would otherwise produce a key that looks valid and matches
// nothing — every package silently clean. The error is the feature.
func TestDistroEcosystem_Unsupported(t *testing.T) {
	tests := []struct {
		name   string
		distro Distro
	}{
		{"edge has no OSV ecosystem", Distro{ID: "alpine", VersionID: "edge"}},
		{"edge as syft spells it", Distro{ID: "alpine", VersionID: "3.21_alpha20240807"}},
		{"no version at all", Distro{ID: "alpine", VersionID: ""}},
		{"major only", Distro{ID: "alpine", VersionID: "3"}},
		{"trailing dot", Distro{ID: "alpine", VersionID: "3."}},
		// "12" has no dot, so it fails on the X.Y check before the ID check is
		// ever reached — the ID guard needs a version that WOULD parse. Without
		// these, deleting `d.ID != "alpine"` leaves the suite green and
		// Distro{ID: "ubuntu", VersionID: "22.04"} yields "Alpine:v22.04".
		{"unsupported distro", Distro{ID: "debian", VersionID: "12"}},
		{"unsupported distro with a parseable version", Distro{ID: "debian", VersionID: "12.5"}},
		{"another unsupported distro", Distro{ID: "ubuntu", VersionID: "22.04"}},
		{"no id", Distro{ID: "", VersionID: "3.19"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.distro.Ecosystem()
			if err == nil {
				t.Fatalf("Ecosystem() = %q, nil error; want an error so the "+
					"packages are skipped rather than reported clean", got)
			}
			if !errors.Is(err, ErrNoEcosystem) {
				t.Errorf("error %v does not wrap ErrNoEcosystem; callers match on it", err)
			}
			if got != "" {
				t.Errorf("Ecosystem() returned %q alongside an error; a caller that "+
					"checks the value first would key on it", got)
			}
			// The message reaches a human in the skip reason, so it has to name
			// what was wrong, not just that something was.
			if !strings.Contains(err.Error(), tt.distro.ID) &&
				!strings.Contains(err.Error(), "distro") {
				t.Errorf("error %q names neither the distro nor the problem", err)
			}
		})
	}
}

// The key must be exactly what the store is written with. A trailing patch
// component or a missing "v" produces a lookup that always misses, which reads
// as a clean scan rather than a failure.
func TestDistroEcosystem_MatchesTheOSVKeyExactly(t *testing.T) {
	got, err := Distro{ID: "alpine", VersionID: "3.19.9"}.Ecosystem()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, ".") != 1 {
		t.Errorf("Ecosystem() = %q; OSV publishes Alpine:vX.Y, not a patch release", got)
	}
	if !strings.HasPrefix(got, "Alpine:v") {
		t.Errorf("Ecosystem() = %q; OSV keys carry the v prefix", got)
	}
}
