package source

import (
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// The callers — Run against a registry, a layout and an archive — are held in
// internal/scancmd/platform_test.go. These are the branches a caller test
// cannot reach economically: every normalisation row and every ladder edge.

func TestParsePlatform_Normalises(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"linux/amd64", "linux/amd64"},
		{"linux/x86_64", "linux/amd64"},
		{"linux/x86-64", "linux/amd64"},
		{"linux/amd64/v1", "linux/amd64"},
		{"linux/amd64/v3", "linux/amd64/v3"},
		{"linux/aarch64", "linux/arm64"},
		{"linux/arm64/v8", "linux/arm64"},
		{"linux/arm64/8", "linux/arm64"},
		{"linux/armhf", "linux/arm/v7"},
		{"linux/armel", "linux/arm/v6"},
		{"linux/arm", "linux/arm/v7"},
		{"linux/arm/7", "linux/arm/v7"},
		{"linux/arm/v5", "linux/arm/v5"},
		{"linux/arm/6", "linux/arm/v6"},
		{"linux/i386", "linux/386"},
		{"LINUX/AMD64", "linux/amd64"},
		{"linux/riscv64", "linux/riscv64"},
	} {
		p, err := ParsePlatform(tc.in)
		if err != nil {
			t.Errorf("ParsePlatform(%q): %v", tc.in, err)
			continue
		}
		if got := PlatformString(p); got != tc.want {
			t.Errorf("ParsePlatform(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestParsePlatform_Refuses(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "empty value"},
		{"linux", "is not os/arch[/variant]"},
		{"linux/arm/v7/x", "one variant at most"},
		{"linux/arm64:10.0", "carries an OS version"},
		{"linux/", "has an empty part"},
		{"/amd64", "has an empty part"},
		{"linux//v7", "has an empty part"},
		{"windows/amd64", "Windows images are not supported"},
	} {
		_, err := ParsePlatform(tc.in)
		if err == nil {
			t.Errorf("ParsePlatform(%q) accepted it", tc.in)
			continue
		}
		if !strings.HasPrefix(err.Error(), "--platform: ") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParsePlatform(%q) = %q, want a --platform error containing %q", tc.in, err, tc.want)
		}
	}
}

// A candidate's OS version is not compared (linux/arm64:cbl-mariner-2.0
// matches a linux/arm64 request); normalisation drops it.
func TestNormalizePlatform_DropsCandidateOSVersion(t *testing.T) {
	got := normalizePlatform(v1.Platform{OS: "linux", Architecture: "arm64", OSVersion: "cbl-mariner-2.0"})
	if !samePlatform(got, v1.Platform{OS: "linux", Architecture: "arm64"}) || got.OSVersion != "" {
		t.Errorf("normalizePlatform kept %+v", got)
	}
}

// choosePlatform over normalised candidates: exact first anywhere, then the
// ladder's highest rung on offer, and nothing else.
func TestChoosePlatform(t *testing.T) {
	norm := func(ss ...string) []v1.Platform {
		var out []v1.Platform
		for _, s := range ss {
			parts := strings.Split(s, "/")
			p := v1.Platform{OS: parts[0], Architecture: parts[1]}
			if len(parts) == 3 {
				p.Variant = parts[2]
			}
			out = append(out, normalizePlatform(p))
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		want  string
		offer []string
		pick  int // -1: miss
		match string
	}{
		{"bare arm is v7, not the first arm", "linux/arm", []string{"linux/amd64", "linux/arm/v5", "linux/arm/v6", "linux/arm/v7"}, 3, MatchExact},
		{"arm64/v8 matches variantless arm64", "linux/arm64/v8", []string{"linux/amd64", "linux/arm64"}, 1, MatchExact},
		{"variantless arm64 matches arm64/v8", "linux/arm64", []string{"linux/arm64/v8"}, 0, MatchExact},
		{"aarch64 candidate", "linux/arm64", []string{"linux/aarch64"}, 0, MatchExact},
		{"x86_64 candidate", "linux/amd64", []string{"linux/x86_64"}, 0, MatchExact},
		{"armhf candidate is v7", "linux/arm/v7", []string{"linux/armhf"}, 0, MatchExact},
		{"armel candidate is v6", "linux/arm/v6", []string{"linux/armel"}, 0, MatchExact},
		{"amd64/v1 is amd64", "linux/amd64/v1", []string{"linux/amd64"}, 0, MatchExact},
		{"exact beats a compatible met first", "linux/arm/v7", []string{"linux/arm/v6", "linux/arm/v7"}, 1, MatchExact},
		{"v7 falls back to v6", "linux/arm/v7", []string{"linux/amd64", "linux/arm/v6"}, 1, MatchCompatible},
		{"the highest compatible rung wins", "linux/arm/v8", []string{"linux/arm/v5", "linux/arm/v6"}, 1, MatchCompatible},
		{"v7 reaches v5", "linux/arm/v7", []string{"linux/arm/v5"}, 0, MatchCompatible},
		{"v5 never climbs to v6", "linux/arm/v5", []string{"linux/arm/v6", "linux/arm/v7"}, -1, ""},
		{"arm64 never falls to arm", "linux/arm64", []string{"linux/arm/v7"}, -1, ""},
		{"arm never climbs to arm64", "linux/arm/v7", []string{"linux/arm64"}, -1, ""},
		{"amd64/v3 on an amd64-only index", "linux/amd64/v3", []string{"linux/arm64", "linux/amd64"}, 1, MatchCompatible},
		{"amd64/v3 prefers v2 over base", "linux/amd64/v3", []string{"linux/amd64", "linux/amd64/v2"}, 1, MatchCompatible},
		{"amd64 never climbs to v2", "linux/amd64", []string{"linux/amd64/v2"}, -1, ""},
		{"OS must match", "linux/amd64", []string{"freebsd/amd64"}, -1, ""},
		{"386 never falls back", "linux/386", []string{"linux/amd64"}, -1, ""},
		{"nothing offered", "linux/amd64", nil, -1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := norm(tc.want)[0]
			i, match, ok := choosePlatform(want, norm(tc.offer...))
			if tc.pick < 0 {
				if ok {
					t.Errorf("chose %s (%s); want a miss", tc.offer[i], match)
				}
				return
			}
			if !ok || i != tc.pick || match != tc.match {
				t.Errorf("choosePlatform = (%d, %q, %v), want (%d, %q, true)", i, match, ok, tc.pick, tc.match)
			}
		})
	}
}

// The miss message's offer list is deterministic: sorted and deduplicated.
func TestOfferedList_SortedAndDeduplicated(t *testing.T) {
	got := offeredList([]v1.Platform{
		{OS: "linux", Architecture: "s390x"},
		{OS: "linux", Architecture: "arm", Variant: "v7"},
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm", Variant: "v7"},
	})
	if want := "linux/amd64, linux/arm/v7, linux/s390x"; got != want {
		t.Errorf("offeredList = %q, want %q", got, want)
	}
}

// The default is HostPlatform normalised: an arm build asks for arm/v7.
func TestDefaultPlatform_NormalisesTheHost(t *testing.T) {
	orig := HostPlatform
	t.Cleanup(func() { HostPlatform = orig })
	HostPlatform = func() v1.Platform { return v1.Platform{OS: "linux", Architecture: "arm"} }
	if got := PlatformString(DefaultPlatform()); got != "linux/arm/v7" {
		t.Errorf("DefaultPlatform = %s, want linux/arm/v7", got)
	}
}
