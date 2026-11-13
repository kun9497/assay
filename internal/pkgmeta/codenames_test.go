package pkgmeta

import "testing"

func TestCanonicalDistroQualifier(t *testing.T) {
	for q, want := range map[string]string{
		"bookworm":        "debian-12",
		"Bookworm":        "debian-12",
		"debian-bookworm": "debian-12",
		"bullseye":        "debian-11",
		"trixie":          "debian-13",
		"etch":            "debian-4.0",
		"squeeze":         "debian-6.0",
		"jammy":           "ubuntu-22.04",
		"ubuntu-jammy":    "ubuntu-22.04",
		"noble":           "ubuntu-24.04",
		"debian-12.15":    "debian-12.15",
		"Debian-12":       "debian-12",
		"Debian-12.15":    "debian-12.15",
		"Ubuntu-22.04":    "ubuntu-22.04",
		"debian-12":       "debian-12",
		"ubuntu-22.04":    "ubuntu-22.04",
		"rhel-9.4":        "rhel-9.4",
		"alpine-3.19":     "alpine-3.19",
		"ubuntu-bookworm": "ubuntu-bookworm",
		"debian-jammy":    "debian-jammy",
		"sid":             "sid",
		"":                "",
	} {
		if got := CanonicalDistroQualifier(q); got != want {
			t.Errorf("CanonicalDistroQualifier(%q) = %q, want %q", q, got, want)
		}
	}
}

// Every row of DebianReleases is a release this build keys (Debian:N), and
// the table holds exactly the codenames it is meant to: a dropped or extra
// row fails here, not in whichever scan first meets it.
func TestDebianReleasesAreKeyedReleases(t *testing.T) {
	// The number is the store's key for the release (Distro.Ecosystem):
	// OSV's two-part spelling before wheezy, the bare major from it on.
	want := map[string]string{"woody": "3.0", "sarge": "3.1", "etch": "4.0", "lenny": "5.0", "squeeze": "6.0", "wheezy": "7", "jessie": "8", "stretch": "9",
		"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14", "duke": "15"}
	got := DebianReleases()
	if len(got) != len(want) {
		t.Fatalf("DebianReleases has %d rows, want %d", len(got), len(want))
	}
	for name, num := range want {
		if got[name] != num {
			t.Errorf("DebianReleases[%q] = %q, want %q", name, got[name], num)
		}
		if q := CanonicalDistroQualifier(name); q != "debian-"+num {
			t.Errorf("CanonicalDistroQualifier(%q) = %q, want debian-%s", name, q, num)
		}
		if eco, err := (Distro{ID: "debian", VersionID: num}).Ecosystem(); err != nil || eco != "Debian:"+num {
			t.Errorf("Debian %s (%s): ecosystem %q, %v; want Debian:%s", name, num, eco, err, num)
		}
	}
}

// A codename names the major: it refines a local OS no finer than the
// major, and contradicts a point release of that major not at all.
func TestDistroScope_ForInstallationReadsCodenames(t *testing.T) {
	for _, tc := range []struct {
		local, installed string
		want             DistroScope
	}{
		{"debian-12.15", "bookworm", DistroScope{Qualifier: "debian-12.15"}},
		{"debian-12", "bookworm", DistroScope{Qualifier: "debian-12"}},
		{"", "bookworm", DistroScope{Qualifier: "debian-12"}},
		{"debian-12.15", "bullseye", DistroScope{Mixed: true}},
		{"debian-12.15", "debian-bookworm", DistroScope{Qualifier: "debian-12.15"}},
		{"ubuntu-22.04", "jammy", DistroScope{Qualifier: "ubuntu-22.04"}},
		{"ubuntu-22.04", "noble", DistroScope{Mixed: true}},
	} {
		if got := (DistroScope{Qualifier: tc.local}).ForInstallation(tc.installed); got != tc.want {
			t.Errorf("ForInstallation(%q) under %q = %+v, want %+v", tc.installed, tc.local, got, tc.want)
		}
	}
}
