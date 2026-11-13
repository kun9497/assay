package pkgmeta

import "testing"

// Main QA of ef0bc1a (2026-11-13): the store spells the Debian releases
// before 7 with OSV's two-part number, and a scan that asked for
// "Debian:4" over a database holding Debian:4.0 left etch, lenny and
// squeeze unevaluated. The key follows the store's spelling by release.
func TestDistro_DebianEcosystemKeySpelling(t *testing.T) {
	for _, tc := range []struct{ versionID, want string }{
		{"12", "Debian:12"},
		{"12.15", "Debian:12"},
		{"7", "Debian:7"},
		{"7.11", "Debian:7"},
		{"6.0", "Debian:6.0"},
		{"6.0.10", "Debian:6.0"},
		{"6", "Debian:6.0"},
		{"5.0", "Debian:5.0"},
		{"5", "Debian:5.0"},
		{"4.0", "Debian:4.0"},
		{"4", "Debian:4.0"},
		{"3.1", "Debian:3.1"},
		{"3.0", "Debian:3.0"},
	} {
		got, err := (Distro{ID: "debian", VersionID: tc.versionID}).Ecosystem()
		if err != nil || got != tc.want {
			t.Errorf("Debian %q: key %q, %v; want %q", tc.versionID, got, err, tc.want)
		}
	}
	for _, versionID := range []string{"3", "", "bookworm/sid", "3.x"} {
		if got, err := (Distro{ID: "debian", VersionID: versionID}).Ecosystem(); err == nil {
			t.Errorf("Debian %q: key %q, want an error (no release the store keys)", versionID, got)
		}
	}
}

// Main QA of 67e2cf6 (2026-11-13): Debian's archive spells the point
// releases before squeeze with an "r" (the etch Release file says 4.0r9),
// and a VERSION_ID or SBOM version of that shape names the release -- it
// had been refused as "no two-part release", and --fail-on-eol fell silent
// on it. A bare "3" (woody or sarge) and sid stay refused, and so do the
// spellings Debian never used.
func TestDistro_DebianArchiveRevisionSpellingNamesItsRelease(t *testing.T) {
	for _, tc := range []struct{ versionID, want string }{
		{"4.0r9", "Debian:4.0"},
		{"4.0r1", "Debian:4.0"},
		{"3.0r6", "Debian:3.0"},
		{"3.1r8", "Debian:3.1"},
		{"5.0r10", "Debian:5.0"},
	} {
		got, err := (Distro{ID: "debian", VersionID: tc.versionID}).Ecosystem()
		if err != nil || got != tc.want {
			t.Errorf("Debian %q: key %q, %v; want %q", tc.versionID, got, err, tc.want)
		}
	}
	for _, versionID := range []string{"3", "3r6", "4r9", "4.0r", "4.0rc1", "4.0r9r1", "sid", "etch"} {
		if got, err := (Distro{ID: "debian", VersionID: versionID}).Ecosystem(); err == nil {
			t.Errorf("Debian %q: key %q, want an error (no release the store keys)", versionID, got)
		}
	}
}
