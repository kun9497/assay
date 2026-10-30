package pkgmeta

import "testing"

// The branches the scan-level tests (scancmd, TestRun_A6_*) do not reach.
func TestInstalledGemVersion(t *testing.T) {
	for _, tc := range []struct {
		version, platform, want string
	}{
		{"1.13.8", "", "1.13.8"},
		{"1.13.8-x86_64-linux", "", "1.13.8"},
		{"1.13.8-x86_64-linux-gnu", "", "1.13.8"},
		{"1.17.0-x86_64-linux-musl", "", "1.17.0"},
		{"1.13.8-arm64-darwin", "", "1.13.8"},
		{"1.13.8-universal-darwin-21", "", "1.13.8"},
		{"1.13.8-x64-mingw-ucrt", "", "1.13.8"},
		{"1.13.8-x86-mingw32", "", "1.13.8"},
		{"1.13.8-x86-mswin32-60", "", "1.13.8"},
		{"1.13.8-aarch64-linux", "", "1.13.8"},
		{"1.13.8-x86_64-freebsd-13", "", "1.13.8"},
		{"0.14.2-java", "", "0.14.2"},
		{"0.14.2-jruby", "", "0.14.2"},
		{"0.14.2-universal-java-17", "", "0.14.2"},
		{"1.0.0-wasm32-wasi", "", "1.0.0"},
		// Prereleases spelled with a hyphen name no platform.
		{"3.0.0-rc1", "", "3.0.0-rc1"},
		{"1.4.0-beta.1", "", "1.4.0-beta.1"},
		{"7.0.0-pre", "", "7.0.0-pre"},
		{"2.0.0-alpha-2", "", "2.0.0-alpha-2"},
		// Gem::Platform's own /^java-?(\d+(?:\.\d+)*)?/ has no end anchor,
		// so Ruby reads "javascript" as the java os too; mirrored, not fixed.
		{"1.0.0-javascript", "", "1.0.0"},
		// A prerelease before a platform: the suffix is not a platform as a
		// whole, so the prerelease is not lost (branch review
		// wf_257e6542-a9a). It stays as written, below its release or
		// unreadable, as before A6.
		{"1.0.0-rc1-arm64-darwin", "", "1.0.0-rc1-arm64-darwin"},
		{"1.0.0-rc1-java", "", "1.0.0-rc1-java"},
		{"1.0.0-rc1-x86_64-linux", "", "1.0.0-rc1-x86_64-linux"},
		{"1.0.0-beta-linux", "", "1.0.0-beta-linux"},
		{"1.0.0-i686-linux", "", "1.0.0"},
		{"1.0.0-armv7-linux", "", "1.0.0"},
		{"1.0.0-ppc64le-linux", "", "1.0.0"},
		{"1.0.0-s390x-linux", "", "1.0.0"},
		{"1.0.0-riscv64-linux", "", "1.0.0"},
		// Nothing before the platform leaves the version as written.
		{"-x86_64-linux", "", "-x86_64-linux"},
		// The purl's own qualifier is believed for any platform.
		{"2.0.0-weirdplat", "weirdplat", "2.0.0"},
		{"2.0.0", "x86_64-linux", "2.0.0"},
		{"2.0.0-rc1", "x86_64-linux", "2.0.0-rc1"},
		{"-weirdplat", "weirdplat", "-weirdplat"},
	} {
		if got := InstalledGemVersion(tc.version, tc.platform); got != tc.want {
			t.Errorf("InstalledGemVersion(%q, %q) = %q, want %q", tc.version, tc.platform, got, tc.want)
		}
	}
}
