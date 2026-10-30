package pkgmeta

import (
	"regexp"
	"strings"
)

// InstalledGemVersion returns an installed gem's version without the platform
// a producer may have left on it (audit A6, D155). syft writes a Gemfile.lock
// entry's text as the version and the purl version alike
// ("pkg:gem/nokogiri@1.13.8-x86_64-linux"), and Gem::Version reads that
// hyphen as a prerelease ("1.13.8.pre.x86_64..."), or refuses the underscore.
//
// The suffix after the first hyphen is taken off only when it is a platform
// as a whole: the purl's own "platform" qualifier says so, or it is a CPU
// Gem::Platform users write followed by an operating system Gem::Platform
// recognises, or a bare operating system (the legacy "java" form). A
// prerelease spelled with a hyphen ("3.0.0-rc1", which a producer may write
// unnormalized; RubyGems itself would have written "3.0.0.pre.rc1") is not
// one, even with a platform after it ("3.0.0-rc1-arm64-darwin"), and is left
// as written, so it still sorts below its release. Advisories spell
// prereleases that way too (10 range bounds among 78,698 RubyGems version
// strings in the published database of 2026-10-27), which is why this is
// done to the installed version here and not in the Gem comparer.
func InstalledGemVersion(version, platformQualifier string) string {
	if platformQualifier != "" && strings.HasSuffix(version, "-"+platformQualifier) {
		if v := strings.TrimSuffix(version, "-"+platformQualifier); v != "" {
			return v
		}
	}
	core, suffix, ok := strings.Cut(version, "-")
	if !ok || core == "" || !gemPlatformOS(suffix) {
		return version
	}
	return core
}

// gemPlatformOS reports whether s, as a whole, is a platform: "cpu-os[-version]"
// with a CPU from gemCPUPattern and an operating system Gem::Platform.new
// recognises (lib/rubygems/platform.rb, Gem::Platform#initialize), or a bare
// operating system for the legacy java form. The OS patterns are Ruby's, with
// Ruby's anchoring: unanchored where Ruby's are, and "^java" with no end
// anchor, as Ruby has it. Gem::Platform itself accepts any CPU; the list here
// is what keeps "rc1-arm64-darwin" (a prerelease, then a platform) from
// reading as CPU "rc1".
func gemPlatformOS(s string) bool {
	s = strings.TrimRight(s, "-")
	cpu, os, ok := strings.Cut(s, "-")
	if !ok {
		return gemOSPattern.MatchString(cpu)
	}
	return gemCPUPattern.MatchString(cpu) && gemOSPattern.MatchString(os)
}

// gemCPUPattern is the CPU field of the platforms RubyGems and bundler write:
// Gem::Platform maps i386..i686 to x86, and the rest appear as written
// (x86_64-linux-gnu, arm64-darwin, x64-mingw-ucrt, universal-java-17,
// wasm32-wasi, ...).
var gemCPUPattern = regexp.MustCompile(`^(x86|x86_64|x64|amd64|i\d86|arm|arm64|armv\w+|aarch64|universal|powerpc\w*|ppc\w*|s390x?|sparc\w*|riscv64|loongarch64|mips\w*|ia64|wasm32|wasm64)$`)

var gemOSPattern = regexp.MustCompile(`aix|cygwin|darwin|^macruby|freebsd|^java|^jruby$|^dalvik-?\d*$|^dotnet|linux|mingw|mswin\d+|netbsdelf|openbsd|solaris|wasi`)
