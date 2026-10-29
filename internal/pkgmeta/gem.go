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
// The suffix after the first hyphen is taken off only when it is a platform:
// the purl's own "platform" qualifier says so, or Gem::Platform would name an
// operating system in it. A prerelease spelled with a hyphen ("3.0.0-rc1",
// which a producer may write unnormalized; RubyGems itself would have
// written "3.0.0.pre.rc1") names none and is left alone, so it still sorts
// below its release. Advisories spell prereleases that way too (13 of 78,698
// RubyGems bounds on 2026-10-27), which is why this is done to the installed
// version here and not in the Gem comparer.
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

// gemPlatformOS reports whether Gem::Platform.new(s) names a known operating
// system (lib/rubygems/platform.rb, Gem::Platform#initialize): "cpu-os", or a
// bare os for the legacy java form. Ruby's own patterns, kept unanchored
// where Ruby's are; anything else is Gem::Platform's "unknown".
func gemPlatformOS(s string) bool {
	s = strings.TrimRight(s, "-")
	cpu, os, ok := strings.Cut(s, "-")
	if !ok {
		os = cpu
	}
	return gemOSPattern.MatchString(os)
}

var gemOSPattern = regexp.MustCompile(`aix|cygwin|darwin|^macruby|freebsd|^java|^jruby$|^dalvik-?\d*$|^dotnet|linux|mingw|mswin\d+|netbsdelf|openbsd|solaris|wasi`)
