// Package version implements per-ecosystem version ordering.
//
// There is deliberately no shared compareVersions (D9). Debian epochs, RPM
// release ordering, semver pre-release precedence, and PEP 440 all disagree,
// and a single function that tries to serve them is the bug this design avoids.
package version

import (
	"errors"
	"regexp"
	"strings"
)

// ErrInvalid marks a version string that cannot be ordered. Callers must treat
// it as "unknown", never as "not vulnerable" — a swallowed error here is a
// missed vulnerability.
var ErrInvalid = errors.New("invalid version")

// Cause says which side of a comparison could not be read (D36). D35 put that
// in the message; this puts it in the type, because a caller deciding whether
// to fail a build cannot match on prose.
//
// The distinction is whether the person running the scan can act on it. An
// unreadable target version usually means their own inventory; an unreadable
// advisory bound is upstream data they will never be able to fix, and a gate
// that cannot tell the two apart is one that stays red forever and gets turned
// off.
type Cause int

const (
	// CauseUnknown is the zero value, for an error this package did not
	// classify. It is deliberately not one of the two real answers: a caller
	// that has to guess should get "unknown" rather than a plausible default,
	// and a new error site that forgets to classify itself shows up as this
	// rather than silently joining whichever side the zero value named.
	CauseUnknown Cause = iota
	// CauseAdvisoryData: a bound in the advisory could not be read.
	CauseAdvisoryData
	// CauseTargetVersion: the version being tested could not be read.
	CauseTargetVersion
)

// causeErr carries a Cause without changing the message. Error() delegates, so
// D35's wording is untouched and this is purely a second, machine-readable
// channel for the same fact.
type causeErr struct {
	cause Cause
	err   error
}

func (e causeErr) Error() string { return e.err.Error() }
func (e causeErr) Unwrap() error { return e.err }

// withCause tags err, leaving its message exactly as written.
func withCause(c Cause, err error) error { return causeErr{cause: c, err: err} }

// CauseOf reports which side of a comparison an error blames, or CauseUnknown.
func CauseOf(err error) Cause {
	var ce causeErr
	if errors.As(err, &ce) {
		return ce.cause
	}
	return CauseUnknown
}

type Comparer interface {
	// Compare returns -1, 0, or 1. It returns an error wrapping ErrInvalid
	// rather than guessing an ordering for input it cannot parse.
	Compare(a, b string) (int, error)
}

var registry = map[string]Comparer{
	"Go":   SemVer{},
	"npm":  SemVer{},
	"PyPI": PEP440{},
	// Cargo requires a semver-compliant version of every crate it publishes,
	// and Cargo.lock records the resolved one, so the comparer written for npm
	// and Go applies unchanged. crates.io is not a distro: the key carries no
	// release, so it is a plain map entry rather than a prefix rule (D6).
	"crates.io": SemVer{},
	// RubyGems, Packagist, NuGet and Maven are language ecosystems like the
	// four above, not distros: their OSV keys carry no release, so each is a
	// plain map entry rather than a prefix rule (D6).
	"RubyGems":  Gem{},
	"Packagist": Composer{},
	"NuGet":     NuGet{},
	"Maven":     Maven{},
}

// mainlineUbuntu matches the two shapes OSV gives a mainline Ubuntu release:
// a long-term one carries the suffix, an interim one does not. Anchored, so
// that no lineage key can satisfy it.
var mainlineUbuntu = regexp.MustCompile(`^Ubuntu:[0-9]{2}\.[0-9]{2}(:LTS)?$`)

func For(ecosystem string) (Comparer, bool) {
	// Distro ecosystems carry their release (D6), so "Alpine:v3.19" cannot be a
	// map key — the map would need one entry per release, forever. The bare
	// "Alpine" must NOT resolve: it is not a key we ever build, and letting it
	// through would make a bug that drops the release look like it worked, every
	// lookup landing in an empty bucket and reporting clean.
	if rel, ok := strings.CutPrefix(ecosystem, "Alpine:"); ok && rel != "" {
		return APK{}, true
	}
	// Same rule, same reason: "Debian" bare is not a key this project ever
	// builds, and resolving it would make a bug that drops the release look
	// like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Debian:"); ok && rel != "" {
		return Deb{}, true
	}
	// Same rule again. "Red Hat" bare is not a key this project builds — the
	// provider writes "Red Hat:9" from the mainline CPE's major (D47) — and
	// resolving it would make a bug that drops the release look like it
	// worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Red Hat:"); ok && rel != "" {
		return RPM{}, true
	}
	// D71. Rocky is RPM too — its OSV archive is release-qualified the same
	// way ("Rocky Linux:9"), and rpmvercmp does not care which distro built
	// the package. Same rule, same reason as the two clauses above: "Rocky
	// Linux" bare is not a key this project ever builds, and resolving it
	// would make a bug that drops the release look like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Rocky Linux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D72. AlmaLinux is RPM too — its own OSV archive is release-qualified the
	// same way ("AlmaLinux:9"), and rpmvercmp does not care which distro built
	// the package (nor that Alma's module builds spell the platform tag
	// "module_el" where Red Hat and Rocky write "module+el" — both are
	// ordinary rpmvercmp separators, D46, and rpmModuleBuild in
	// internal/matcher already recognizes both spellings). Same rule, same
	// reason as the two clauses above: "AlmaLinux" bare is not a key this
	// project ever builds, and resolving it would make a bug that drops the
	// release look like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "AlmaLinux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D53. Ubuntu is dpkg, so the comparer D40 wrote for Debian handles its
	// revisions (2.4.4-2ubuntu17.10) unchanged — the version scheme was never
	// the blocker. The KEY was.
	//
	// Matched by an anchored pattern rather than by prefix, and that is the
	// whole point. Ubuntu:Pro:22.04:LTS and Ubuntu:Pro:FIPS-updates:22.04:LTS
	// are real OSV keys describing the SAME release, and this build does not
	// ingest them (D53). A prefix match would hand them a comparer, and a
	// package carrying such a key would then be evaluated against a database
	// holding nothing for it — the silent clean D20 exists to prevent.
	// Refusing them here routes those packages to the coverage skip instead.
	if mainlineUbuntu.MatchString(ecosystem) {
		return Deb{}, true
	}
	c, ok := registry[ecosystem]
	return c, ok
}
