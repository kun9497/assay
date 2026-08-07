// Package version implements per-ecosystem version ordering.
//
// There is deliberately no shared compareVersions (D9). Debian epochs, RPM
// release ordering, semver pre-release precedence, and PEP 440 all disagree,
// and a single function that tries to serve them is the bug this design avoids.
package version

import (
	"errors"
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
}

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
	c, ok := registry[ecosystem]
	return c, ok
}
