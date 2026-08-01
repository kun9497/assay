package gobinary

import (
	"strconv"
	"strings"
)

// normalizeGoVersion turns a toolchain version as Go stamps it into one the
// Go comparer can order against a stdlib advisory's bounds (D24).
//
// The live database holds 159 advisories against `stdlib`, with ordinary
// ranges — `introduced="1.16.0-0"`, `fixed="1.16.1"`. The toolchain version
// arrives as `go1.26.4`. Three of the four shapes Go emits are rejected by the
// comparer outright, which was measured:
//
//	go1.26.4    -> core identifier "go1": invalid version
//	1.26        -> core needs exactly three identifiers
//	1.21rc1     -> core needs exactly three identifiers
//	1.22beta1   -> core needs exactly three identifiers
//
// That makes a MISSED normalization loud: the package is skipped and counted.
// The quiet failure is the opposite — a form that parses but orders wrongly.
// `1.21.0+rc.1` is the trap: it parses, it looks right, and semver ignores
// build metadata in precedence, so a release candidate would compare EQUAL to
// its release and a vulnerable toolchain would scan clean. The pre-release
// separator has to be a hyphen, and the number has to be its own dot-separated
// identifier so that rc.2 orders above rc.1 rather than lexically.
//
// Written as an explicit scan rather than a regexp so it can be read against
// the shapes above line by line. Same reasoning as the apk comparer (D9): the
// tidier version is where the quiet ordering bug gets in.
func normalizeGoVersion(v string) (string, bool) {
	// A development toolchain — "devel go1.27-abc123 2026-01-01" — names no
	// released version. Refusing is right: inventing 1.27.0 would claim a
	// version that does not exist and could sit on either side of a fix.
	//
	// Removing this check leaves the suite green, verified as a mutation: a
	// devel string fails the digit check below anyway, because it starts with
	// "devel" rather than "go". It stays because it says WHY that input is
	// refused, where the digit check only says it is malformed.
	if strings.ContainsAny(v, " \t") {
		return "", false
	}
	// The prefix is optional so this is safe to call on an already-normalized
	// value. "golang1.26" is not a toolchain version and must not become one —
	// though the numeric check on each component below also rejects it, so
	// removing this guard is another verified true equivalent. Both are kept:
	// they fail at different distances from the cause, and the near one gives
	// the better answer to "why".
	rest := strings.TrimPrefix(v, "go")
	if rest == "" || !isDigit(rest[0]) {
		return "", false
	}

	// Split off a pre-release. Go writes it with no separator (1.21rc1), but
	// also emits the semver form for some toolchains (1.24.0-rc.1), which is
	// already correct and passes through.
	core, pre := rest, ""
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		core, pre = rest[:i], rest[i+1:]
	} else {
		for _, kind := range []string{"rc", "beta", "alpha"} {
			if i := strings.Index(rest, kind); i > 0 {
				n := rest[i+len(kind):]
				if n == "" || !allDigits(n) {
					return "", false
				}
				core, pre = rest[:i], kind+"."+n
				break
			}
		}
	}

	// The core must be one to three numeric components, padded to three.
	// Padding is not cosmetic: the comparer rejects a two-component core, so
	// without it every binary built by a pre-1.21 initial release — go1.20,
	// go1.16 — is silently skipped.
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return "", false
	}
	for _, p := range parts {
		if p == "" || !allDigits(p) {
			return "", false
		}
		// A leading zero is not a valid semver identifier, and no Go release
		// has one.
		if len(p) > 1 && p[0] == '0' {
			return "", false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return "", false
		}
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}

	out := strings.Join(parts, ".")
	if pre != "" {
		// A hyphen, never a plus: build metadata is ignored in semver
		// precedence, so "+rc.1" would make a release candidate equal to its
		// own release.
		out += "-" + pre
	}
	return out, true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}
