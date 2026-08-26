package version

import (
	"errors"
	"testing"
)

// The ordering rules come from apk-tools/src/version.c. Cases are grouped by the
// rule they exercise, so a failure names the rule rather than just a pair.
func TestAPKCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		why  string
	}{
		// Plain numeric ordering, the 7,565-case majority shape in v3.19.
		{"1.2.3-r0", "1.2.3-r0", 0, "identical"},
		{"1.2.3-r0", "1.2.3-r1", -1, "revision breaks the tie"},
		{"1.2.3-r2", "1.2.3-r10", -1, "revision is numeric, not lexical"},
		{"1.2.3-r0", "1.2.4-r0", -1, "patch component"},
		{"1.2.9-r0", "1.2.10-r0", -1, "digit runs are numeric, not lexical"},
		{"1.9.0-r0", "1.10.0-r0", -1, "minor component is numeric too"},
		{"1.2.3.4-r0", "1.2.3.5-r0", -1, "four components is a real shape (431 of them)"},

		// Differing component counts. apkEnd is the highest token kind and a
		// higher kind means a lower version, so the shorter one sorts below.
		{"1.2", "1.2.1", -1, "shorter runs out first"},
		{"1.2.0", "1.2", 1, "an explicit .0 still outranks nothing"},
		{"1-r0", "1.0-r0", -1, "one component vs two"},

		// The surprising one: a missing revision is lower than -r0, because
		// apkEnd(7) outranks apkRevisionNo(6).
		{"1.0", "1.0-r0", -1, "no revision sorts below -r0"},

		// Pre-release suffixes sort BELOW the bare version.
		{"1.0_alpha1", "1.0", -1, "alpha is a pre-release"},
		{"1.0_beta1", "1.0", -1, "beta is a pre-release"},
		{"1.0_pre1", "1.0", -1, "pre is a pre-release"},
		{"1.0_rc1", "1.0", -1, "rc is a pre-release"},
		{"1.0_alpha1", "1.0_beta1", -1, "alpha < beta"},
		{"1.0_beta1", "1.0_pre1", -1, "beta < pre"},
		{"1.0_pre1", "1.0_rc1", -1, "pre < rc"},
		{"1.0_rc1", "1.0_rc2", -1, "suffix number is numeric"},
		{"1.0_rc2", "1.0_rc10", -1, "suffix number is numeric, not lexical"},

		// Post-release suffixes sort ABOVE the bare version. Reversing this half
		// silently clears every _p package — 594 version strings in v3.19.
		{"1.0", "1.0_p1", -1, "p is a post-release"},
		{"1.0_rc1", "1.0_p1", -1, "pre-release < bare < post-release"},
		{"1.0_cvs1", "1.0_svn1", -1, "cvs < svn"},
		{"1.0_svn1", "1.0_git1", -1, "svn < git"},
		{"1.0_git1", "1.0_hg1", -1, "git < hg"},
		{"1.0_hg1", "1.0_p1", -1, "hg < p"},
		{"1.0_p1", "1.0_p2", -1, "post-release number is numeric"},
		{"1.0_git", "1.0_git1", -1, "the suffix number is optional"},

		// Single trailing letter, the openssl shape (1.1.1l-r0).
		{"1.1.1", "1.1.1a", -1, "a letter outranks no letter"},
		{"1.1.1a", "1.1.1b", -1, "letters compare by byte"},
		{"1.1.1k-r0", "1.1.1l-r0", -1, "the real openssl case"},
		{"1.1.1l-r0", "1.1.1l-r1", -1, "revision still breaks the tie"},

		// D31: a letter may carry a numeric patch level. Alpine ships these —
		// libretls 3.3.3p1-r3, sudo 1.7.4p6-r0, py3-* 0.12.5a0-r0 — and
		// apk-tools 2.x, which every released Alpine runs, parses them.
		{"3.3.3-r3", "3.3.3p1-r3", -1, "the letter outranks the bare version: libretls, Alpine 3.14"},
		{"3.3.3p1-r3", "3.3.4-r0", -1, "the numeric components still decide first"},
		{"3.3.3p1-r2", "3.3.3p1-r3", -1, "revision breaks the tie under the patch level"},
		{"3.3.3p1-r0", "3.3.3p2-r0", -1, "the patch level itself orders"},
		{"3.3.3p2-r0", "3.3.3p10-r0", -1, "and it is numeric, not lexical: 2 < 10"},
		{"1.7.4p6-r0", "1.9.5p2-r0", -1, "real sudo pair; components before the letter win"},
		{"2.1a15-r17", "2.1a16-r0", -1, "real py-* shape, two-digit patch level"},
		{"1.0a1", "1.0.1", -1, "apkLetter(2) outranks apkDigit(1), so the letter form is lower"},

		// The patch level is NOT subject to the leading-zero string sort below:
		// in apk-tools 2.x that rule belongs to the token entered after '.', and
		// this one is a plain digit token. This pair is the only one in the table
		// that can tell the two apart — "0" vs "1" gives '<' either way, so the
		// obvious-looking 0.12.5a0 vs 0.12.5a1 row proves nothing here.
		{"1.0a01", "1.0a1", 0, "patch level is numeric: 01 == 1, where a string sort would differ"},
		{"1.0a010", "1.0a10", 0, "same rule, two digits"},

		// The patch level must be a DIGIT token, which is what apk-tools 2.x
		// emits (next_token sets n = TOKEN_DIGIT there). Every row above still
		// passes if it is given apkSuffixNo instead, because that kind compares
		// numerically too — these are the pairs that align it against a token of
		// another kind, where the ordinal alone decides. apkDigit(1) is below
		// apkSuffix(3), so the suffixed side is the lower version; under
		// apkSuffixNo(4) both answers invert.
		{"1.0a_p1", "1.0a1", -1, "a patch level outranks a _p suffix: apkDigit(1) < apkSuffix(3)"},
		{"1.0a_git1", "1.0a1", -1, "same ordinal rule with a different post-release suffix"},
		{"1.0a1", "1.0a1_p1", -1, "and a suffix may still follow the patch level"},

		// Leading zeros switch to string comparison — but only for components
		// AFTER the first. That is why apk-tools gives the first one its own
		// token kind.
		{"1.01", "1.1", -1, "leading zero forces string sort: '01' < '1'"},
		{"1.001", "1.01", -1, "string sort again: '001' < '01'"},
		{"1.10", "1.9", 1, "no leading zero, so numeric: 10 > 9"},

		// The initial component stays numeric even with a leading zero. Every
		// one of these was a real mismatch against apk-tools' own vectors
		// before the initial digit got its own case; date-stamped versions
		// like 021109 are not hypothetical.
		{"006", "1.0.0", 1, "initial digit is numeric despite the zeros: 6 > 1"},
		{"1.06-r6", "006", -1, "initial digit numeric: 1 < 6"},
		{"3.0.0-r2", "021109-r3", -1, "initial digit numeric: 3 < 21109"},
		{"2.2.3-r2", "013", -1, "initial digit numeric: 2 < 13"},
		{"014-r1", "1.3.1-r1", 1, "initial digit numeric: 14 > 1"},

		// Commit-hash versions (1.0~abc123). Rare in Alpine's own packages but
		// legal syntax, and every one of these pairs kills a mutation the rest
		// of the table missed: the hash's position in the kind order, hash
		// comparison existing at all, and the parse branch existing at all.
		{"1.0~abc", "1.0~abd", -1, "hashes compare as strings"},
		{"1.0~abc", "1.0-r1", 1, "commit hash outranks a revision: END-ward kinds sort lower"},
		{"1.0~abc", "1.0", 1, "a hash outranks nothing"},
		{"1.0~aaa-r1", "1.0~aaa-r2", -1, "revision still breaks the tie after a hash"},

		// Kind-order boundaries that only these shapes reach.
		{"1.1.1w", "1.1.1_p1", 1, "a letter outranks a post-release suffix"},
		{"1.0_p_git", "1.0_p1", 1, "a further suffix outranks a suffix number"},

		// Real pairs lifted from Alpine:v3.19 advisories.
		{"2.1.23-r0", "2.1.26-r7", -1, "cyrus-sasl, CVE-2013-4122"},
		{"3.1.4-r5", "3.1.4-r6", -1, "openssl revision bump"},
		{"1.36.1-r15", "1.36.1-r2", 1, "busybox: r15 > r2, numerically"},
	}

	var c APK
	for _, tt := range tests {
		got, err := c.Compare(tt.a, tt.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) unexpected error: %v", tt.a, tt.b, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (%s)", tt.a, tt.b, got, tt.want, tt.why)
		}
		// Antisymmetry is a property of the ordering, not an extra case: without
		// it the comparator cannot be used to sort either.
		back, err := c.Compare(tt.b, tt.a)
		if err != nil {
			t.Errorf("Compare(%q, %q) unexpected error: %v", tt.b, tt.a, err)
			continue
		}
		if back != -tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry with %s)",
				tt.b, tt.a, back, -tt.want, tt.why)
		}
	}
}

// D9: an unparseable version must surface as ErrInvalid so the package is
// reported as skipped. Returning "not vulnerable" for garbage is a miss.
//
// This is a deliberate divergence from apk itself, which falls back to a raw
// string sort for input it cannot parse — its own vectors carry "1.0 < 1.0bc"
// and "23_foo > 4_beta" with the comment "invalid. do string sort". Guessing an
// order is the right call for a package manager deciding whether to upgrade and
// the wrong one for a scanner deciding whether you are exposed. Those two are
// the only cases in apk-tools' 738-comparison test/unit/version.data where this
// implementation does not return apk's answer.
func TestAPKCompare_Invalid(t *testing.T) {
	bad := []string{
		"",          // empty
		"-r1",       // revision with no version
		"1.0-r",     // revision marker with no number
		"1.0_",      // suffix marker with no suffix
		"1.0_wat1",  // unknown suffix
		"latest",    // not a version at all
		"1.0-r1-r2", // two revisions
		"1..0",      // empty component
		"1.0-1",     // '-' that is not '-r'
		"1.0 ",      // trailing space
		"v1.0",      // apk versions carry no v prefix
		"1.0A",      // apk's suffix class is [a-z]; uppercase is not a letter
		"1.0ab",     // one trailing letter only
		"1.0~",      // commit-hash marker with no hash
		"1.0~ABC",   // apk's hex class is [0-9a-f]; uppercase is not hex
		"1.0~xyz",   // not hex at all

		// D31 adds digits after the letter and nothing else. apk-tools 2.x is
		// bug-compatible with more than this — it accepts an empty digit run,
		// so "1.18.-r2" and "0.8.21.r2" parse there and the second sorts ABOVE
		// the "0.8.21-r2" it is a typo for. The rule is "a letter may carry a
		// patch level", not "match 2.x exactly", and these hold that line.
		"1.0a1b2",   // a second letter after the patch level
		"1.0a1.2",   // a dot after it; apk-tools 3.x asserts !0.1a.1 in its vectors
		"1.18.-r2",  // empty digit run, which 2.x accepts and 3.x rejects
		"0.8.21.r2", // '.r2' is a typo for '-r2', not a revision
		"1.0a1-1",   // still must be '-r'
	}
	var c APK
	for _, v := range bad {
		// Comparer's contract is an error *wrapping* ErrInvalid, not merely a
		// non-nil error: callers distinguish "cannot evaluate" from a genuine
		// failure by matching on it, and the two lead to different exit codes.
		if _, err := c.Compare(v, "1.0-r0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, %q) err = %v, want one wrapping ErrInvalid", v, "1.0-r0", err)
		}
		if _, err := c.Compare("1.0-r0", v); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, %q) err = %v, want one wrapping ErrInvalid", "1.0-r0", v, err)
		}
	}
}

// The registry must hand out APK for release-qualified Alpine keys. A miss here
// means every Alpine package silently falls through to "no comparer".
func TestForAlpine(t *testing.T) {
	for _, eco := range []string{"Alpine:v3.19", "Alpine:v3.20", "Alpine:v3.2"} {
		c, ok := For(eco)
		if !ok {
			t.Errorf("For(%q) not found", eco)
			continue
		}
		if _, isAPK := c.(APK); !isAPK {
			t.Errorf("For(%q) = %T, want APK", eco, c)
		}
	}
	// Unversioned "Alpine" is not a key we ever build (D6) and must not resolve,
	// or a bug that drops the release would look like it worked.
	for _, eco := range []string{"Alpine", "Alpine:"} {
		if _, ok := For(eco); ok {
			t.Errorf("For(%q) resolved; D6 requires a release in the key, and a "+
				"bug that drops it must not look like it worked", eco)
		}
	}
	// The language ecosystems must keep their own comparers.
	if c, ok := For("PyPI"); !ok {
		t.Error(`For("PyPI") stopped resolving`)
	} else if _, isPEP := c.(PEP440); !isPEP {
		t.Errorf(`For("PyPI") = %T, want PEP440`, c)
	}
}

// TestForWolfiAndChainguard: D88. Unlike Alpine above, "Wolfi" and
// "Chainguard" resolve BARE -- that is the whole key OSV publishes for
// either (no release axis to qualify, D6 satisfied vacuously), not a
// truncated one. A miss here means every Wolfi or Chainguard package
// silently falls through to "no comparer" and every package on those images
// reports skipped rather than evaluated.
func TestForWolfiAndChainguard(t *testing.T) {
	for _, eco := range []string{"Wolfi", "Chainguard"} {
		c, ok := For(eco)
		if !ok {
			t.Errorf("For(%q) not found", eco)
			continue
		}
		if _, isAPK := c.(APK); !isAPK {
			t.Errorf("For(%q) = %T, want APK", eco, c)
		}
	}
	// Unlike every OTHER apk/rpm distro's bare family name (Alpine, Debian,
	// Red Hat, Rocky Linux, AlmaLinux, ...), a release-qualified spelling of
	// either must NOT resolve -- there is no such key, since OSV never
	// publishes one, and letting a fabricated "Wolfi:1.0" resolve would
	// silently accept a shape nothing populates or looks up.
	for _, eco := range []string{"Wolfi:1.0", "Chainguard:1.0"} {
		if _, ok := For(eco); ok {
			t.Errorf("For(%q) resolved; neither ecosystem has a release axis, "+
				"and a release-qualified spelling of either is not a key anything builds", eco)
		}
	}
}

// TestForMinimOS: D92, a clean clone of TestForWolfiAndChainguard above.
// "MinimOS" resolves BARE -- that is the whole key OSV publishes (no release
// axis to qualify, D6 satisfied vacuously) -- not a truncated one. A miss
// here means every MinimOS package silently falls through to "no comparer"
// and every package on a MinimOS image reports skipped rather than
// evaluated.
func TestForMinimOS(t *testing.T) {
	c, ok := For("MinimOS")
	if !ok {
		t.Fatal(`For("MinimOS") not found`)
	}
	if _, isAPK := c.(APK); !isAPK {
		t.Errorf(`For("MinimOS") = %T, want APK`, c)
	}
	// Unlike every OTHER apk/rpm distro's bare family name, a
	// release-qualified spelling must NOT resolve -- there is no such key,
	// since OSV never publishes one, and letting a fabricated "MinimOS:1.0"
	// resolve would silently accept a shape nothing populates or looks up.
	if _, ok := For("MinimOS:1.0"); ok {
		t.Error(`For("MinimOS:1.0") resolved; MinimOS has no release axis, and a ` +
			`release-qualified spelling of it is not a key anything builds`)
	}
}
