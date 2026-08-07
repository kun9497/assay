package version

import (
	"errors"
	"testing"
)

// The ordering rules come from dpkg's lib/dpkg/version.c. Cases are grouped by
// the rule they exercise, so a failure names the rule rather than just a pair.
//
// Most of these are upstream dpkg's own vectors (scripts/t/Dpkg_Version.t and
// lib/dpkg/t/t-version.c); the rest are real version strings taken from
// debian:bookworm, gcr.io/distroless/base-debian12 and Ubuntu 24.04, so the
// table covers the shapes a scan actually meets and not only the ones the
// algorithm makes interesting.
var debTests = []struct {
	a, b string
	want int
	why  string
}{
	// Epoch. Compared as an integer, before either other part is looked at.
	{"1.2.3", "0:1.2.3", 0, "an omitted epoch is epoch 0, not 'unset'"},
	{"1:1.2.3", "01:1.2.3", 0, "the epoch is parsed as an integer, so leading zeros do not matter"},
	{"1:1.2.3-4", "1.2.4-1", 1, "the epoch decides before the upstream version is compared"},
	{"2.30.2-1", "1:2.30.2-1", -1, "the ONLY difference is the epoch; stripping it would call these equal"},
	{"2:2.5", "1:7.5", 1, "epoch 2 > 1 despite upstream 2.5 < 7.5"},

	// The revision, and where it splits.
	{"1.2.3", "1.2.3-0", 0, "dpkg strips the leading zero from the revision, leaving both empty — an absent revision and \"-0\" are one version"},
	{"1.2.3-4", "1.2.3-4", 0, "identical"},

	// The tilde. The rule most implementations get wrong, and the one that
	// costs most: a backport reading as NEWER than the release it was built
	// from is a silent miss on exactly the systems that took the fix.
	{"1.0~rc1", "1.0", -1, "order('~') = -1 is below order(end-of-part) = 0"},
	{"1.0~rc1", "1.0~", 1, "the '~' matches, then 'r' (114) beats the end of the part (0)"},
	{"1.0~rc1", "1.0a", -1, "'~' (-1) < 'a' (97)"},
	{"1.0~", "1.0", -1, "a tilde sorts before anything, even the end of a part"},
	{"1.0~~", "1.0~", -1, "Policy's chain: ~~ < ~~a < ~ < empty < a"},
	{"1.0~~a", "1.0~", -1, "same chain, second versus third element"},
	{"1.0~~", "1.0~~a", -1, "same chain, first versus second: end-of-part (0) < 'a' (97)"},
	{"1.2.3-4~bpo11+1", "1.2.3-4", -1, "a backport sorts below the release it was rebuilt from"},
	{"1.0~beta1~svn1245", "1.0~beta1", -1, "a snapshot of a beta sorts below the beta"},
	{"2.2~rc-4", "2.2-1", -1, "upstream '2.2~rc' < '2.2' is decided before the revisions are reached"},
	{"3.0.20-1~deb12u2", "3.0.20-1", -1, "real distroless libssl3: the tilde revision is a rebuild, not an update"},

	// The character classes. Letters rank below every other punctuation mark,
	// which is the opposite of ASCII order.
	{"1.0a", "1.0+", -1, "a letter returns c (97); other punctuation returns c+256 (299)"},
	{"1.0z", "1.0.0", -1, "'z' (122) < '.' (302): even the last letter precedes the first punctuation"},
	{"1.0", "1.0+", -1, "end-of-part (0) < '+' (299): running out is less than continuing"},
	{"0foo~foo+Bar", "0foo~foo+bar", -1, "within the letter class plain ASCII holds: 'B' (66) < 'b' (98)"},
	{"0foo.bar", "0foobar", 1, "'.' (302) > 'b' (98): punctuation outranks a letter"},
	{"1.0.8+nmu1", "1.0.8", 1, "'+' (299) > end-of-part (0)"},

	// Digit runs: leading zeros stripped, then numeric, not lexical.
	{"1.09", "1.9", 0, "leading zeros are stripped from both runs, so these are one version"},
	{"1.0000-1", "1.0-1", 0, "the same rule over a longer run"},
	{"1a", "1000a", -1, "after the zero-strip, the side with digits left is numerically longer"},
	{"0foo2.1", "0foo2.10", -1, "1 < 10 numerically; a lexical compare says the opposite"},
	{"0foo2.0", "0foo2.0.0", -1, "a is exhausted while b continues with a digit run"},
	{"1.011-1", "1.06-2", 1, "11 > 6 after zero-stripping, decided in the upstream part"},
	{"3.11", "3.10+nmu1", 1, "the digit run 11 > 10 returns before '+nmu1' is reached"},
	{"0foo1bar-1", "0foobar-1", -1, "alternation: 'foo' ties, then a has a digit and b has a letter"},

	// Real Debian security shapes. These are the comparisons a scan actually
	// performs, and every one of them decides a verdict.
	{"1.2.3-4", "1.2.3-4+deb11u1", -1, "a Debian point-release security fix"},
	{"1.2.3-4+deb11u1", "1.2.3-4+deb11u2", -1, "successive point releases"},
	{"5.2.15-2", "5.2.15-2+b13", -1, "real bookworm bash: a binNMU rebuild of the same source"},
	{"1:2.66-4+deb12u3", "1:2.66-4+deb12u3+b1", -1, "the same binNMU rule with an epoch present"},
	{"1.47.0-2", "1.47.0-2+b2", -1, "real bookworm e2fsprogs"},
	{"2.38.1-5+deb12u3", "1:2.38.1-5+deb12u3", -1, "real bookworm bsdutils: the source carries an epoch the binary does not"},
	{"2.4.4-2ubuntu17.4", "2.4.4-2ubuntu17.10", -1, "Ubuntu 24.04 gpgv: 4 < 10 numerically inside the revision"},
	{"12.2.0-14+deb12u1", "12.2.0-14+deb12u1", 0, "real bookworm gcc-12-base"},
}

func TestDebCompare(t *testing.T) {
	var c Deb
	for _, tc := range debTests {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q): %v (%s)", tc.a, tc.b, err, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d — %s", tc.a, tc.b, got, tc.want, tc.why)
		}
		// Antisymmetry on every row rather than in its own test: a comparer
		// that returned the same sign both ways would satisfy every assertion
		// above and order nothing.
		rev, err := c.Compare(tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%q, %q): %v", tc.b, tc.a, err)
			continue
		}
		if rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, rev, -tc.want)
		}
	}
}

// dpkg accepts what this rejects, and the difference is deliberate: dpkg
// downgrades the character-set violations to warnings and carries on with a
// usable parse, while D9 says an unparseable version must surface as ErrInvalid
// so the package is reported as skipped. Ordering a string dpkg itself calls
// malformed would mean vouching for something neither tool can.
func TestDebInvalid(t *testing.T) {
	bad := []string{
		"",        // empty
		"1.0-",    // trailing hyphen: an empty revision
		":1.0",    // empty epoch
		"10a:5.2", // the text before the colon is not an integer
		"-0",      // the last-hyphen split leaves an empty upstream
		"1.2 3-4", // interior whitespace
		"1:",      // nothing after the epoch colon
		"foo",     // upstream must start with a digit
		"1.2:3-4", // a colon with no epoch before it
		"1.0-2_3", // '_' is in neither character set
		"1.0/2",   // '/' is in neither character set
		"1.0-2:3", // ':' is not legal inside a revision
		"-1:1.0",  // a negative epoch is not a number
		"1.0\t2",  // a tab is whitespace, reached before TrimSpace could help
	}
	var c Deb
	for _, v := range bad {
		// The contract is an error WRAPPING ErrInvalid, not merely a non-nil
		// error: callers distinguish "cannot evaluate" from a genuine failure
		// by matching on it, and the two lead to different exit codes.
		if _, err := c.Compare(v, "1.0-1"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, …) err = %v, want one wrapping ErrInvalid", v, err)
		}
		if _, err := c.Compare("1.0-1", v); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(…, %q) err = %v, want one wrapping ErrInvalid", v, err)
		}
	}
}

// Shapes that look malformed and are not. Each is here because rejecting it
// would silently skip a real package.
func TestDebValidButUnusual(t *testing.T) {
	valid := []string{
		"1.0",       // no revision at all
		"0",         // the smallest legal upstream version
		"1:1.2:3-4", // a colon inside upstream IS legal once an epoch precedes it
		// The discriminator for the last-hyphen split. Under a FIRST-hyphen
		// split the revision would be "3-4", which contains a '-' and is
		// therefore illegal — so this string parses under dpkg's rule and is
		// rejected under the wrong one. Ordering cannot tell the two splits
		// apart here (both give the same answer on every pair we tried), but
		// validity can.
		"1.2-3-4",
		"1.0~~",                    // a doubled tilde
		"1.0+really1.1-1",          // the '+really' idiom for a downgraded upstream
		"2.4.4-2ubuntu17.4",        // an Ubuntu revision
		"1.2.3-4+deb11u1",          // a Debian point release
		"1:2.66-4+deb12u3+b1",      // epoch, point release and binNMU together
		"3.0.20-1~deb12u2",         // a tilde inside a revision
		"1.21.0+dfsg-1",            // the '+dfsg' repack idiom
		"7.74.0-1.3+deb11u10",      // a real fixed version from OSV
		"239-1",                    // systemd, plain
		"0.0~git20200101.abcdef-1", // a git snapshot
	}
	var c Deb
	for _, v := range valid {
		if _, err := c.Compare(v, v); err != nil {
			t.Errorf("Compare(%q, %q) err = %v, want nil — rejecting this skips a real package", v, v, err)
		}
	}
}

// Transitivity over a chain the specification itself publishes, checked over
// every pair rather than only neighbours. A comparer can be right about
// neighbours and wrong about transitivity, and InRange's event sort depends on
// the latter.
func TestDeb_PolicyChain(t *testing.T) {
	chain := []string{
		"1.0~~",
		"1.0~~a",
		"1.0~",
		"1.0",
		"1.0a",
		"1.0+",
		"1.0.1",
		"1.0.1-1",
		// 'b' (98) < 'd' (100): the binNMU sorts below the point release, which
		// is the opposite of what the names suggest.
		"1.0.1-1+b1",
		"1.0.1-1+deb11u1",
		"1.1",
		"1:0.1",
	}
	assertAscending(t, Deb{}, chain, "Debian Policy §5.6.12")
}
