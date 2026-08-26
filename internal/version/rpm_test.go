package version

import (
	"errors"
	"testing"
)

// Segment ordering, which is rpmvercmp on its own — no epoch, no release.
// These are the rows the upstream oracle in rpm_upstream_test.go replays
// verbatim, so none of them may contain a colon or a hyphen: whether rpm's Lua
// `vercmp` parses a full EVR or only a version differs between releases, and
// restricting the input to strings where the two readings coincide is what
// makes the oracle unambiguous.
//
// Every expectation was derived from rpm's own rpmio/rpmvercmp.cc rather than
// recalled. That distinction earned its place: three rows here contradict what
// the Debian comparer next door would say, and one contradicted what I first
// wrote down.
var rpmSegmentTests = []struct {
	a, b string
	want int
	why  string
}{
	// Plain numeric and alphabetic runs.
	{"1.0", "1.0", 0, "identical"},
	{"1.0", "2.0", -1, "the first differing segment decides"},
	{"2.0", "2.0.1", -1, "a runs out while b has a segment left"},
	{"2.0.1a", "2.0.1", 1, "the same rule the other way round"},
	{"5.5p1", "5.5p2", -1, "an alphabetic segment splits the numbers around it"},
	{"5.5p1", "5.5p10", -1, "1 < 10 numerically; a lexical compare says the opposite"},
	{"10b2", "10a1", 1, "within the alphabetic class plain byte order holds"},
	{"1.0aa", "1.0a", 1, "a longer alphabetic run wins on byte order, not on length"},
	{"4.999.9", "5.0", -1, "4 < 5 decides before anything else is read"},
	{"20101121", "20101122", -1, "a date-stamped version is just a long digit run"},

	// Leading zeros are not part of the number.
	{"10.0001", "10.1", 0, "zeros are stripped from both runs, so these are one version"},
	{"10.0001", "10.0039", -1, "after stripping, 1 < 39 by length"},
	{"1.0", "1.00", 0, "the same rule on a segment that strips to nothing"},

	// SEPARATORS ARE ALL THE SAME, which Debian does not say. Any byte that is
	// not alphanumeric, `~` or `^` is skipped, so the four spellings below are
	// one version. Debian ranks '.' against '_' against '+' instead, and a
	// comparer that carried that rule here would order things rpm calls equal.
	{"1.0.2", "1_0_2", 0, "'.' and '_' are both separators and neither is compared"},
	{"1.0.2", "1..0...2", 0, "runs of separators collapse"},
	{"1.0.2", "1+0+2", 0, "'+' too, which matters for module release tags"},
	{"1.0", "1.0.", 0, "a trailing separator is not a segment"},

	// A NUMERIC segment always outranks an ALPHABETIC one. Debian says the
	// opposite — its letters rank below its punctuation and never meet a digit
	// — so this is the single most transplantable-looking rule in the file and
	// the one that must not be transplanted.
	{"1.1", "1.a", 1, "a numeric segment is newer than an alphabetic one"},
	{"xyz.4", "8", -1, "the whole first segment is alphabetic, so it loses to a number"},
	{"10xyz", "10.1xyz", -1, "'1xyz' begins with a digit where 'xyz' begins with a letter"},
	{"1b.fc17", "1.fc17", -1, "'b' against 'fc': byte order inside the alphabetic class"},
	{"1g.fc17", "1.fc17", 1, "'g' against 'fc': the same comparison landing the other way"},

	// The tilde: below everything, including the end of the string. The one
	// rule shared with Debian.
	{"1.0~rc1", "1.0", -1, "a pre-release sorts under its own base version"},
	{"1.0~rc1", "1.0~rc2", -1, "and orders normally against another pre-release"},
	{"1.0~rc1~git123", "1.0~rc1", -1, "a snapshot of a pre-release sorts under it"},
	{"1.0~~", "1.0~", -1, "end-of-string still outranks a tilde"},

	// The caret: the tilde's mirror, and Debian has NOTHING like it. Above the
	// end of the string, below any alphanumeric.
	{"1.0^", "1.0", 1, "a caret sorts ABOVE the end of the string"},
	{"1.0^git1", "1.0", 1, "which is how a post-release snapshot is spelled"},
	{"1.0^git1", "1.0^git2", -1, "two snapshots order normally"},
	{"1.0^git1", "1.01", -1, "and both sort below the next version"},
	{"1.0^20160102", "1.0^20160101^git1", 1, "a later date wins before the second caret is read"},
	{"1.0~rc1^git1", "1.0~rc1", 1, "caret and tilde compose: a snapshot OF a pre-release"},
	{"1.0^git1~pre", "1.0^git1", -1, "and the other way round"},
	{"1.0^a", "1.0^1", -1, "past the caret the numeric-beats-alphabetic rule still holds"},
}

func TestRPM_SegmentOrdering(t *testing.T) {
	var c RPM
	for _, tc := range rpmSegmentTests {
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

// Epoch and release: the parts rpmvercmp never sees, and the parts real
// advisory data disagrees about.
func TestRPM_EVR(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		why  string
	}{
		// D46's highest-risk row, from both directions. AlmaLinux omits the
		// epoch when it is zero (52,290 of 67,076 fixed events) while Red Hat
		// and Rocky always write it, and on the installed side 145 of 158 real
		// packages in almalinux:9 carry no EPOCH tag at all — so this exact
		// comparison happens on every Alma scan.
		{"0:1.0-1", "1.0-1", 0, "an omitted epoch is zero, not 'unset'"},
		{"7.76.1-23.el9_2.4", "0:7.76.1-23.el9_2.4", 0, "the real Alma-against-Red-Hat spelling"},
		{":1.0-1", "0:1.0-1", 0, "rpm reads an EMPTY epoch as zero rather than as an error"},
		{"01:1.0-1", "1:1.0-1", 0, "the epoch is an integer, so leading zeros do not matter"},

		// The epoch decides before anything else is read.
		{"1:1.0-1", "2.0-1", 1, "epoch 1 beats epoch 0 despite 1.0 < 2.0"},
		{"2:2.5-1", "1:7.5-1", 1, "and it is compared numerically, not lexically"},
		{"1:1.0-1", "10:1.0-1", -1, "2 < 10 as integers; as strings it would be the reverse"},

		// The release is a separate comparison, not a suffix on the version.
		{"1.0-1", "1.0-2", -1, "the release decides when the version ties"},
		{"1.0-1", "1.0", 1, "a version WITH a release outranks one without"},
		{"1.0-010", "1.0-10", 0, "leading zeros are stripped inside the release too"},
		// The discriminator for comparing the two parts SEPARATELY. Appending
		// the release to the version and comparing one string gives 1.0.2
		// against 1.0.2, which is 0 — the wrong answer, and one that would
		// call a vulnerable package fixed.
		{"1.0-2", "1.0.2-1", -1, "version 1.0 < 1.0.2 decides before either release is read"},
		// The discriminator for splitting on the LAST hyphen. Under a
		// first-hyphen split the left side becomes version "1.2" with release
		// "3-4" and the pair compares -1; under rpm's rule the interior hyphen
		// is just another separator inside the version and the two are equal.
		{"1.2-3-4", "1.2.3-4", 0, "the release starts at the LAST hyphen, so '1.2-3' is one version"},

		// Real Red Hat EVRs. Every one of these is a comparison a RHEL scan
		// performs, and the last four are the measurement that showed the
		// recorded backport objection was wrong: on a real ubi9 image each
		// installed package outranks the highest advisory fixed version.
		{"0:7.76.1-14.el9_0.9", "0:7.76.1-26.el9_3.2", -1, "curl across two RHEL 9 minors"},
		{"0:8.7p1-38.el9_4.1", "0:8.7p1-38.el9_4.2", -1, "regreSSHion's fix and its successor"},
		{"1:3.5.5-6.el9_8", "1:3.5.5-4.el9_8", 1, "real ubi9 openssl-libs against its advisory"},
		{"0:2.34-275.el9_8", "0:2.34-274.el9_8", 1, "real ubi9 glibc"},
		{"0:252-67.el9_8.4", "0:252-67.el9_8.2", 1, "real ubi9 systemd-libs"},
		{"0:2.9.13-14.el9_8.2", "0:2.9.13-6.el9_5.2", 1, "real ubi9 libxml2: 14 > 6 numerically"},

		// The .ael7b_1 build, which is a real Red Hat release string and the
		// one that shows the alphabetic run is taken whole.
		{"0:208-20.ael7b_1.9", "0:208-20.el7_1.9", -1, "'ael' against 'el' in byte order"},

		// Module builds. The two spellings compare EQUAL because '+' and '_'
		// are both separators — which is why the hazard recorded against
		// AlmaLinux is cross-distro MATCHING and not ordering.
		{"0:1.0-1.module+el8.5.0+119+9a9ec082", "0:1.0-1.module_el8.5.0+119+9a9ec082", 0,
			"Red Hat's 'module+el' and Alma's 'module_el' are one string to rpm"},
		{"1:20.20.2-2.module+el9.6.0+24220+c44c288d", "1:20.20.2-3.module+el9.6.0+24220+c44c288d", -1,
			"within one stream the build number still orders"},
	} {
		var c RPM
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q): %v (%s)", tc.a, tc.b, err, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d — %s", tc.a, tc.b, got, tc.want, tc.why)
		}
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

// rpm itself compares almost anything, treating whatever it does not recognize
// as a separator. This rejects the shapes that are not versions at all, for
// D9's reason: an unorderable input must surface as ErrInvalid so the package
// is reported as skipped, and a loud skip beats an ordering neither tool can
// vouch for.
func TestRPMInvalid(t *testing.T) {
	bad := []string{
		"",                           // empty
		"1.0-",                       // trailing hyphen: an empty release
		"-1",                         // the last-hyphen split leaves an empty version
		"1:",                         // nothing after the epoch colon
		"1.2 3-4",                    // interior whitespace
		"1.0\t2",                     // a tab, reached before any trim could help
		"99999999999999999999:1.0-1", // an epoch no integer can hold
	}
	var c RPM
	for _, v := range bad {
		// The contract is an error WRAPPING ErrInvalid, not merely a non-nil
		// one: callers distinguish "cannot evaluate" from a genuine failure by
		// matching on it, and the two lead to different exit codes.
		if _, err := c.Compare(v, "1.0-1"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, …) err = %v, want one wrapping ErrInvalid", v, err)
		}
		if _, err := c.Compare("1.0-1", v); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(…, %q) err = %v, want one wrapping ErrInvalid", v, err)
		}
	}
}

// Shapes that look malformed and are not. Each is here because rejecting it
// would silently skip a real package or a real advisory bound.
func TestRPMValidButUnusual(t *testing.T) {
	valid := []string{
		"0",   // OSV's "sorts before everything" sentinel, which reaches here as a bound
		"1.0", // no release at all
		// A colon that is NOT an epoch separator. rpm finds the epoch by
		// scanning DIGITS from the start, so this parses as a version
		// containing a colon — where dpkg would call the same string
		// malformed. The two schemes genuinely disagree (D9).
		"1a:2.3",
		":1.0",               // an empty epoch, which rpm reads as zero
		"1.2-3-4",            // the last-hyphen split: version "1.2-3", release "4"
		"1.0^git1",           // a post-release snapshot
		"1.0~rc1",            // a pre-release
		"0:8.7p1-38.el9_4.1", // a real RHEL 9 EVR
		"1:20.20.2-2.module+el9.6.0+24220+c44c288d", // a real module build
		"0:2.6.9-55.EL",   // RHEL 4's uppercase dist tag
		"0:1.0-1.el9_4.1", // an EUS-style release
	}
	var c RPM
	for _, v := range valid {
		if _, err := c.Compare(v, v); err != nil {
			t.Errorf("Compare(%q, %q) err = %v, want nil — rejecting this skips a real package", v, v, err)
		}
	}
}

// Transitivity over the chain the two separators define, checked over every
// pair rather than only neighbours. A comparer can be right about neighbours
// and wrong about transitivity, and InRange's event sort depends on the latter.
//
// The middle of this chain is where rpm and dpkg part company: `^` sits ABOVE
// the bare version and below any alphanumeric, and there is no Debian version
// string that lands in that gap at all.
func TestRPM_TildeCaretChain(t *testing.T) {
	assertAscending(t, RPM{}, []string{
		"1.0~~",
		"1.0~~a",
		"1.0~",
		"1.0~a",
		"1.0",
		"1.0^",
		"1.0^a",
		"1.0^1",
		"1.0a",
		// '.' is a separator, so this is the segments 1, 0, 1 — which sorts
		// below "1.01" because that one's second segment is the number 1
		// where this one's is 0.
		"1.0.1",
		"1.01",
		"1.2",
	}, "rpm rpmio/rpmvercmp.cc")
}

// The comparer is now reachable, and only under a release-qualified key.
//
// It was written one slice before it could be used: D43 shipped the rpmdb
// reader with no provider, so registering it then would have let an empty
// lookup report clean -- the mistake TestNoUnbackedDistroComparer exists to
// catch. The Red Hat CSAF VEX provider (D47-D49) is what moved that line, and
// this test is the other half of the same guard.
func TestRPM_Routing(t *testing.T) {
	for _, eco := range []string{
		"Red Hat:7", "Red Hat:8", "Red Hat:9", "Red Hat:10",
		// Rocky left this list under D71: its own OSV archive is
		// release-qualified the same way Red Hat's CSAF key is, and
		// rpmvercmp does not care which distro built the package.
		"Rocky Linux:8", "Rocky Linux:9", "Rocky Linux:10",
		// AlmaLinux left this list under D72, for the same reason.
		"AlmaLinux:8", "AlmaLinux:9", "AlmaLinux:10",
		// Oracle Linux left this list under D74, for the same reason: its
		// own OVAL archive is release-qualified the same way, and an
		// Oracle rebuild's own release suffixes (elNuek, .ksplice1.) are
		// still ordinary rpmvercmp separators.
		"Oracle Linux:8", "Oracle Linux:9", "Oracle Linux:10",
		// Fedora left this list under D75, for the same reason: Bodhi's
		// updates feed is release-qualified the same way ("Fedora:44"), and
		// rpmvercmp does not care which distro built the package.
		"Fedora:43", "Fedora:44",
		// Azure Linux left this list under D94, for the same reason: its own
		// OSV archive is release-qualified the same way ("Azure Linux:2",
		// "Azure Linux:3"), and rpmvercmp does not care which distro built
		// the package.
		"Azure Linux:2", "Azure Linux:3",
	} {
		c, ok := For(eco)
		if !ok {
			t.Errorf("For(%q) does not resolve; every RHEL package would be reported "+
				"as having no comparer", eco)
			continue
		}
		if _, isRPM := c.(RPM); !isRPM {
			t.Errorf("For(%q) = %T, want RPM", eco, c)
		}
	}
	// The bare family is NOT a key this project builds (D6), and resolving it
	// would make a bug that drops the release look like it worked -- every
	// lookup landing in an empty bucket and reporting clean.
	if _, ok := For("Red Hat"); ok {
		t.Error(`For("Red Hat") resolves; the provider only ever writes "Red Hat:<major>"`)
	}
	if _, ok := For("Rocky Linux"); ok {
		t.Error(`For("Rocky Linux") resolves; the provider only ever writes "Rocky Linux:<major>"`)
	}
	if _, ok := For("AlmaLinux"); ok {
		t.Error(`For("AlmaLinux") resolves; the provider only ever writes "AlmaLinux:<major>"`)
	}
	if _, ok := For("Oracle Linux"); ok {
		t.Error(`For("Oracle Linux") resolves; the provider only ever writes "Oracle Linux:<major>"`)
	}
	if _, ok := For("Fedora"); ok {
		t.Error(`For("Fedora") resolves; the provider only ever writes "Fedora:<VERSION_ID>"`)
	}
	if _, ok := For("Azure Linux"); ok {
		t.Error(`For("Azure Linux") resolves; the provider only ever writes "Azure Linux:<major>"`)
	}
	// And the rest still do not: Red Hat's errata describe Red Hat's own
	// builds (D50), Rocky's own feed is ingested only under "Rocky Linux:N"
	// (D71), AlmaLinux's only under "AlmaLinux:N" (D72), and Fedora's own
	// feed only under "Fedora:N" (D75) -- none of them populate CentOS's
	// key. Its packages are still catalogued and reported as not evaluated.
	for _, eco := range []string{"CentOS:9"} {
		if _, ok := For(eco); ok {
			t.Errorf("For(%q) resolves, but nothing populates that ecosystem", eco)
		}
	}
}
