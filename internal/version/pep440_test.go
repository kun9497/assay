package version

import (
	"errors"
	"testing"
)

var pep440Tests = []struct {
	a, b string
	want int
}{
	// Epoch
	{"1.0", "1!1.0", -1},
	{"1!1.0", "1.0", 1},
	{"2!1.0", "1!2.0", 1},
	{"1!0.1", "9999999", 1},
	{"1!0", "0!99999", 1},
	{"0!1.0", "1.0", 0},
	{"01!1.0", "1!1.0", 0},
	{"1!1.0", "1!1.0.0", 0},
	{"1!1.0.dev1", "1.0", 1},

	// Release segment: length, trailing zeros, numeric compare
	{"1.0", "1.0.0", 0},
	{"1", "1.0.0.0", 0},
	{"1.0", "1.0.0.0.0.0.0.0.0.0", 0},
	{"1.0", "1.0.1", -1},
	{"1.0.0.1", "1.0.1", -1},
	{"1.0.0.0.0.0.1", "1.0.1", -1},
	{"1.0.1", "1.1", -1},
	{"1.10", "1.9", 1},
	{"1.0.15", "1.0.2", 1},
	{"10.0", "9.0", 1},
	{"2", "1.999999", 1},
	{"1.0.0.0.0.0.0.1", "1.0.0.0.0.0.0.2", -1},
	{"0", "0.0", 0},
	{"0", "0.0.1", -1},
	{"99999999999999999999999999.0", "100000000000000000000000000.0", -1},

	// Leading zeros
	{"1.01", "1.1", 0},
	{"01.0", "1.0", 0},
	{"1.0.00", "1", 0},
	{"1.0a01", "1.0a1", 0},
	{"1.0.post01", "1.0.post1", 0},
	{"1.0.dev01", "1.0.dev1", 0},
	{"1.0+001", "1.0+1", 0},           // numeric local segment IS normalized
	{"1.0+foo0100", "1.0+foo100", -1}, // alphanumeric local segment is NOT

	// v prefix, whitespace, case folding
	{"v1.0", "1.0", 0},
	{"V1.0", "1.0", 0},
	{"  1.0  ", "1.0", 0},
	{"\t1.0\n", "1.0", 0},
	{"1.0A1", "1.0a1", 0},
	{"1.0RC1", "1.0rc1", 0},
	{"1.0.POST1", "1.0.post1", 0},
	{"1.0.DEV1", "1.0.dev1", 0},
	{"1.0+ABC", "1.0+abc", 0},
	{"v1!1.0.post1.dev2+ABC.1", "1!1.0.post1.dev2+abc.1", 0},
	{"1!2.0.0a1.post2.dev3+ubuntu.1", "v1!2.0.0.alpha.1-post-2_dev3+UBUNTU-1", 0},

	// Pre-release spelling equivalences
	{"1.0alpha1", "1.0a1", 0},
	{"1.0beta2", "1.0b2", 0},
	{"1.0c1", "1.0rc1", 0},
	{"1.0pre1", "1.0rc1", 0},
	{"1.0preview1", "1.0rc1", 0},
	{"1.0.0rc1", "1.0.0c1", 0},
	{"1.0-alpha-1", "1.0a1", 0},
	{"1.0_beta_2", "1.0b2", 0},
	{"1.0.rc.1", "1.0rc1", 0},
	{"1.0.0-rc.1", "1.0.0rc1", 0}, // semver-shaped input is legal PEP 440
	{"1.0.0-beta.1", "1.0.0b1", 0},

	// Implicit pre-release number
	{"1.0a", "1.0a0", 0},
	{"1.0b", "1.0b0", 0},
	{"1.0rc", "1.0rc0", 0},
	{"1.0alpha", "1.0a0", 0},
	{"1.0a", "1.0a1", -1},

	// Pre-release ordering
	{"1.0a1", "1.0a2", -1},
	{"1.0a2", "1.0a10", -1},
	{"1.0a10", "1.0b1", -1},
	{"1.0b1", "1.0rc1", -1},
	{"1.0b2", "1.0c1", -1},
	{"1.0rc1", "1.0", -1},
	{"1.0a1", "0.9", 1},

	// Post-release spellings and implicit forms
	{"1.0.post1", "1.0-post1", 0},
	{"1.0.post1", "1.0post1", 0},
	{"1.0.post1", "1.0_post_1", 0},
	{"1.0.post1", "1.0-1", 0}, // implicit post release
	{"1-0", "1.post0", 0},
	{"1.0.rev1", "1.0.post1", 0},
	{"1.0.r1", "1.0.post1", 0},
	{"1.0.post", "1.0.post0", 0},
	{"1.0-r", "1.0.post0", 0},
	{"1.0-0", "1.0.post0", 0},

	// Post-release ordering
	{"1.0", "1.0.post0", -1}, // .post0 is GREATER than no post at all
	{"1.0.post1", "1.0.post2", -1},
	{"1.0.post2", "1.0.post10", -1},
	{"1.0.post1", "1.0.1", -1}, // post never escapes its release
	{"1.0.post1", "1.1", -1},
	{"1.0.post1", "1.0rc1", 1},

	// Dev releases
	{"1.0.dev1", "1.0", -1},
	{"1.0.dev1", "1.0a1", -1}, // dev-only sorts before ALL pre-releases
	{"1.0.dev0", "1.0a0.dev0", -1},
	{"1.0a1.dev1", "1.0.dev1", 1},
	{"1.0.dev", "1.0.dev0", 0},
	{"1.0dev1", "1.0.dev1", 0},
	{"1.0-dev1", "1.0.dev1", 0},
	{"1.0_dev_1", "1.0.dev1", 0},
	{"1.0.0-dev-1", "1.0.0.dev1", 0},
	{"1.0.dev1", "1.0.dev2", -1},
	{"1.0.dev2", "1.0.dev10", -1},
	{"1.0a1.dev1", "1.0a1", -1},
	{"1.0a1.dev1", "1.0a1.dev2", -1},
	{"1.0.dev1", "0.9.9", 1},
	{"1.dev0", "1.0.dev456", -1},
	{"1.0.dev0", "1.0.0.dev0", 0},

	// Dev release OF a post release: sorts AFTER the base version
	{"1.0.post1.dev1", "1.0", 1}, // counterintuitive, most-missed rule
	{"1.0.post1.dev1", "1.0.post1", -1},
	{"1.0.post1.dev1", "1.0.dev1", 1},
	{"1.0.post0.dev0", "1.0", 1},
	{"1.0.dev0", "1.0.post0.dev0", -1},
	{"1.0.post1.dev0", "1.0.post0", 1},
	{"2.0", "2.0.post0.dev0", -1},

	// Pre + post + dev combinations
	{"1.0a1.post1", "1.0a1", 1},
	{"1.0a1.post1", "1.0b1", -1},
	{"1.0a1.post2", "1.0a2", -1}, // pre number outranks post
	{"1.0a1.post1.dev1", "1.0a1.post1", -1},
	{"1.0a1.post1.dev1", "1.0a1", 1},
	{"1.0a1.post1", "1.0a1.post1.dev999", 1},
	{"1.0b2.post345.dev456", "1.0b2.post345", -1},
	{"1.0rc1.dev1", "1.0b1", 1},
	{"1.2.3.4rc1.post2.dev3", "1.2.3.4rc1.post2", -1},

	// Local versions
	{"1.0", "1.0+abc", -1},
	{"1.0", "1.0+0", -1},
	{"1.0.0+build.1", "1.0.0", 1},
	{"1!1.0+local", "1!1.0", 1},
	{"1.0.post1+local", "1.0.post1", 1},
	{"1.0+abc.5", "1.0+abc.7", -1},
	{"1.0+2", "1.0+10", -1},
	{"1.0+abc", "1.0+abd", -1},
	{"1.0+abc.7", "1.0+5", -1}, // numeric segment > alphanumeric segment
	{"1.0+5", "1.0+abc", 1},
	{"1.0+0", "1.0+a", 1},
	{"1.0+1.a", "1.0+1.1", -1},
	{"1.0+foo", "1.0+foo.0", -1}, // shorter prefix first; NO trailing-zero trim
	{"1.0+1", "1.0+1.0", -1},
	{"1.0+abc", "1.0+abc.0", -1},
	{"1.0+abc.1", "1.0+abc.1.0", -1},
	{"1.0+a.1", "1.0+a.1.b", -1},
	{"1.0+ubuntu-1", "1.0+ubuntu.1", 0},
	{"1.0+ubuntu_1", "1.0+ubuntu.1", 0},
	{"1.0+abc", "1.0+ABC", 0},
	{"1.0.0+abc", "1.0+abc", 0},
	{"1.0+deadbeef", "1.0.1", -1},
	{"1.0+local", "1.0.post1", -1},
	{"1.0+99999999999999999999", "1.0+100000000000000000000", -1},

	// "0" is NOT the minimum PEP 440 version — same trap as semver
	{"0", "1.0", -1},
	{"0", "0.dev0", 1},
	{"0", "0a1", 1},
	{"0", "0.0.0rc1", 1},

	// Reflexivity
	{"1.0", "1.0", 0},
	{"1!2.0.0a1.post2.dev3+ubuntu.1", "1!2.0.0a1.post2.dev3+ubuntu.1", 0},

	// The canonical ordering example from PEP 440, as adjacent pairs
	{"1.dev0", "1.0.dev456", -1},
	{"1.0.dev456", "1.0a1", -1},
	{"1.0a1", "1.0a2.dev456", -1},
	{"1.0a2.dev456", "1.0a12.dev456", -1},
	{"1.0a12.dev456", "1.0a12", -1},
	{"1.0a12", "1.0b1.dev456", -1},
	{"1.0b1.dev456", "1.0b2", -1},
	{"1.0b2", "1.0b2.post345.dev456", -1},
	{"1.0b2.post345.dev456", "1.0b2.post345", -1},
	{"1.0b2.post345", "1.0rc1.dev456", -1},
	{"1.0rc1.dev456", "1.0rc1", -1},
	{"1.0rc1", "1.0", -1},
	{"1.0", "1.0+abc.5", -1},
	{"1.0+abc.5", "1.0+abc.7", -1},
	{"1.0+abc.7", "1.0+5", -1},
	{"1.0+5", "1.0.post456.dev34", -1},
	{"1.0.post456.dev34", "1.0.post456", -1},
	{"1.0.post456", "1.0.15", -1},
	{"1.0.15", "1.1.dev1", -1},
}

func TestPEP440Compare(t *testing.T) {
	var c PEP440
	for _, tc := range pep440Tests {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		rev, err := c.Compare(tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.b, tc.a, err)
			continue
		}
		if rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, rev, -tc.want)
		}
	}
}

func TestPEP440Invalid(t *testing.T) {
	invalid := []string{
		// Structurally malformed
		"", "   ", "1.", "1.0.0.", ".1.0", "1..0", "-1.0", "+1.0",
		"1!", "!1.0", "1!2!3.0", "vv1.0", "x1.0", "latest", "None",
		"*", "1.0.*", "1.0 beta", "1 . 0",
		// Segment misuse
		"1.0_1", "1.0.0_1", // implicit post release requires "-" specifically
		"1.0.0-1.2", "1.0.dev1.post2", "1.0.post1.pre2",
		"3.0.0.rc1.dev1.post2", "1.0a1b2", "1.0.0rc1.rc2",
		"1.0.post1.post2", "1.0.0.dev1.dev2",
		"1.0.0-alpha.beta", "1.0.0a-b", "1.0a.1.2", "1.0K", "2011k",
		// Local-version malformed
		"1.0+", "1.0+.", "1.0+abc.", "1.0.0+abc-", "1.0+abc..1",
		"1.0.0++abc", "1.0+abc+def", "1.0.0+local!", "1.0.0+lo cal",
		// Non-ASCII: Go's (?i) would fold these into ASCII if not rejected first
		"１.０", "٣.٤", "1.0+\u212A",
		// Legacy PyPI shapes that cannot be ordered at all
		"1.0dev-r1234", "1.0.0-SNAPSHOT", "linux-2.6",
		// OSV sentinel, as in semver
		"0!",
	}
	for _, in := range invalid {
		if _, err := (PEP440{}).Compare(in, "1.0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, …) err = %v, want ErrInvalid", in, err)
		}
	}
}

func TestPEP440LegacyLookingButValid(t *testing.T) {
	// These look legacy but do parse, and rejecting them would drop real
	// advisories on the floor.
	valid := map[string]string{
		"0.9.9a-1":   "0.9.9a1",
		"1.0.0-rc.1": "1.0.0rc1",
		"2.0-r":      "2.0.post0",
		"1-0":        "1.post0",
	}
	for in, equiv := range valid {
		got, err := (PEP440{}).Compare(in, equiv)
		if err != nil {
			t.Errorf("Compare(%q, %q) err = %v, want nil", in, equiv, err)
			continue
		}
		if got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", in, equiv, got)
		}
	}
}

func TestPEP440RegisteredForPyPI(t *testing.T) {
	c, ok := For("PyPI")
	if !ok {
		t.Fatal("For(PyPI) not registered")
	}
	if _, ok := c.(PEP440); !ok {
		t.Errorf("For(PyPI) = %T, want PEP440", c)
	}
}
