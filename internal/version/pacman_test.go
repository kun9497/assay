package version

import (
	"errors"
	"testing"
)

// TestPacman_Vercmp8Chain replays vercmp(8)'s own documented ordering
// chains, every adjacent pair in both directions plus self-equality — the
// same replay discipline the apk comparer applies to apk-tools' vector
// file. The alphanumeric chain is the one that separates this comparer
// from RPM{}: every element left of `1.0` is a trailing-alpha spelling
// that rpm would sort ABOVE `1.0` instead of below it.
func TestPacman_Vercmp8Chain(t *testing.T) {
	chains := [][]string{
		{"1.0a", "1.0b", "1.0beta", "1.0p", "1.0pre", "1.0rc", "1.0", "1.0.a", "1.0.1"},
		{"1", "1.1", "1.1.1", "1.2", "2.0", "3.0.0"},
	}
	c := Pacman{}
	for _, chain := range chains {
		for i, low := range chain {
			if got, err := c.Compare(low, low); err != nil || got != 0 {
				t.Errorf("Compare(%q, %q) = %d, %v; want 0, nil", low, low, got, err)
			}
			for _, high := range chain[i+1:] {
				if got, err := c.Compare(low, high); err != nil || got >= 0 {
					t.Errorf("Compare(%q, %q) = %d, %v; want < 0", low, high, got, err)
				}
				if got, err := c.Compare(high, low); err != nil || got <= 0 {
					t.Errorf("Compare(%q, %q) = %d, %v; want > 0", high, low, got, err)
				}
			}
		}
	}
}

func TestPacman_Compare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Epoch: leading digits before ':' only; absent is zero; an empty
		// epoch (":1.0") is zero, not an error — parseEVR's own rules.
		{"1:0.5", "1.0", 1},
		{"0:1.0", "1.0", 0},
		{":1.0", "1.0", 0},
		{"2:1.0", "1:9.9", 1},
		// "1a:2.3" has no epoch — the digit scan stops at 'a', so the whole
		// string (colon and all, an ordinary separator from here on) is the
		// version and the side compares as epoch 0: OLDER than any real
		// epoch, regardless of how its version half would have ranked.
		{"1a:2.3", "1:2.3", -1},

		// pkgrel: compared only when BOTH sides carry one. `1.0-2` equals a
		// bare `1.0` — that is alpm_pkg_vercmp's own rel1 && rel2 guard, and
		// it is how the Arch tracker spells "any packaging of this pkgver".
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0", 0},
		{"1.0", "1.0-10", 0},
		{"1.0-1.1", "1.0-1", 1},
		// A trailing hyphen is a PRESENT, empty release: both sides have
		// one, so the legs are compared and empty loses to non-empty.
		{"1.0-", "1.0-1", -1},
		{"1.0-", "1.0", 0},

		// The release starts at the LAST hyphen.
		{"1.2-3-4", "1.2-3-5", -1},

		// Separator-length clause (libalpm only, rpm has no equivalent):
		// the side that skipped more separator bytes is newer; equal-length
		// runs of different separators are equal.
		{"1..0", "1.0", 1},
		{"1.0", "1__0", -1},
		{"1_0", "1.0", 0},

		// Numeric beats alpha on a type mismatch; leading zeros strip.
		{"1.a", "1.1", -1},
		{"1.001", "1.1", 0},
		{"1.01a", "1.1a", 0},

		// Tilde and caret are ordinary separators (no rpm special rules).
		// The tilde direction FLIPS against RPM{}: rpm_test.go holds
		// "1.0~rc1" < "1.0", this comparer orders it the other way because
		// the tail's first byte is a separator, not a letter, so the
		// remaining-alpha rule does not fire and the longer side wins.
		{"1.0~1", "1.0", 1},
		{"1.0~rc1", "1.0", 1},
		{"1.0^git1", "1.0", 1},

		// THE measured RPM{} divergence that forced this type (D97): the
		// live feed's tensorflow pair. rpm orders the rc build ABOVE the
		// bare release — a silent false negative against the real fix.
		{"2.4.0rc4-2", "2.4.0-1", -1},

		// Date-shaped and long numeric segments: length-compare, never
		// integer conversion, so nothing overflows.
		{"20250901-1", "20250831-1", 1},
		{"999999999999999999999999", "1000000000000000000000000", -1},

		// Real Arch spellings from the live feed.
		{"1:1.26.1-1", "1:1.26.0-1", 1},
		{"6.12.41.arch1-1", "6.12.40.arch1-1", 1},
	}
	c := Pacman{}
	for _, tc := range cases {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q): %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		back, err := c.Compare(tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%q, %q): %v", tc.b, tc.a, err)
			continue
		}
		if back != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, back, -tc.want)
		}
	}
}

// TestPacman_DivergesFromRPMWhereMeasured pins that Pacman{} and RPM{}
// genuinely disagree on the rows the D97 research measured — if a future
// refactor quietly aliases one onto the other, at least one side of each
// pair goes red. Both comparers are called on the SAME inputs and the test
// asserts the signs differ, so it cannot pass by both being wrong the same
// way.
func TestPacman_DivergesFromRPMWhereMeasured(t *testing.T) {
	rows := []struct{ a, b string }{
		{"2.4.0rc4", "2.4.0"}, // pacman: rc older; rpm: rc newer
		{"1.0~1", "1.0"},      // pacman: newer (separator); rpm: tilde sorts below
	}
	for _, r := range rows {
		pg, err := Pacman{}.Compare(r.a, r.b)
		if err != nil {
			t.Fatalf("Pacman(%q, %q): %v", r.a, r.b, err)
		}
		rg, err := RPM{}.Compare(r.a, r.b)
		if err != nil {
			t.Fatalf("RPM(%q, %q): %v", r.a, r.b, err)
		}
		if pg == rg {
			t.Errorf("Pacman and RPM agree on (%q, %q) = %d — the measured divergence "+
				"this type exists for has been lost", r.a, r.b, pg)
		}
	}
}

func TestPacman_Refusals(t *testing.T) {
	c := Pacman{}
	for _, bad := range []string{"", "1.0 2", "1.0\t2", "1.0\n"} {
		if _, err := c.Compare(bad, "1.0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, ...) error = %v, want ErrInvalid", bad, err)
		}
		if _, err := c.Compare("1.0", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(..., %q) error = %v, want ErrInvalid", bad, err)
		}
	}
}
