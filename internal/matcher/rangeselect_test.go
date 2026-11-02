package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// advWithRanges is one affected entry carrying several ranges, in the order
// given -- the shape the Red Hat and SUSE CSAF providers write, one [0, fix)
// range per fixed build in lexical order, an unfixed [0,) range last.
func advWithRanges(id, eco, name string, ranges ...[]advisory.Event) advisory.Advisory {
	a := advisory.Advisory{ID: id, Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: eco, Name: name}}}
	for _, ev := range ranges {
		a.Affected[0].Ranges = append(a.Affected[0].Ranges,
			advisory.Range{Type: advisory.RangeEcosystem, Events: ev})
	}
	return a
}

func fixedRange(v string) []advisory.Event {
	return []advisory.Event{{Introduced: "0"}, {Fixed: v}}
}

// Audit P4, re-verified 2026-11-02: when several ranges of one entry hold
// the installed version, the finding named whichever came first in the
// file, so the fix it advised moved with the producer's order. Ranges are a
// union (OSV), so the package stays affected until it clears every one: the
// fix that does that is the highest fixed bound among the ranges that hit,
// whatever their order, and a bounded range is preferred over an open one
// (which no upgrade clears) wherever it sits.
func TestMatch_SeveralHittingRangesNameTheFixThatClearsThemAll(t *testing.T) {
	open := []advisory.Event{{Introduced: "0"}}
	for _, tc := range []struct {
		name   string
		ranges [][]advisory.Event
		want   string
	}{
		{"wide first", [][]advisory.Event{fixedRange("2.0.0"), fixedRange("1.5.0")}, "2.0.0"},
		{"narrow first", [][]advisory.Event{fixedRange("1.5.0"), fixedRange("2.0.0")}, "2.0.0"},
		{"open first", [][]advisory.Event{open, fixedRange("1.5.0")}, "1.5.0"},
		{"open last", [][]advisory.Event{fixedRange("1.5.0"), open}, "1.5.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fakeStore{byKey: map[string][]advisory.Advisory{
				"npm\x00rs-lib": {advWithRanges("GHSA-rs01-0000-0001", "npm", "rs-lib", tc.ranges...)},
			}}
			res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("rs-lib", "1.0.0", "npm")}})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 1 {
				t.Fatalf("Findings = %+v, want 1", res.Findings)
			}
			f := res.Findings[0]
			if f.Evidence.Fixed != tc.want {
				t.Errorf("Evidence.Fixed = %q, want %q (reason %q)", f.Evidence.Fixed, tc.want, f.Evidence.Reason)
			}
			if len(f.Ratings) == 0 || f.Ratings[0].Fixed != tc.want {
				t.Errorf("Ratings = %+v, want Ratings[0].Fixed %q", f.Ratings, tc.want)
			}
		})
	}
}

// A range whose bound cannot be read used to abort the whole entry, so a
// later range that holds the package turned a finding into a skip. Ranges
// are a union: an unreadable one cannot take away what a readable one says.
// With no range holding the package the unreadable one is still a skip.
func TestMatch_UnreadableRangeDoesNotHideALaterHit(t *testing.T) {
	bad := []advisory.Event{{Introduced: "0"}, {Fixed: "not a version!!"}}
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"npm\x00rs-hit":  {advWithRanges("GHSA-rs02-0000-0001", "npm", "rs-hit", bad, fixedRange("2.0.0"))},
		"npm\x00rs-miss": {advWithRanges("GHSA-rs02-0000-0002", "npm", "rs-miss", bad, fixedRange("0.5.0"))},
	}}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("rs-hit", "1.0.0", "npm"), pkg("rs-miss", "1.0.0", "npm"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Package.Name != "rs-hit" || res.Findings[0].Evidence.Fixed != "2.0.0" {
		t.Errorf("Findings = %+v, want rs-hit alone, fixed 2.0.0", res.Findings)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Package.Name != "rs-miss" || res.Skipped[0].Cause != SkipAdvisory {
		t.Errorf("Skipped = %+v, want rs-miss alone, cause advisory", res.Skipped)
	}
}

// Audit P4, re-verified 2026-11-02: a bound that parses on its own but does
// not order against the installed version, or a fixed "0" a comparer cannot
// read (sortEvents exempts "0" as the introduced sentinel whatever its
// role), reached the walk's error path, which always blamed the installed
// version: the skip said "this package's own version could not be read" and
// counted as target incompleteness, so --fail-on-incomplete=target failed
// over upstream data the user cannot fix. D88's comment already promised
// this case an advisory-data skip.
func TestMatch_ABoundThatDoesNotOrderIsTheAdvisorysFault(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Packagist\x00acme/devbound": {advWithRange("GHSA-rs03-0000-0001", "Packagist", "acme/devbound", "0", "dev-master", advisory.RangeEcosystem)},
		"npm\x00zero-fix":            {advWithRange("GHSA-rs03-0000-0002", "npm", "zero-fix", "0", "0", advisory.RangeSemver)},
		"npm\x00bad-own":             {advWithRange("GHSA-rs03-0000-0003", "npm", "bad-own", "0", "2.0.0", advisory.RangeSemver)},
	}}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("acme/devbound", "1.5.0", "Packagist"),
		pkg("zero-fix", "1.2.0", "npm"),
		pkg("bad-own", "not.a.version", "npm"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Skipped{}
	for _, sk := range res.Skipped {
		got[sk.Package.Name] = sk
	}
	for _, name := range []string{"acme/devbound", "zero-fix"} {
		sk, ok := got[name]
		if !ok || sk.Cause != SkipAdvisory || strings.Contains(sk.Reason, "own version") {
			t.Errorf("%s: skipped=%v cause %q reason %q, want an advisory skip that does not blame the package", name, ok, sk.Cause, sk.Reason)
		}
	}
	// The control: a version that really cannot be read is still the target's.
	if sk := got["bad-own"]; sk.Cause != SkipTarget {
		t.Errorf("bad-own: cause %q reason %q, want target", sk.Cause, sk.Reason)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none", res.Findings)
	}
}
