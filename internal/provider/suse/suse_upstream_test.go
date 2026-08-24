//go:build upstreamvectors

// This file runs the provider against SUSE's live CSAF VEX feed.
//
// Run it with:
//
//	go test -tags upstreamvectors -timeout 15m ./internal/provider/suse/
//
// It is behind a build tag because it downloads a 445 MB archive and parses
// roughly 11 GB of decompressed JSON, which takes a few minutes. `go test
// ./...` never does that; this is a manual/CI-only check, mirroring
// redhat_upstream_test.go's identical reason for existing behind the same
// tag.
//
// What it protects that nothing else does: the D20 zero-records guard in
// Fetch fails a build whose key fold stops matching, and that runs on every
// real sync -- but it cannot see whether the SHAPE of what was parsed is
// still right, or whether SUSE's feed still spells things the way this
// package assumes (recommended vs. fixed, the purl shape, changes.csv's sort
// order).
package suse

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func TestAgainstTheLiveFeed(t *testing.T) {
	var progress strings.Builder
	p := New(Options{Progress: &progress})

	var (
		advisories, withFix, withoutFix int
		ecos                            = map[string]int{}
		sawFixedOpenSSH                 bool
		sawUnfixedOnLeap                bool
	)
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		advisories++
		for _, af := range a.Affected {
			ecos[af.Ecosystem]++
			for _, r := range af.Ranges {
				switch len(r.Events) {
				case 1:
					withoutFix++
					if af.Ecosystem == "openSUSE Leap:15.6" {
						sawUnfixedOnLeap = true
					}
				case 2:
					withFix++
					if a.ID == "SUSE-CVE-2024-3094" && af.Name == "xz" && r.Events[1].Fixed != "" {
						sawFixedOpenSSH = true
					}
				default:
					t.Errorf("%s/%s produced a range with %d events; a range is either "+
						"introduced-then-fixed or introduced alone", a.ID, af.Name, len(r.Events))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d advisories, %d ranges with a fix, %d without, as of %s",
		advisories, withFix, withoutFix, prov.DataAsOf.Format("2006-01-02"))
	t.Logf("%s", strings.TrimSpace(progress.String()))

	if !sawFixedOpenSSH {
		t.Error("CVE-2024-3094 (the xz backdoor) did not yield a fixed xz range")
	}
	if !sawUnfixedOnLeap {
		t.Error("no fix-less range landed on openSUSE Leap:15.6 at all; " +
			"affected-with-no-fix is the whole reason this provider exists")
	}

	for _, want := range []string{"SLES:15.SP6", "SLES:12.SP5", "openSUSE Leap:15.6"} {
		if ecos[want] == 0 {
			t.Errorf("no records for %s; a supported release with no advisories reports "+
				"every scan of it as clean", want)
		}
	}
	if os.Getenv("CI") != "" && advisories < 5000 {
		t.Errorf("only %d advisories; the archive held tens of thousands as of 2026-08-19", advisories)
	}
}
