//go:build upstreamvectors

// This file runs the provider against Red Hat's live CSAF VEX feed.
//
// Run it with:
//
//	go test -tags upstreamvectors ./internal/provider/redhat/
//
// It is behind a build tag because it downloads a 262 MB archive and streams
// 17.1 GB through the parser, which takes about ninety seconds. `go test ./...`
// never does that; CI is the only place it happens.
//
// What it protects is not covered by anything else. The D20 coverage guard in
// Fetch fails a build whose CPE filter stops matching, and that runs on every
// real sync — but it cannot see whether the SHAPE of what was parsed is still
// right. A change that turned every known_affected entry into something with a
// version would keep the coverage set full, keep the record count plausible,
// and quietly delete the only thing this provider exists to carry.
package redhat

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
		// One CVE of each kind, checked by name. regreSSHion is the fix Red Hat
		// shipped for RHEL 9; CVE-2005-2541 is tar, which Red Hat has said for
		// twenty years is affected and will not be fixed.
		sawFixedOpenSSH bool
		sawUnfixedTar   bool
	)
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		advisories++
		for _, af := range a.Affected {
			ecos[af.Ecosystem]++
			for _, r := range af.Ranges {
				switch len(r.Events) {
				case 1:
					withoutFix++
					if a.ID == "CVE-2005-2541" && af.Name == "tar" {
						sawUnfixedTar = true
					}
				case 2:
					withFix++
					if a.ID == "CVE-2024-6387" && af.Name == "openssh" &&
						af.Ecosystem == "Red Hat:9" && r.Events[1].Fixed != "" {
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

	// Nothing may be dropped for a reason the parser cannot name. Measured on
	// the 2026-08-05 archive both of these are zero across all 67,261
	// documents, and a non-zero count means the feed's shape moved.
	if !strings.Contains(progress.String(), "0 unreadable products") ||
		!strings.Contains(progress.String(), "0 unreadable documents") {
		t.Errorf("the feed's shape has moved: %s", progress.String())
	}

	// The shape assertions. Both directions, because a provider that produced
	// only fixes would look healthy by every count above and would be exactly
	// the OSV export this one exists to replace.
	if !sawFixedOpenSSH {
		t.Error("CVE-2024-6387 (regreSSHion) did not yield a fixed openssh range on Red Hat:9")
	}
	if !sawUnfixedTar {
		t.Error("CVE-2005-2541 did not yield a FIX-LESS tar range; " +
			"affected-with-no-fix is the whole reason this provider exists")
	}
	if withoutFix < withFix {
		t.Errorf("%d ranges without a fix against %d with one; measured on 2026-08-05 the "+
			"first is roughly double the second", withoutFix, withFix)
	}

	// Coverage, which is what D20 stores and every RHEL scan depends on.
	for _, want := range []string{"Red Hat:8", "Red Hat:9", "Red Hat:10"} {
		if ecos[want] == 0 {
			t.Errorf("no records for %s; a supported release with no advisories reports "+
				"every scan of it as clean", want)
		}
	}
	if os.Getenv("CI") != "" && advisories < 20000 {
		t.Errorf("only %d advisories; the archive held 28,907 on 2026-08-05", advisories)
	}
}
