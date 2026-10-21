package suse

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestD131_AgainstAnExtractedArchive converts every document of an extracted
// SUSE CSAF VEX archive and checks D131's invariants on the whole of it: no
// entry on a folded key is left under a NEVR-shaped name, every split build
// stored a fixed version, and no split build's range reached a Leap key. The
// counts it logs are the "after" column of D131's measurement; they are
// logged, not asserted, because they move with the archive.
//
// Opt-in: set ASSAY_SUSE_ARCHIVE_DIR to the directory the archive was
// extracted into (the csaf-vex/ root holding the year directories). Skipped
// otherwise -- it reads ~70k documents.
func TestD131_AgainstAnExtractedArchive(t *testing.T) {
	root := os.Getenv("ASSAY_SUSE_ARCHIVE_DIR")
	if root == "" {
		t.Skip("ASSAY_SUSE_ARCHIVE_DIR not set")
	}
	nevrTail := regexp.MustCompile(`-[0-9][^-]*-[^-]*\.[^-]*$`)

	var st stats
	var docs, splitEntries, cocoFixed, nevrNamed, leapSplit int
	splitNames := map[string]int{}
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var d document
		if err := json.Unmarshal(b, &d); err != nil {
			return nil // the provider counts these as SkippedBadDoc; not this test's subject
		}
		docs++
		before := st.RecommendedNamedByNEVRSplit
		adv, ok := convert(&d, &st)
		if !ok {
			return nil
		}
		split := st.RecommendedNamedByNEVRSplit - before
		for _, a := range adv.Affected {
			onFolded := strings.HasPrefix(a.Ecosystem, "SLES:") || strings.HasPrefix(a.Ecosystem, "openSUSE Leap:")
			if onFolded && nevrTail.MatchString(a.Name) {
				nevrNamed++
				if nevrNamed <= 5 {
					t.Logf("NEVR-shaped name left: %s %s/%s", d.Document.Tracking.ID, a.Ecosystem, a.Name)
				}
			}
			for _, r := range a.Ranges {
				for _, ev := range r.Events {
					if ev.Fixed == "" {
						continue
					}
					if strings.Contains(ev.Fixed, "coco") {
						if a.Ecosystem == "SLES:15.SP6" {
							cocoFixed++
						} else {
							leapSplit++
							if leapSplit <= 5 {
								t.Logf("split build's range on a Leap key: %s %s/%s fixed %s", d.Document.Tracking.ID, a.Ecosystem, a.Name, ev.Fixed)
							}
						}
					}
				}
			}
		}
		if split > 0 {
			splitEntries += split
			for _, a := range adv.Affected {
				if a.Ecosystem == "SLES:15.SP6" {
					for _, r := range a.Ranges {
						for _, ev := range r.Events {
							if strings.Contains(ev.Fixed, "coco") {
								splitNames[a.Name]++
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("documents %d; RecommendedNamedByNEVRSplit %d; RecommendedEmptyVersionKept %d; "+
		"SLES:15.SP6 fixed events from split builds %d; SkippedLeapMirrorSplitBuild %d; MirroredToLeap %d; "+
		"Unfixable %d (unstated %d); distinct split package names %d",
		docs, st.RecommendedNamedByNEVRSplit, st.RecommendedEmptyVersionKept, cocoFixed,
		st.SkippedLeapMirrorSplitBuild, st.MirroredToLeap, st.Unfixable, st.UnfixableUnstated, len(splitNames))
	for _, n := range []string{"kernel-coco", "qemu", "ovmf"} {
		t.Logf("  %s: %d split fixed events", n, splitNames[n])
	}
	if nevrNamed != 0 {
		t.Errorf("%d entries on folded keys still carry a NEVR-shaped name", nevrNamed)
	}
	if leapSplit != 0 {
		t.Errorf("%d split-build ranges reached a Leap key", leapSplit)
	}
	if st.RecommendedEmptyVersionKept != 0 {
		t.Errorf("RecommendedEmptyVersionKept = %d, want 0 on the measured archive: a new empty-version shape appeared", st.RecommendedEmptyVersionKept)
	}
	if cocoFixed != st.RecommendedNamedByNEVRSplit {
		t.Errorf("split builds %d but fixed events from them on SLES:15.SP6 %d: a split did not store its version", st.RecommendedNamedByNEVRSplit, cocoFixed)
	}
}
