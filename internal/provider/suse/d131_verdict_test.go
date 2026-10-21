package suse

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// verdictsOf drives one converted document through the REAL store and the
// matcher, and returns what each installed package was told: "" for no
// finding, the fixed version for a finding that names one, and
// affectedNoFix for a finding that names none. The third value is what
// keeps a "clean" row honest -- a package reported affected at every version
// also carries no fixed version, and D131's review found the first draft
// folding that into "" (every clean row then passed under a store that kept
// the no-fix range beside the split one). This is the path a scan takes; a
// convert-level assertion says what was stored, this says what a host
// running the package would be told.
const affectedNoFix = "<affected, no fix>"

func verdictsOf(t *testing.T, adv advisory.Advisory, pkgs ...pkgmeta.Package) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(adv); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:   time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"suse": {Ecosystems: []string{"SLES:15.SP6", "openSUSE Leap:15.6"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	out := map[string]string{}
	for _, p := range pkgs {
		res, err := matcher.New(db).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
		if err != nil {
			t.Fatalf("Match(%s %s): %v", p.Name, p.Version, err)
		}
		if len(res.Skipped) != 0 {
			t.Fatalf("Match(%s %s) skipped: %+v", p.Name, p.Version, res.Skipped)
		}
		key := p.Ecosystem + "/" + p.Name + "@" + p.Version
		switch len(res.Findings) {
		case 0:
			out[key] = ""
		case 1:
			out[key] = res.Findings[0].Evidence.Fixed
			if out[key] == "" {
				out[key] = affectedNoFix
			}
		default:
			t.Fatalf("Match(%s %s) = %d findings, want at most 1", p.Name, p.Version, len(res.Findings))
		}
	}
	return out
}

// D131 end to end: a kernel-coco older than the split build's version is
// found and told the fix; one at or past it is clean. Before D131 every one
// of these was clean -- the record sat under a name no rpm has.
func TestD131_KernelCocoIsJudgedAgainstTheSplitBuild(t *testing.T) {
	const plat = "SUSE Linux Enterprise Module for Confidential Computing Technical Preview 15 SP6"
	d := buildDoc(t, "CVE-2024-50102",
		[]string{plat},
		map[string]string{"kernel-coco-6.4.0-15061.9.coco15sp6.1": "pkg:rpm/suse/kernel-coco-6.4.0-15061.9.coco15sp6.1@"},
		[]string{plat + ":kernel-coco-6.4.0-15061.9.coco15sp6.1"},
		nil, nil)
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped the document")
	}

	got := verdictsOf(t, adv,
		pkgmeta.Package{Name: "kernel-coco", Version: "6.4.0-15061.8.coco15sp6.1", Ecosystem: "SLES:15.SP6"},
		pkgmeta.Package{Name: "kernel-coco", Version: "6.4.0-15061.9.coco15sp6.1", Ecosystem: "SLES:15.SP6"},
		pkgmeta.Package{Name: "kernel-coco", Version: "6.4.0-15061.21.coco15sp6.1", Ecosystem: "SLES:15.SP6"},
		// The name the record used to be stored under: nothing installs it,
		// and nothing must match it either.
		pkgmeta.Package{Name: "kernel-coco-6.4.0-15061.9.coco15sp6.1", Version: "6.4.0-15061.8.coco15sp6.1", Ecosystem: "SLES:15.SP6"},
	)
	want := map[string]string{
		"SLES:15.SP6/kernel-coco@6.4.0-15061.8.coco15sp6.1":                           "6.4.0-15061.9.coco15sp6.1",
		"SLES:15.SP6/kernel-coco@6.4.0-15061.9.coco15sp6.1":                           "",
		"SLES:15.SP6/kernel-coco@6.4.0-15061.21.coco15sp6.1":                          "",
		"SLES:15.SP6/kernel-coco-6.4.0-15061.9.coco15sp6.1@6.4.0-15061.8.coco15sp6.1": "",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: judged fixed-at %q, want %q", k, got[k], w)
		}
	}
}

// The coexistence the reviewer asked about (D131 review, condition 3): the
// Confidential Computing module's qemu build sits beside Basesystem's on the
// same key with a LOWER release number (15061.6 < 150600.3.20.1 by rpm
// order). The matcher takes the union of an entry's ranges, so the lower
// bound cannot hide anything: a codestream qemu below its own fix is still
// found, one at its fix is clean, and a module build below the module's fix
// is found. Every verdict here is what it was before D131 -- the split range
// lies inside the codestream one -- which is the point: adding it changes
// nothing for the 168 measured builds that have a codestream twin.
func TestD131_SplitBuildBesideACodestreamFixChangesNoVerdict(t *testing.T) {
	const base = "SUSE Linux Enterprise Module for Basesystem 15 SP6"
	const coco = "SUSE Linux Enterprise Module for Confidential Computing Technical Preview 15 SP6"
	d := buildDoc(t, "CVE-2024-7730",
		[]string{base, coco},
		map[string]string{
			"qemu-8.2.7-150600.3.20.1":       "pkg:rpm/suse/qemu@8.2.7-150600.3.20.1",
			"qemu-8.2.7-15061.6.coco15sp6.1": "pkg:rpm/suse/qemu-8.2.7-15061.6.coco15sp6.1@",
		},
		[]string{base + ":qemu-8.2.7-150600.3.20.1", coco + ":qemu-8.2.7-15061.6.coco15sp6.1"},
		nil, nil)
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped the document")
	}
	pk := func(v string) pkgmeta.Package {
		return pkgmeta.Package{Name: "qemu", Version: v, Ecosystem: "SLES:15.SP6"}
	}
	got := verdictsOf(t, adv,
		pk("8.2.7-150600.3.15.1"),       // codestream, below its fix
		pk("8.2.7-150600.3.20.1"),       // codestream, at its fix
		pk("8.2.7-15061.5.coco15sp6.1"), // module build, below the module's fix
	)
	if got["SLES:15.SP6/qemu@8.2.7-150600.3.15.1"] == "" {
		t.Errorf("codestream qemu below its fix judged clean: the split build's lower bound hid it")
	}
	if got["SLES:15.SP6/qemu@8.2.7-150600.3.20.1"] != "" {
		t.Errorf("codestream qemu at its fix judged affected (fixed-at %q)", got["SLES:15.SP6/qemu@8.2.7-150600.3.20.1"])
	}
	if got["SLES:15.SP6/qemu@8.2.7-15061.5.coco15sp6.1"] == "" {
		t.Errorf("module qemu below the module's fix judged clean")
	}
}
