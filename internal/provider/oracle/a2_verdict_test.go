package oracle

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// 2026-10-22 audit, A2. Two ELSAs that fix one CVE for one non-kernel
// package at two different EVRs used to make the whole (CVE, major,
// package, stream) group ambiguous, and every contributor was dropped: the
// live archive measured 9,090 such non-kernel groups across 1,564 packages
// on 2026-10-26, openssh's CVE-2024-6387 and glibc's CVE-2023-4911 among
// them, so an Oracle Linux host running the vulnerable build was reported
// clean. D144 orders the fixes into trains (one epoch:version each) and
// gives each record a window per train it fixes, which is what these tests
// hold through the store and the matcher -- the path a scan takes.

const ol9 = "Oracle Linux:9"

// verdictsOf parses doc, normalizes it, stores every record and matches each
// installed package alone: "" for no finding, else the fixed version the
// finding reports.
func verdictsOf(t *testing.T, doc string, pkgs ...pkgmeta.Package) map[string]string {
	t.Helper()
	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)

	path := filepath.Join(t.TempDir(), "v.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, a := range advs {
		if err := w.Put(a); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:   time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"oracle": {Ecosystems: []string{ol9}}},
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
		key := p.Name + "@" + p.Version
		switch len(res.Findings) {
		case 0:
			out[key] = ""
		case 1:
			out[key] = res.Findings[0].Evidence.Fixed
			if out[key] == "" {
				t.Fatalf("Match(%s %s): a finding with no fixed version", p.Name, p.Version)
			}
		default:
			t.Fatalf("Match(%s %s) = %d findings, want at most 1: %+v", p.Name, p.Version, len(res.Findings), res.Findings)
		}
	}
	return out
}

func ol9Pkg(name, version string) pkgmeta.Package {
	return pkgmeta.Package{Name: name, Version: version, Type: "rpm", Ecosystem: ol9}
}

func twoFixes(pkg, cve, evrA, evrB string) string {
	o := &ovalBuilder{}
	critA := o.platformCriterion(9) + o.fixCriterion(pkg, evrA)
	critB := o.platformCriterion(9) + o.fixCriterion(pkg, evrB)
	return o.doc(
		definitionXML("ELSA-2026-7001", "elsa", pkg+" security update", []cveFixture{{cve, ""}}, "IMPORTANT", critA),
		definitionXML("ELSA-2026-7002", "elsa", pkg+" security update", []cveFixture{{cve, ""}}, "IMPORTANT", critB))
}

// One train, two fixes: Oracle's own early regreSSHion build
// (ELSA-2024-12468, 8.7p1-38.0.2.el9) and the RHEL sync (ELSA-2024-4312,
// 8.7p1-38.0.2.el9_4.1). Both are fixes, so the lower one is the boundary;
// a host that took Oracle's July 2024 build is fixed, not told to upgrade.
func TestA2_SameVersionTwoFixesTheLowerIsTheBoundary(t *testing.T) {
	doc := twoFixes("openssh", "CVE-2024-6387", "0:8.7p1-38.0.2.el9", "0:8.7p1-38.0.2.el9_4.1")
	got := verdictsOf(t, doc,
		ol9Pkg("openssh", "8.7p1-38.el9"),
		ol9Pkg("openssh", "8.7p1-38.0.2.el9"),
		ol9Pkg("openssh", "8.7p1-38.0.2.el9_4.1"))
	want := map[string]string{
		"openssh@8.7p1-38.el9":         "0:8.7p1-38.0.2.el9",
		"openssh@8.7p1-38.0.2.el9":     "",
		"openssh@8.7p1-38.0.2.el9_4.1": "",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: verdict %q, want %q", k, got[k], w)
		}
	}
}

// Two trains: 389-ds-base fixed in 9.5.z at 2.5.2-9.el9_5 and in 9.6 at
// 2.6.1-8.el9_6 (ELSA-2025-4491 / ELSA-2025-7395, CVE-2025-2487). A host
// still on the fixed 9.5.z build is clean; one on an unfixed 2.6.1 build is
// told 2.6.1-8.el9_6, not 2.5.2-9.el9_5, which it is already above.
func TestA2_TwoVersionsEachTrainGetsItsOwnWindow(t *testing.T) {
	doc := twoFixes("389-ds-base", "CVE-2025-2487", "0:2.5.2-9.el9_5", "0:2.6.1-8.el9_6")
	got := verdictsOf(t, doc,
		ol9Pkg("389-ds-base", "2.5.2-8.el9_5"),
		ol9Pkg("389-ds-base", "2.5.2-9.el9_5"),
		ol9Pkg("389-ds-base", "2.6.1-3.el9_6"),
		ol9Pkg("389-ds-base", "2.6.1-8.el9_6"))
	want := map[string]string{
		"389-ds-base@2.5.2-8.el9_5": "0:2.5.2-9.el9_5",
		"389-ds-base@2.5.2-9.el9_5": "",
		"389-ds-base@2.6.1-3.el9_6": "0:2.6.1-8.el9_6",
		"389-ds-base@2.6.1-8.el9_6": "",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: verdict %q, want %q", k, got[k], w)
		}
	}
}

// Two epochs: RHEL's qemu-kvm (epoch 10) and Oracle's KVM build (epoch 15)
// are two products under one name (CVE-2019-12155, ELSA-2019-2607 /
// ELSA-2019-4713, measured on OL7 and reshaped onto OL9 here). The higher
// train's window opens at its own epoch, so a fixed RHEL build is not
// judged against Oracle's.
func TestA2_TwoEpochsAreTwoTrains(t *testing.T) {
	doc := twoFixes("qemu-kvm", "CVE-2019-12155", "10:1.5.3-167.el9", "15:3.1.0-5.el9")
	got := verdictsOf(t, doc,
		ol9Pkg("qemu-kvm", "10:1.5.3-160.el9"),
		ol9Pkg("qemu-kvm", "10:1.5.3-167.el9"),
		ol9Pkg("qemu-kvm", "15:3.1.0-4.el9"),
		ol9Pkg("qemu-kvm", "15:3.1.0-5.el9"))
	want := map[string]string{
		"qemu-kvm@10:1.5.3-160.el9": "10:1.5.3-167.el9",
		"qemu-kvm@10:1.5.3-167.el9": "",
		"qemu-kvm@15:3.1.0-4.el9":   "15:3.1.0-5.el9",
		"qemu-kvm@15:3.1.0-5.el9":   "",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: verdict %q, want %q", k, got[k], w)
		}
	}
}

// The kernel family keeps D74's drop: kernel-uek's trains and the bpftool,
// perf and python-perf builds that come from them are not windowed here
// (D144 scopes the change to non-kernel packages). bpftool is the case a
// name prefix alone would miss.
func TestA2_UEKBuiltPackagesKeepTheDrop(t *testing.T) {
	doc := twoFixes("bpftool", "CVE-2024-35801", "0:5.15.0-300.163.18.7.el9uek", "0:7.4.0-503.11.1.el9_5")
	got := verdictsOf(t, doc,
		ol9Pkg("bpftool", "5.15.0-200.1.1.el9uek"),
		ol9Pkg("bpftool", "7.4.0-400.1.1.el9_5"))
	for k, v := range got {
		if v != "" {
			t.Errorf("%s: verdict %q, want no finding -- a UEK-built group is still dropped", k, v)
		}
	}
}

// A definition whose own entry sits in two CVE groups that would give it
// two different windows has no single range that is right for both CVEs.
// It keeps its own statement, [0, its own fix): that contains every
// group's window, so no CVE it names goes unreported, and the cost is that a
// host on the other definition's lower fix is still told about this record
// -- for CVE-2023-4527, which only this record fixes, correctly.
func TestA2_EntryWhoseGroupsDisagreeKeepsItsOwnStatement(t *testing.T) {
	o := &ovalBuilder{}
	critA := o.platformCriterion(9) + o.fixCriterion("glibc", "0:2.34-60.0.3.el9")
	critB := o.platformCriterion(9) + o.fixCriterion("glibc", "0:2.34-60.0.3.el9_2.7")
	doc := o.doc(
		definitionXML("ELSA-2026-7101", "elsa", "glibc", []cveFixture{{"CVE-2023-4911", ""}}, "IMPORTANT", critA),
		// B fixes CVE-2023-4911 (where A's lower build is the boundary) and
		// CVE-2023-4527 (where only B speaks): one entry, two answers.
		definitionXML("ELSA-2026-7102", "elsa", "glibc", []cveFixture{{"CVE-2023-4911", ""}, {"CVE-2023-4527", ""}}, "IMPORTANT", critB))

	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	for id, want := range map[string]string{"ELSA-2026-7101": "0:2.34-60.0.3.el9", "ELSA-2026-7102": "0:2.34-60.0.3.el9_2.7"} {
		a, ok := findAdvisory(advs, id)
		if !ok {
			t.Errorf("%s missing: %+v", id, advs)
			continue
		}
		aff, ok := affectedFor(a, ol9, "glibc")
		if !ok || len(aff.Ranges) != 1 || !eventsEqual(aff.Ranges[0].Events, []advisory.Event{{Introduced: "0"}, {Fixed: want}}) {
			t.Errorf("%s glibc = %+v, want [0, %s)", id, aff, want)
		}
	}
	if st.ConflictingWindows != 1 {
		t.Errorf("ConflictingWindows = %d, want 1", st.ConflictingWindows)
	}
	got := verdictsOf(t, doc, ol9Pkg("glibc", "2.34-60.0.3.el9"))
	if got["glibc@2.34-60.0.3.el9"] != "0:2.34-60.0.3.el9_2.7" {
		t.Errorf("glibc 2.34-60.0.3.el9: verdict %q, want the CVE-2023-4527 fix 0:2.34-60.0.3.el9_2.7", got["glibc@2.34-60.0.3.el9"])
	}
}

// The windows are carried as OSV events on one range, introduced/fixed
// pairs in order, which is what the matcher's range evaluation reads.
func TestA2_WindowsAreOrderedEventPairs(t *testing.T) {
	doc := twoFixes("389-ds-base", "CVE-2025-2487", "0:2.6.1-8.el9_6", "0:2.5.2-9.el9_5")
	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatal(err)
	}
	advs := normalize(defs, &st)
	hi, _ := findAdvisory(advs, "ELSA-2026-7001")
	lo, _ := findAdvisory(advs, "ELSA-2026-7002")
	affHi, _ := affectedFor(hi, ol9, "389-ds-base")
	affLo, _ := affectedFor(lo, ol9, "389-ds-base")
	wantHi := []advisory.Event{{Introduced: "0:2.6.1"}, {Fixed: "0:2.6.1-8.el9_6"}}
	wantLo := []advisory.Event{{Introduced: "0"}, {Fixed: "0:2.5.2-9.el9_5"}}
	if len(affHi.Ranges) != 1 || !eventsEqual(affHi.Ranges[0].Events, wantHi) {
		t.Errorf("higher train's ranges = %+v, want one range %+v", affHi.Ranges, wantHi)
	}
	if len(affLo.Ranges) != 1 || !eventsEqual(affLo.Ranges[0].Events, wantLo) {
		t.Errorf("lower train's ranges = %+v, want one range %+v", affLo.Ranges, wantLo)
	}
	if st.WindowedGroups != 1 {
		t.Errorf("WindowedGroups = %d, want 1", st.WindowedGroups)
	}
}

func eventsEqual(a, b []advisory.Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The RHEL-compatible kernel carries no "uek" in its release, so only the
// kernel* prefix keeps it under the drop D144 leaves the kernel family.
func TestA2_RHCKKernelKeepsTheDrop(t *testing.T) {
	doc := twoFixes("kernel", "CVE-2024-26900", "0:5.14.0-427.13.1.el9_4", "0:5.14.0-503.11.1.el9_5")
	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatal(err)
	}
	if advs := normalize(defs, &st); len(advs) != 0 {
		t.Errorf("normalize = %+v, want nothing: a kernel group is still dropped", advs)
	}
	if st.AmbiguousGroups != 1 || st.WindowedGroups != 0 {
		t.Errorf("AmbiguousGroups = %d, WindowedGroups = %d, want 1 and 0", st.AmbiguousGroups, st.WindowedGroups)
	}
}

// A group holding an EVR the RPM comparer refuses cannot be cut into
// ordered trains; it is dropped as D74 dropped it rather than windowed in
// whatever order a failed comparison happens to leave.
func TestA2_UnorderableGroupKeepsTheDrop(t *testing.T) {
	doc := twoFixes("openssh", "CVE-2024-6387", "0:8.7p1-38.0.2 el9", "0:8.7p1-38.0.2.el9_4.1")
	var st stats
	defs, _, err := parseOVAL(strings.NewReader(doc), &st)
	if err != nil {
		t.Fatal(err)
	}
	if advs := normalize(defs, &st); len(advs) != 0 {
		t.Errorf("normalize = %+v, want nothing", advs)
	}
	if st.AmbiguousGroups != 1 {
		t.Errorf("AmbiguousGroups = %d, want 1", st.AmbiguousGroups)
	}
}
