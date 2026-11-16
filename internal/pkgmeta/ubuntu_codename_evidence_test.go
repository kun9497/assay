package pkgmeta

import "testing"

// Main QA of f554fb2 (2026-11-13): a codename is evidence for the release it
// names only. kinetic is 22.10, so a 22.04 operating system saying kinetic
// contradicts itself; a codename neither table knows is accepted only for a
// release neither table names.
func TestUbuntuCodenameOf(t *testing.T) {
	for _, tc := range []struct{ id, version, codename, want string }{
		{"ubuntu", "22.04", "jammy", "jammy"},
		{"ubuntu", "22.04", "JAMMY", "jammy"},
		{"Ubuntu", "22.04.5", "jammy", "jammy"},
		{"ubuntu", "22.04", "noble", ContradictedCodename},
		{"ubuntu", "22.04", "kinetic", ContradictedCodename},
		{"ubuntu", "22.10", "kinetic", "kinetic"},
		{"ubuntu", "22.10", "lunar", ContradictedCodename}, // both retired: the table holds them to their releases
		{"ubuntu", "16.04", "xenial", "xenial"},
		{"ubuntu", "12.04", "precise", "precise"},
		{"ubuntu", "22.04", "tangy", ContradictedCodename}, // 22.04 is named: jammy
		{"ubuntu", "27.04", "tangy", "tangy"},              // a release newer than the tables
		{"ubuntu", "22.04", ContradictedCodename, ContradictedCodename},
		{"ubuntu", "22.04", "", ""},
		{"ubuntu", "", "jammy", ""},
		{"debian", "12", "bookworm", ""},
	} {
		got := UbuntuCodenameOf(Distro{ID: tc.id, VersionID: tc.version, VersionCodename: tc.codename})
		if got != tc.want {
			t.Errorf("%s %s %q: got %q, want %q", tc.id, tc.version, tc.codename, got, tc.want)
		}
	}
}

func TestMergeCodename(t *testing.T) {
	for _, tc := range [][3]string{
		{"", "", ""}, {"jammy", "", "jammy"}, {"", "jammy", "jammy"}, {"jammy", "JAMMY", "jammy"},
		{"jammy", "noble", ContradictedCodename}, {ContradictedCodename, "jammy", ContradictedCodename},
		{"jammy", ContradictedCodename, ContradictedCodename}, {ContradictedCodename, "", ContradictedCodename},
	} {
		if got := MergeCodename(tc[0], tc[1]); got != tc[2] {
			t.Errorf("MergeCodename(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
	if UbuntuCodenameEvidence(ContradictedCodename) != "" || UbuntuCodenameEvidence("jammy") != "jammy" {
		t.Error("UbuntuCodenameEvidence must read a contradiction as no evidence")
	}
}

// Every retired codename names a release the tracker table does not, so the
// two tables cannot disagree about a release.
func TestUbuntuRetiredReleasesDoNotOverlapTheTracker(t *testing.T) {
	live := UbuntuReleases()
	for cn, r := range ubuntuRetiredReleases {
		if live[cn] != "" {
			t.Errorf("%s is in both tables", cn)
		}
		for lcn, lr := range live {
			if lr == r {
				t.Errorf("%s (%s) and %s name one release", cn, r, lcn)
			}
		}
	}
}
