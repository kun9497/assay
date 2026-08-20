package fedora

import "testing"

// TestExtractCVEs_TitleAndNotesBothScanned, TestFetch_ExtractsCVEFromNotesNotJustTitle
// already drove this through Fetch; this is the direct unit test for the
// branches that test cannot cheaply reach (multiple CVEs, dedup across
// title+notes, no match at all).
func TestExtractCVEs(t *testing.T) {
	for _, tt := range []struct {
		name         string
		title, notes string
		want         []string
	}{
		{"CVE in title only", "CVE-2026-1001 openssh update", "", []string{"CVE-2026-1001"}},
		{"CVE in notes only", "openssh update", "Fixes CVE-2026-1002.", []string{"CVE-2026-1002"}},
		{"CVEs in both, title first", "CVE-2026-1003 update",
			"Also fixes CVE-2026-1004.", []string{"CVE-2026-1003", "CVE-2026-1004"}},
		{"duplicate across title and notes is deduped", "CVE-2026-1005 update",
			"See CVE-2026-1005 for details.", []string{"CVE-2026-1005"}},
		{"multiple CVEs in notes, first-seen order", "kernel update",
			"Fixes CVE-2026-2002 and CVE-2026-2001.", []string{"CVE-2026-2002", "CVE-2026-2001"}},
		{"long sequence number", "CVE-2017-1000001 update", "", []string{"CVE-2017-1000001"}},
		{"no CVE anywhere", "general bugfixes", "Stability improvements.", nil},
		{"CVE-shaped but too short a sequence is not matched", "CVE-2026-1 update", "", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCVEs(tt.title, tt.notes)
			if len(got) != len(tt.want) {
				t.Fatalf("extractCVEs(%q, %q) = %v, want %v", tt.title, tt.notes, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractCVEs(%q, %q)[%d] = %q, want %q", tt.title, tt.notes, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseNVR(t *testing.T) {
	for _, tt := range []struct {
		nvr                            string
		wantName, wantVersion, wantRel string
		wantOK                         bool
	}{
		{"openssh-8.7p1-1.fc43", "openssh", "8.7p1", "1.fc43", true},
		{"kernel-6.10.5-100.fc43", "kernel", "6.10.5", "100.fc43", true},
		// A hyphenated NAME is real and common ("java-17-openjdk") -- the
		// split has to come from the RIGHT, not the first hyphen.
		{"java-17-openjdk-17.0.9-1.fc43", "java-17-openjdk", "17.0.9", "1.fc43", true},
		{"no-hyphens-at-all", "no-hyphens", "at", "all", true},
		{"onlyonehyphen-x", "", "", "", false},
		{"nohyphenatall", "", "", "", false},
		{"", "", "", "", false},
		{"trailing-hyphen-", "", "", "", false},
	} {
		t.Run(tt.nvr, func(t *testing.T) {
			name, version, release, ok := parseNVR(tt.nvr)
			if ok != tt.wantOK {
				t.Fatalf("parseNVR(%q) ok = %v, want %v", tt.nvr, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if name != tt.wantName || version != tt.wantVersion || release != tt.wantRel {
				t.Errorf("parseNVR(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.nvr, name, version, release, tt.wantName, tt.wantVersion, tt.wantRel)
			}
		})
	}
}

func TestRpmEVR(t *testing.T) {
	zero, ten := 0, 10
	for _, tt := range []struct {
		name             string
		epoch            *int
		version, release string
		want             string
	}{
		{"nil epoch", nil, "1.2.3", "4.fc43", "1.2.3-4.fc43"},
		{"zero epoch", &zero, "1.2.3", "4.fc43", "1.2.3-4.fc43"},
		{"nonzero epoch", &ten, "1.5.3", "141.fc43", "10:1.5.3-141.fc43"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := rpmEVR(tt.epoch, tt.version, tt.release); got != tt.want {
				t.Errorf("rpmEVR(%v, %q, %q) = %q, want %q", tt.epoch, tt.version, tt.release, got, tt.want)
			}
		})
	}
}

func TestNormalizeSeverityWord(t *testing.T) {
	for _, tt := range []struct {
		word     string
		wantWord string
		wantOK   bool
	}{
		{"urgent", "Urgent", true},
		{"URGENT", "Urgent", true},
		{"high", "High", true},
		{"medium", "Medium", true},
		{"low", "Low", true},
		{" low ", "Low", true},
		// Bodhi's own "nobody set a severity" value -- deliberately NOT
		// recognized (D17).
		{"unspecified", "", false},
		{"", "", false},
		{"Critical", "", false}, // RHSA's word, never Bodhi's own
	} {
		t.Run(tt.word, func(t *testing.T) {
			got, ok := normalizeSeverityWord(tt.word)
			if ok != tt.wantOK {
				t.Fatalf("normalizeSeverityWord(%q) ok = %v, want %v", tt.word, ok, tt.wantOK)
			}
			if ok && got != tt.wantWord {
				t.Errorf("normalizeSeverityWord(%q) = %q, want %q", tt.word, got, tt.wantWord)
			}
		})
	}
}

func TestDatabaseOf(t *testing.T) {
	for _, tt := range []struct{ id, want string }{
		{"FEDORA-2026-abcdef1234", "FEDORA"},
		{"FEDORA-EPEL-2026-abcdef1234", "FEDORA"},
		{"noHyphen", "noHyphen"},
		{"", ""},
	} {
		if got := databaseOf(tt.id); got != tt.want {
			t.Errorf("databaseOf(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
