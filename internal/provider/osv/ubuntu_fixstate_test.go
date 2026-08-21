package osv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// writeUbuntuTrackerFile writes one CVE file under dir/sub (sub is "active"
// or "retired"), mirroring the real tracker's layout: no file extension, one
// file per CVE.
func writeUbuntuTrackerFile(t *testing.T, dir, sub, cve, body string) {
	t.Helper()
	full := filepath.Join(dir, sub)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, cve), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildUbuntuTracker parses dir (built by the caller with
// writeUbuntuTrackerFile) into a *ubuntuTracker via the real parse path
// (parseUbuntuTracker), so every test below exercises the actual walk+parse
// code rather than a hand-built map that could drift from it.
func buildUbuntuTracker(t *testing.T, dir string, st *stats) *ubuntuTracker {
	t.Helper()
	tracker, err := parseUbuntuTracker(dir, st)
	if err != nil {
		t.Fatalf("parseUbuntuTracker: %v", err)
	}
	return tracker
}

// ubuntuFixlessRecord is one OSV record shaped the way a real Ubuntu record
// with no fixed version looks: affected.ecosystem is the mainline release
// key (D53), affected.name is already the source package (D8), and the
// range is fix-less -- a lone `{"introduced":"0"}` event, exactly the shape
// D52 and D85's brief both describe.
func ubuntuFixlessRecord(id, cve, ecosystem, pkg string) string {
	return `{"id":"` + id + `","upstream":["` + cve + `"],"affected":[` +
		`{"package":{"name":"` + pkg + `","ecosystem":"` + ecosystem + `"},` +
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
}

// TestConvert_UbuntuIgnoredStampsWontFix is the caller-first test: it drives
// convert() -- the function fetchOne actually calls -- with a real tracker
// parsed from a real file, exactly the "OSV provider's real conversion path"
// the brief asks for. Commenting out the stampUbuntuFixState call site in
// convert() (record.go) turns this red: FixState stays "" (unknown) instead
// of wont-fix. Verified by hand during development; left as a comment here
// rather than a permanently-disabled second test, matching how this
// package's other delete-goes-red claims are recorded (D53's own
// TestConvert_UbuntuLineageEntriesAreDropped doc comment does the same).
func TestConvert_UbuntuIgnoredStampsWontFix(t *testing.T) {
	dir := t.TempDir()
	writeUbuntuTrackerFile(t, dir, "active", "CVE-2026-9001", "Candidate: CVE-2026-9001\n"+
		"PublicDate: 2026-01-01 00:00:00 UTC\n"+
		"Priority: medium\n\n"+
		"Patches_openssl:\n"+
		"jammy_openssl: ignored (no fix will be provided)\n")
	var st stats
	tracker := buildUbuntuTracker(t, dir, &st)

	rec := ubuntuFixlessRecord("UBUNTU-CVE-2026-9001", "CVE-2026-9001", "Ubuntu:22.04:LTS", "openssl")
	got, ok, err := convert([]byte(rec), "Ubuntu", &st, tracker)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !ok {
		t.Fatal("convert returned ok=false, want a converted advisory")
	}
	if len(got.Affected) != 1 || len(got.Affected[0].Ranges) != 1 {
		t.Fatalf("Affected = %+v, want one entry with one range", got.Affected)
	}
	rng := got.Affected[0].Ranges[0]
	if rng.FixState != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q", rng.FixState, advisory.FixStateWontFix)
	}
	// The reason text never reaches advisory.Range (ubuntuFixState's own
	// comment explains why: it mirrors Red Hat's remediation category, which
	// is likewise never stored as prose). It is still checked here, against
	// the PARSED table rather than the advisory, which is what "the reason"
	// means for this source: proof the parser captured it, not that the
	// schema carries it.
	entry, found := tracker.lookup("CVE-2026-9001", "openssl", "22.04")
	if !found {
		t.Fatal("tracker.lookup found no entry for the tuple this record names")
	}
	if entry.reason != "no fix will be provided" {
		t.Errorf("parsed reason = %q, want %q", entry.reason, "no fix will be provided")
	}
	if st.UbuntuStampedWontFix != 1 {
		t.Errorf("stats.UbuntuStampedWontFix = %d, want 1", st.UbuntuStampedWontFix)
	}
}

// TestConvert_UbuntuNeededStampsNotFixed covers the "not fixed yet" half of
// the mapping, and needs-triage/pending/deferred alongside it -- all four are
// the "no fix yet" instructions D85's brief separates from `ignored`.
func TestConvert_UbuntuNeededStampsNotFixed(t *testing.T) {
	for _, state := range []string{"needed", "needs-triage", "pending", "deferred"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			writeUbuntuTrackerFile(t, dir, "active", "CVE-2026-9002",
				"Candidate: CVE-2026-9002\n\nPatches_curl:\njammy_curl: "+state+"\n")
			var st stats
			tracker := buildUbuntuTracker(t, dir, &st)

			rec := ubuntuFixlessRecord("UBUNTU-CVE-2026-9002", "CVE-2026-9002", "Ubuntu:22.04:LTS", "curl")
			got, ok, err := convert([]byte(rec), "Ubuntu", &st, tracker)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}
			if !ok {
				t.Fatal("convert returned ok=false")
			}
			rng := got.Affected[0].Ranges[0]
			if rng.FixState != advisory.FixStateNotFixed {
				t.Errorf("FixState = %q, want %q", rng.FixState, advisory.FixStateNotFixed)
			}
		})
	}
}

// TestConvert_UbuntuReleasedStampsNothing covers the states the design says
// must stamp nothing: released, DNE, not-affected, and a tuple absent from
// the table altogether (a package/release the tracker never mentions for
// this CVE). All four must leave FixState at its zero value -- the "unknown"
// this build already reported before D85, not a fabricated fourth answer.
func TestConvert_UbuntuReleasedStampsNothing(t *testing.T) {
	for _, tt := range []struct {
		name  string
		state string
		abs   bool // true: the tuple is absent from the table entirely
	}{
		{name: "released", state: "released"},
		{name: "DNE", state: "DNE"},
		{name: "not-affected", state: "not-affected (uses system openssl)"},
		{name: "absent from the table", abs: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			body := "Candidate: CVE-2026-9003\n\nPatches_nodejs:\n"
			if !tt.abs {
				body += "jammy_nodejs: " + tt.state + "\n"
			}
			writeUbuntuTrackerFile(t, dir, "active", "CVE-2026-9003", body)
			var st stats
			tracker := buildUbuntuTracker(t, dir, &st)

			rec := ubuntuFixlessRecord("UBUNTU-CVE-2026-9003", "CVE-2026-9003", "Ubuntu:22.04:LTS", "nodejs")
			got, ok, err := convert([]byte(rec), "Ubuntu", &st, tracker)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}
			if !ok {
				t.Fatal("convert returned ok=false")
			}
			rng := got.Affected[0].Ranges[0]
			if rng.FixState != "" {
				t.Errorf("FixState = %q, want empty (unknown) -- nothing should be stamped", rng.FixState)
			}
		})
	}
}

// TestConvert_UbuntuBareIgnoredHasEmptyReason pins the divergence from Red
// Hat documented on ubuntuFixState: a bare `ignored`, with no parenthesized
// reason at all (the common mainline case, 5,352 of the measured 5,546
// `ignored` rows), must still classify as wont-fix. Requiring a reason
// before trusting the state word would silently narrow wont-fix to the
// minority that happens to carry prose.
func TestConvert_UbuntuBareIgnoredHasEmptyReason(t *testing.T) {
	dir := t.TempDir()
	writeUbuntuTrackerFile(t, dir, "active", "CVE-2026-9004",
		"Candidate: CVE-2026-9004\n\nPatches_coreutils:\njammy_coreutils: ignored\n")
	var st stats
	tracker := buildUbuntuTracker(t, dir, &st)

	entry, found := tracker.lookup("CVE-2026-9004", "coreutils", "22.04")
	if !found {
		t.Fatal("tracker.lookup found no entry")
	}
	if entry.reason != "" {
		t.Errorf("parsed reason = %q, want empty", entry.reason)
	}

	rec := ubuntuFixlessRecord("UBUNTU-CVE-2026-9004", "CVE-2026-9004", "Ubuntu:22.04:LTS", "coreutils")
	got, ok, err := convert([]byte(rec), "Ubuntu", &st, tracker)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !ok {
		t.Fatal("convert returned ok=false")
	}
	if fs := got.Affected[0].Ranges[0].FixState; fs != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q (a bare `ignored` still classifies)", fs, advisory.FixStateWontFix)
	}
}

// TestConvert_UbuntuCVEInRetiredResolvesSameAsActive drives the "one
// namespace" property (D85's brief) through convert(): a CVE file that
// migrated to retired/ must stamp identically to one still in active/.
func TestConvert_UbuntuCVEInRetiredResolvesSameAsActive(t *testing.T) {
	dir := t.TempDir()
	writeUbuntuTrackerFile(t, dir, "retired", "CVE-2026-9005",
		"Candidate: CVE-2026-9005\n\nPatches_bash:\njammy_bash: ignored (end of life)\n")
	var st stats
	tracker := buildUbuntuTracker(t, dir, &st)

	rec := ubuntuFixlessRecord("UBUNTU-CVE-2026-9005", "CVE-2026-9005", "Ubuntu:22.04:LTS", "bash")
	got, ok, err := convert([]byte(rec), "Ubuntu", &st, tracker)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !ok {
		t.Fatal("convert returned ok=false")
	}
	if fs := got.Affected[0].Ranges[0].FixState; fs != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q -- a retired/ CVE must resolve the same as an active/ one",
			fs, advisory.FixStateWontFix)
	}
}

// TestParseUbuntuTrackerFile_LineagePrefixedRowsNeverEnterTable is the
// parser-level half of D53's rule applied to the tracker's own file shape:
// esm-infra/, esm-apps/, fips/, fips-updates/, .../esm and precise/esm are
// all dropped by ubuntuTrackerLineRe's own anchor, never merely filtered
// downstream. Mixed with mainline rows in one file, the way a real CVE file
// is, so a regex that accidentally matched a lineage row would show up as an
// extra tuple rather than being invisible.
func TestParseUbuntuTrackerFile_LineagePrefixedRowsNeverEnterTable(t *testing.T) {
	dir := t.TempDir()
	writeUbuntuTrackerFile(t, dir, "active", "CVE-2026-9006", "Candidate: CVE-2026-9006\n\n"+
		"Patches_pcre3:\n"+
		"esm-infra/jammy_pcre3: ignored (end of ESM support, was ignored)\n"+
		"trusty/esm_pcre3: ignored (end of ESM support, was deferred)\n"+
		"precise/esm_pcre3: ignored (end of life, was deferred)\n"+
		"fips-updates/jammy_openssl: released (3.0.2-0ubuntu1.9+Fips1)\n"+
		"jammy_pcre3: ignored (see notes)\n")
	var st stats
	tracker := buildUbuntuTracker(t, dir, &st)

	if _, found := tracker.lookup("CVE-2026-9006", "pcre3", "22.04"); !found {
		t.Fatal("the mainline jammy_pcre3 row must be in the table")
	}
	if len(tracker.entries) != 1 {
		t.Errorf("tracker holds %d entries, want exactly 1 -- every esm-infra/, "+
			"trusty/esm_, precise/esm_ and fips-updates/ row must be dropped by the "+
			"line anchor: %+v", len(tracker.entries), tracker.entries)
	}
	if st.UbuntuTuplesLoaded != 1 {
		t.Errorf("UbuntuTuplesLoaded = %d, want 1", st.UbuntuTuplesLoaded)
	}
}

// TestParseUbuntuTrackerFile_UnknownCodenameCounted covers the pseudo-release
// rows every real file also carries (upstream_pkg, devel_pkg) plus a
// genuinely EOL'd interim this build does not map (kinetic): none of the
// three enters the table, and each is counted.
func TestParseUbuntuTrackerFile_UnknownCodenameCounted(t *testing.T) {
	dir := t.TempDir()
	writeUbuntuTrackerFile(t, dir, "active", "CVE-2026-9007", "Candidate: CVE-2026-9007\n\n"+
		"Patches_vim:\n"+
		"upstream_vim: needed\n"+
		"devel_vim: ignored\n"+
		"kinetic_vim: ignored (end of life)\n"+
		"jammy_vim: needed\n")
	var st stats
	tracker := buildUbuntuTracker(t, dir, &st)

	if _, found := tracker.lookup("CVE-2026-9007", "vim", "22.04"); !found {
		t.Fatal("the mainline jammy_vim row must be in the table")
	}
	if len(tracker.entries) != 1 {
		t.Errorf("tracker holds %d entries, want exactly 1: %+v", len(tracker.entries), tracker.entries)
	}
	if st.UbuntuUnknownCodename != 3 {
		t.Errorf("UbuntuUnknownCodename = %d, want 3 (upstream, devel, kinetic)", st.UbuntuUnknownCodename)
	}
}

// TestParseUbuntuTrackerFile_NoReadableCandidateIsUnparsed covers the
// "files unparsed" count: a file with no Candidate: line at all (a
// placeholder, or a shape this build does not expect) contributes zero
// tuples and is counted rather than silently skipped.
func TestParseUbuntuTrackerFile_NoReadableCandidateIsUnparsed(t *testing.T) {
	dir := t.TempDir()
	writeUbuntuTrackerFile(t, dir, "active", "not-a-cve-file", "just some text\nwith no Candidate line\n")
	var st stats
	tracker := buildUbuntuTracker(t, dir, &st)
	if len(tracker.entries) != 0 {
		t.Errorf("tracker holds %d entries, want 0", len(tracker.entries))
	}
	if st.UbuntuFilesUnparsed != 1 {
		t.Errorf("UbuntuFilesUnparsed = %d, want 1", st.UbuntuFilesUnparsed)
	}
}

// TestParseUbuntuTrackerLine is the stanza line grammar's own table:
// vocabulary, the parenthesized reason (including one with a comma inside
// it -- "(end of ESM support, was ignored)", which must capture whole, not
// split on the comma), and the shapes that must NOT match at all.
func TestParseUbuntuTrackerLine(t *testing.T) {
	for _, tt := range []struct {
		name       string
		line       string
		wantOK     bool
		wantRel    string
		wantPkg    string
		wantState  string
		wantReason string
	}{
		{name: "bare ignored, no reason", line: "jammy_coreutils: ignored",
			wantOK: true, wantRel: "jammy", wantPkg: "coreutils", wantState: "ignored"},
		{name: "ignored with simple reason", line: "trusty_coreutils: ignored (end of standard support)",
			wantOK: true, wantRel: "trusty", wantPkg: "coreutils", wantState: "ignored",
			wantReason: "end of standard support"},
		{name: "reason with a comma inside the parens",
			line:   "esm-infra/xenial_pcre3: ignored (end of ESM support, was ignored)",
			wantOK: false}, // lineage-prefixed: dropped by the anchor, not by content
		{name: "reason with a comma, mainline row",
			line:   "jammy_pcre3: ignored (end of ESM support, was ignored)",
			wantOK: true, wantRel: "jammy", wantPkg: "pcre3", wantState: "ignored",
			wantReason: "end of ESM support, was ignored"},
		{name: "needed", line: "jammy_openssl1.0: needed",
			wantOK: true, wantRel: "jammy", wantPkg: "openssl1.0", wantState: "needed"},
		{name: "package name with a dot and digit", line: "focal_edk2: not-affected (2023.11-5)",
			wantOK: true, wantRel: "focal", wantPkg: "edk2", wantState: "not-affected", wantReason: "2023.11-5"},
		{name: "released with a version reason", line: "jammy_openssl: released (3.0.2-0ubuntu1.9)",
			wantOK: true, wantRel: "jammy", wantPkg: "openssl", wantState: "released", wantReason: "3.0.2-0ubuntu1.9"},
		{name: "DNE", line: "jammy_openssl1.0: DNE", wantOK: true,
			wantRel: "jammy", wantPkg: "openssl1.0", wantState: "DNE"},
		{name: "esm-infra lineage prefix", line: "esm-infra/bionic_pcre3: ignored (see notes)", wantOK: false},
		{name: "trusty/esm lineage prefix", line: "trusty/esm_coreutils: ignored (end of ESM support, was deferred)",
			wantOK: false},
		{name: "precise/esm lineage prefix", line: "precise/esm_coreutils: ignored (end of life)", wantOK: false},
		{name: "fips-updates lineage prefix", line: "fips-updates/jammy_openssl: needed", wantOK: false},
		{name: "esm-infra-legacy lineage prefix", line: "esm-infra-legacy/trusty_coreutils: ignored", wantOK: false},
		{name: "blank line", line: "", wantOK: false},
		{name: "Candidate line", line: "Candidate: CVE-2016-2781", wantOK: false},
		{name: "prose line", line: " mdeslaur> We will not be fixing this CVE in Ubuntu.", wantOK: false},
		{name: "header line", line: "Patches_coreutils:", wantOK: false},
		{name: "upstream pseudo-release", line: "upstream_coreutils: needed",
			wantOK: true, wantRel: "upstream", wantPkg: "coreutils", wantState: "needed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseUbuntuTrackerLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("parseUbuntuTrackerLine(%q) ok = %v, want %v (got %+v)", tt.line, ok, tt.wantOK, got)
			}
			if !ok {
				return
			}
			if got.release != tt.wantRel {
				t.Errorf("release = %q, want %q", got.release, tt.wantRel)
			}
			if got.pkg != tt.wantPkg {
				t.Errorf("pkg = %q, want %q", got.pkg, tt.wantPkg)
			}
			if got.state != tt.wantState {
				t.Errorf("state = %q, want %q", got.state, tt.wantState)
			}
			if got.reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", got.reason, tt.wantReason)
			}
		})
	}
}

// TestUbuntuFixState pins the closed vocabulary: exactly two words resolve
// to wont-fix's opposite number and one to wont-fix itself, everything else
// (including case variants and typos) stamps nothing rather than guessing.
func TestUbuntuFixState(t *testing.T) {
	for _, tt := range []struct {
		state string
		want  advisory.FixState
		ok    bool
	}{
		{state: "ignored", want: advisory.FixStateWontFix, ok: true},
		{state: "needed", want: advisory.FixStateNotFixed, ok: true},
		{state: "needs-triage", want: advisory.FixStateNotFixed, ok: true},
		{state: "pending", want: advisory.FixStateNotFixed, ok: true},
		{state: "deferred", want: advisory.FixStateNotFixed, ok: true},
		{state: "released", ok: false},
		{state: "DNE", ok: false},
		{state: "not-affected", ok: false},
		{state: "Ignored", ok: false}, // case-sensitive: the tracker's own vocabulary is lowercase
		{state: "", ok: false},
	} {
		t.Run(tt.state, func(t *testing.T) {
			got, ok := ubuntuFixState(tt.state)
			if ok != tt.ok {
				t.Fatalf("ubuntuFixState(%q) ok = %v, want %v", tt.state, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("ubuntuFixState(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}
