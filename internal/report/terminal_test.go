package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/dirscan"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/version"
)

// QA 2026-11-20. Every control character below is assembled from its code
// point rather than typed (CLAUDE.md: a literal one is lost in transit).
var (
	esc     = string(rune(0x1b))
	newline = string(rune(0x0a))
	tab     = string(rune(0x09))
	bel     = string(rune(0x07))
	c1      = string(rune(0x9b))   // CSI as one C1 character
	rlo     = string(rune(0x202e)) // right-to-left override
	lineSep = string(rune(0x2028))
)

func TestText(t *testing.T) {
	bs := string(rune(0x5c))
	for _, tc := range []struct{ name, in, want string }{
		{"plain", "libssl3", "libssl3"},
		{"other scripts pass", "패키지-ライブラリ-ü", "패키지-ライブラリ-ü"},
		{"escape", "a" + esc + "[2Jb", "a" + bs + "x1b[2Jb"},
		{"newline", "a" + newline + "error: forged", "a" + bs + "x0aerror: forged"},
		{"tab", "a" + tab + "b", "a" + bs + "x09b"},
		{"bell", bel, bs + "x07"},
		{"C1 control", "a" + c1 + "b", "a" + bs + "x9bb"},
		{"bidi override", "evil" + rlo + "gpj.exe", "evil" + bs + "u202egpj.exe"},
		{"line separator", "a" + lineSep + "b", "a" + bs + "u2028b"},
		{"invalid UTF-8", "a" + string([]byte{0xff}) + "b", "a" + bs + "xffb"},
	} {
		if got := Text(tc.in); got != tc.want {
			t.Errorf("%s: Text(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// hostile is a result in which every string the table prints carries a
// terminal escape and a newline.
func hostile() (matcher.Result, []dirscan.Unread) {
	bad := esc + "[31m" + newline + "error: forged"
	f := matcher.Finding{
		Package:  pkgmeta.Package{Name: "pkg" + bad, Version: "1.0" + bad, Ecosystem: "npm"},
		Advisory: advisory.Advisory{ID: "GHSA-x" + bad, Summary: "summary" + bad, Aliases: []string{"CVE-1" + bad}},
		Evidence: version.Evidence{Introduced: "0", Fixed: "2.0" + bad, Reason: "below" + bad},
		Severity: severity.High, Score: 7.5,
		Identifiers: []string{"GHSA-x" + bad, "CVE-1" + bad},
		Waived:      []matcher.Waived{{CVE: "CVE-2" + bad, Reason: "why" + bad, Source: "vex"}},
	}
	res := matcher.Result{
		Findings:   []matcher.Finding{f},
		Suppressed: []matcher.Suppressed{{Finding: f, Reason: "waived" + bad, Source: "ignore-file"}},
		Skipped:    []matcher.Skipped{{Package: pkgmeta.Package{Name: "skip" + bad, Version: "3" + bad}, Reason: "no" + bad}},
	}
	return res, []dirscan.Unread{{Path: "dir/file" + bad, Reason: "unreadable" + bad, Failed: true}}
}

// The caller's test: nothing the target supplied reaches a terminal as a
// control character, in the table or in --explain. Colour is off, so any ESC
// in the output is the target's.
func TestTableAndExplain_PrintNoControlCharacterFromTheTarget(t *testing.T) {
	res, unread := hostile()
	var table, explain bytes.Buffer
	if _, err := Table(&table, res, cyclonedx.Stats{Components: 2, Cataloged: 2}, unread, EOLStatus{}, Coverage{}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Explain(&explain, res, "GHSA-x"+esc+"[31m"+newline+"error: forged"); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"table": table.String(), "explain": explain.String()} {
		if out == "" {
			t.Fatalf("%s printed nothing", name)
		}
		if strings.Contains(out, esc) {
			t.Errorf("%s output carries a raw ESC", name)
		}
		for _, line := range strings.Split(out, newline) {
			if strings.HasPrefix(line, "error: forged") {
				t.Errorf("%s output lets the target start a line: %q", name, line)
			}
		}
		if !strings.Contains(out, string(rune(0x5c))+"x1b[31m") {
			t.Errorf("%s output does not show the escape spelled out:%s%s", name, newline, out)
		}
	}
}

// The copy is a copy: the JSON renderer and the verdict read the caller's
// value after the table has printed from it.
func TestTerminalSafe_LeavesTheCallersValueAlone(t *testing.T) {
	res, unread := hostile()
	wantName, wantAlias, wantPath := res.Findings[0].Package.Name, res.Findings[0].Advisory.Aliases[0], unread[0].Path

	safe, safeUnread := terminalSafe(res), terminalSafe(unread)
	if strings.Contains(safe.Findings[0].Package.Name, esc) || strings.Contains(safe.Findings[0].Advisory.Aliases[0], esc) ||
		strings.Contains(safe.Suppressed[0].Finding.Waived[0].Reason, esc) || strings.Contains(safeUnread[0].Path, esc) {
		t.Errorf("the copy still carries a raw ESC: %+v", safe.Findings[0])
	}
	if res.Findings[0].Package.Name != wantName || res.Findings[0].Advisory.Aliases[0] != wantAlias || unread[0].Path != wantPath {
		t.Error("terminalSafe changed the value it was given")
	}
}
