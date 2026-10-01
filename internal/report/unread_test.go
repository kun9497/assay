package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/dirscan"
	"github.com/kun9497/assay/internal/matcher"
)

// D109's renderer-level branches the scancmd caller tests cannot reach. Chief
// among them is (e): no dirscan code path produces a Failed: false entry today
// (requirements.txt is read since D38), so the rule that "we did not look"
// stays out of both the count and the gate can only be held here.
//
// Fixture values are chosen not to collide as substrings: neither path nor
// reason appears inside the other, nor in anything else a renderer prints.
var (
	failedUnread = dirscan.Unread{Path: "ui-bundle/package-lock.json", Reason: "truncated-lockfile-xyz", Failed: true}
	// deliberate is the requirements.txt-class entry: recognized, and not
	// looked at by design.
	deliberate = dirscan.Unread{Path: "deliberately-skipped.txt", Reason: "deliberate-parser-limit", Failed: false}
	cleanCat   = cyclonedx.Stats{Components: 1, Cataloged: 1}
	// nl is a newline, assembled rather than typed (CLAUDE.md's escape
	// sequence hazard).
	nl = string(rune(10))
)

func TestSummarize_D109_OnlyFailedUnreadCounts(t *testing.T) {
	cases := []struct {
		name       string
		unread     []dirscan.Unread
		wantUnread int
		wantTarget int
	}{
		{"nil", nil, 0, 0},
		{"a deliberate skip alone counts toward neither", []dirscan.Unread{deliberate}, 0, 0},
		{"a failure counts toward both", []dirscan.Unread{failedUnread}, 1, 1},
		{"mixed: only the failure counts", []dirscan.Unread{deliberate, failedUnread}, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum := Summarize(matcher.Result{}, cleanCat, tc.unread, Coverage{})
			if sum.UnreadManifests != tc.wantUnread {
				t.Errorf("UnreadManifests = %d, want %d", sum.UnreadManifests, tc.wantUnread)
			}
			if sum.TargetIncomplete != tc.wantTarget {
				t.Errorf("TargetIncomplete = %d, want %d", sum.TargetIncomplete, tc.wantTarget)
			}
			// Counted apart: an unread manifest yields no component, so it
			// must not move the evaluated/not-evaluated split.
			if sum.NotEvaluated != 0 || sum.Evaluated != 1 {
				t.Errorf("Evaluated/NotEvaluated = %d/%d, want 1/0", sum.Evaluated, sum.NotEvaluated)
			}
		})
	}

	// Added to, not replacing, the cataloger's own target skips (D38).
	sum := Summarize(matcher.Result{}, cyclonedx.Stats{Components: 3, Cataloged: 1, SkippedNoVersion: 2},
		[]dirscan.Unread{failedUnread}, Coverage{})
	if sum.TargetIncomplete != 3 {
		t.Errorf("TargetIncomplete = %d, want 3 (2 unversioned + 1 unread)", sum.TargetIncomplete)
	}
}

func TestJSON_D109_UnreadArray(t *testing.T) {
	t.Run("always present, [] when nothing went unread", func(t *testing.T) {
		var buf bytes.Buffer
		if _, err := JSON(&buf, matcher.Result{}, cleanCat, nil, EOLStatus{}, Coverage{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), `"unread": []`) {
			t.Errorf("unread is absent or null rather than []:\n%s", buf.String())
		}
		if !strings.Contains(buf.String(), `"unreadManifests": 0`) {
			t.Errorf("summary.unreadManifests is absent at zero:\n%s", buf.String())
		}
	})

	t.Run("a deliberate skip stays out", func(t *testing.T) {
		var buf bytes.Buffer
		if _, err := JSON(&buf, matcher.Result{}, cleanCat, []dirscan.Unread{deliberate, failedUnread}, EOLStatus{}, Coverage{}); err != nil {
			t.Fatal(err)
		}
		var doc Document
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		want := UnreadRecord{Path: failedUnread.Path, Reason: failedUnread.Reason}
		if len(doc.Unread) != 1 || doc.Unread[0] != want {
			t.Errorf("unread = %+v, want only %+v", doc.Unread, want)
		}
		if doc.Summary.UnreadManifests != 1 || doc.Summary.TargetIncomplete != 1 {
			t.Errorf("summary unreadManifests/targetIncomplete = %d/%d, want 1/1",
				doc.Summary.UnreadManifests, doc.Summary.TargetIncomplete)
		}
		if strings.Contains(buf.String(), deliberate.Path) {
			t.Errorf("the deliberate skip reached the document:\n%s", buf.String())
		}
	})
}

func TestTable_D109_NotReadBlock(t *testing.T) {
	t.Run("a deliberate skip is neither listed nor counted", func(t *testing.T) {
		var buf bytes.Buffer
		if _, err := Table(&buf, matcher.Result{}, cleanCat, []dirscan.Unread{deliberate}, EOLStatus{}, Coverage{}, false); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "not read") || strings.Contains(buf.String(), deliberate.Path) {
			t.Errorf("a deliberate skip reached the table:\n%s", buf.String())
		}
	})

	// D107: colors must not touch these lines, so piped and TTY output agree
	// on them byte for byte.
	t.Run("the same bytes with and without color", func(t *testing.T) {
		line := "not read: " + failedUnread.Path + " (" + failedUnread.Reason + ")" + nl
		for _, colorize := range []bool{false, true} {
			var buf bytes.Buffer
			if _, err := Table(&buf, matcher.Result{}, cleanCat, []dirscan.Unread{failedUnread}, EOLStatus{}, Coverage{}, colorize); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(buf.String(), nl+line) {
				t.Errorf("colorize=%v: the table does not end with a blank line then %q:\n%q", colorize, line, buf.String())
			}
			if !strings.Contains(buf.String(), ", 1 manifest(s) not read"+nl) {
				t.Errorf("colorize=%v: the summary line does not count it:\n%s", colorize, buf.String())
			}
		}
	})
}

type d109SARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results     []sarifResult     `json:"results"`
		Invocations []sarifInvocation `json:"invocations"`
	} `json:"runs"`
}

func renderSARIF(t *testing.T, unread []dirscan.Unread) d109SARIF {
	t.Helper()
	var buf bytes.Buffer
	if _, err := SARIF(&buf, matcher.Result{}, cleanCat, unread, "dir:.", "v0", EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	var doc d109SARIF
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || len(doc.Runs) != 1 {
		t.Fatalf("not a one-run SARIF document (%v):\n%s", err, buf.String())
	}
	return doc
}

func TestSARIF_D109_NotRead(t *testing.T) {
	t.Run("no result, no rule", func(t *testing.T) {
		run := renderSARIF(t, []dirscan.Unread{deliberate}).Runs[0]
		for _, r := range run.Tool.Driver.Rules {
			if r.ID == notReadRuleID {
				t.Errorf("assay/not-read declared with no result naming it")
			}
		}
		for _, r := range run.Results {
			if r.RuleID == notReadRuleID {
				t.Errorf("a deliberate skip became a not-read result: %+v", r)
			}
		}
		if lvl := run.Invocations[0].ToolExecutionNotifications[0].Level; lvl != "note" {
			t.Errorf("summary notification level = %q, want note on a clean run", lvl)
		}
	})

	t.Run("one result, fingerprinted on the path", func(t *testing.T) {
		run := renderSARIF(t, []dirscan.Unread{failedUnread}).Runs[0]
		var got []sarifResult
		for _, r := range run.Results {
			if r.RuleID == notReadRuleID {
				got = append(got, r)
			}
		}
		if len(got) != 1 {
			t.Fatalf("%d not-read results, want 1", len(got))
		}
		r := got[0]
		wantMsg := failedUnread.Path + " could not be read: " + failedUnread.Reason
		if r.Message.Text != wantMsg {
			t.Errorf("message = %q, want %q", r.Message.Text, wantMsg)
		}
		if fp := r.PartialFingerprints[fingerprintKey]; fp != hash(notReadRuleID, failedUnread.Path) {
			t.Errorf("fingerprint = %q, want hash(rule id, path)", fp)
		}
		if loc := r.Locations[0].PhysicalLocation; loc.Region != nil {
			t.Errorf("a not-read location carries a region %+v; the path may be a directory", loc.Region)
		}
		// The notification half, for a consumer that honours the spec, and the
		// summary level lifted to warning.
		notes := run.Invocations[0].ToolExecutionNotifications
		if notes[0].Level != "warning" {
			t.Errorf("summary notification level = %q, want warning", notes[0].Level)
		}
		found := false
		for _, n := range notes[1:] {
			if n.Message.Text == wantMsg {
				found = true
			}
		}
		if !found {
			t.Errorf("no toolExecutionNotification carries %q: %+v", wantMsg, notes)
		}
	})
}
