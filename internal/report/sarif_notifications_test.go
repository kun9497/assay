package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/version"
)

// P4 of the 2026-11-20 audit: the invocation's notifications carry the two
// no-fix counts, and each cataloger skip (D158) with its level.
func TestSARIF_NotificationsCarryTheNoFixCountsAndCatalogerSkips(t *testing.T) {
	f := func(id string, state advisory.FixState) matcher.Finding {
		return matcher.Finding{
			Package:  pkgmeta.Package{Name: "x", Version: "1", Ecosystem: "Red Hat:9"},
			Advisory: advisory.Advisory{ID: id}, Evidence: version.Evidence{Introduced: "0", FixState: state},
			Ratings: []matcher.Rating{{AdvisoryID: id, FixState: state}},
		}
	}
	res := matcher.Result{Findings: []matcher.Finding{f("A-1", advisory.FixStateNotFixed), f("A-2", advisory.FixStateNotFixed), f("A-3", advisory.FixStateWontFix)}}
	var buf bytes.Buffer
	if _, err := SARIF(&buf, res, cyclonedx.Stats{Components: 3, Cataloged: 1, SkippedNoVersion: 1, SkippedNoPURL: 1}, nil, "t", "v", EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID, Level string
				Message       struct{ Text string }
			}
			Invocations []struct {
				ToolExecutionNotifications []struct {
					Level   string
					Message struct{ Text string }
				}
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	notes := doc.Runs[0].Invocations[0].ToolExecutionNotifications
	if !strings.HasSuffix(notes[0].Message.Text, " 3 with no fix available (1 will not be fixed)") {
		t.Errorf("summary %q", notes[0].Message.Text)
	}
	skips := 0
	for _, r := range doc.Runs[0].Results {
		if r.RuleID != "assay/not-evaluated" {
			continue
		}
		skips++
		n := 0
		for _, note := range notes[1:] {
			if note.Level == r.Level && note.Message.Text == r.Message.Text {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q has %d notifications, want 1", r.Message.Text, n)
		}
	}
	if skips != 2 {
		t.Errorf("%d not-evaluated results, want 2", skips)
	}
}
