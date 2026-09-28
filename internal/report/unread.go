package report

import "github.com/kun9497/assay/internal/cataloger/dirscan"

// UnreadRecord is one manifest a directory scan found and could not read
// (D109): a lockfile whose parser refused it, or a subtree the walk could not
// enter (#136). Path is relative to the scanned root and slash-separated, as
// dirscan produces it; Reason is the parser's or the operating system's own
// words, because the action is per file and a reader needs the why to take it.
//
// A plain struct rather than dirscan.Unread marshaled directly, on
// FindingRecord's reasoning: a field that type gains for an unrelated reason
// must not silently change this document. Failed is not carried either - only
// Failed entries reach this type at all (unreadRecords).
type UnreadRecord struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// unreadRecords keeps only the Failed entries and reshapes them. It is the one
// place the Failed/not-Failed line is drawn for every renderer and for
// Summarize, so the JSON array, the SARIF results, the table block and the
// count behind --fail-on-incomplete=target cannot disagree about which entries
// count.
//
// Failed: false is "we did not look" - a deliberate parser limit, the
// requirements.txt class - and D109 keeps it out: it is not the target's
// state, and no action the caller takes on their own file changes it.
//
// Always non-nil, so Document.Unread encodes as [] rather than null when
// nothing went unread, the same discipline Skipped and Suppressed follow.
func unreadRecords(unread []dirscan.Unread) []UnreadRecord {
	out := make([]UnreadRecord, 0, len(unread))
	for _, u := range unread {
		if !u.Failed {
			continue
		}
		out = append(out, UnreadRecord{Path: u.Path, Reason: u.Reason})
	}
	return out
}
