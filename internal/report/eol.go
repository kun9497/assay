package report

import "fmt"

// EOLStatus is what scancmd found about the scanned target's distro
// release's end-of-life state (D87) — a SCAN-TIME derived fact (today's
// date against the database's stored EOLFrom), never something
// pkgmeta.Target itself carries. Computed once in scancmd.Run and threaded
// into whichever renderer actually runs, so Table, JSON and SARIF cannot
// silently disagree about what the scan found.
type EOLStatus struct {
	// Known is false when there is nothing to answer with at all: the
	// target carries no distro identity, its release is not one the
	// database's EOL data covers, or the database carries no EOL data at
	// all. No renderer may print anything about EOL when this is false —
	// the D87 rule is never a silent skip and never a false trip, and a
	// renderer inventing a "not EOL" line from an unanswered lookup would
	// be exactly the false trip half of that.
	Known bool
	// Reason names why Known is false. Renderers ignore it — it exists for
	// scancmd's own --fail-on-eol disclosure, not for display, since the
	// three unanswerable shapes (no distro, unrecognized release, no EOL
	// data) call for a stderr warning, not a report line.
	Reason string

	DistroID string
	Release  string
	// EOL is whether TODAY is strictly after EOLFrom — endoflife.date's own
	// isEol semantics (its boundary is exclusive: a release is not EOL on
	// the day named by EOLFrom itself, only the day after) — computed here
	// rather than trusted from a stored boolean, because store.EOLRelease
	// deliberately carries no isEol field at all (its own doc comment: that
	// boolean is fixed at db-build time and goes stale the moment the
	// database outlives the day it was built).
	EOL      bool
	EOLFrom  string
	EOLLabel string
	// StillMaintained is IsMaintained as endoflife.date published it (D13:
	// trusted, not re-derived — store.EOLRelease's own doc comment), OR an
	// EOESFrom date that has not itself passed yet. Either is enough: the
	// Debian-LTS shape D87 exists for is bookworm, EOL yet still under LTS,
	// and a reader needs the "still maintained, under what name, until
	// when" fact right beside "reached end of life" or EOL alone misreads
	// as abandoned when it is not.
	StillMaintained bool
	EOESFrom        string
	EOESLabel       string
}

// Line renders the table's one-line EOL disclosure, and reports whether
// there is anything to print — a caller must not print when ok is false,
// whether because Known is false (nothing to say) or EOL is false (the
// release is current and the table stays silent about it, D87's own "one
// line only when EOL" rule).
func (s EOLStatus) Line() (line string, ok bool) {
	if !s.Known || !s.EOL {
		return "", false
	}
	label := s.EOLLabel
	if label == "" {
		label = "support"
	}
	line = fmt.Sprintf("EOL: %s %s reached end of %s on %s", s.DistroID, s.Release, label, s.EOLFrom)
	if s.StillMaintained {
		mLabel := s.EOESLabel
		if mLabel == "" {
			mLabel = "extended support"
		}
		if s.EOESFrom != "" {
			line += fmt.Sprintf("; still under %s until %s", mLabel, s.EOESFrom)
		} else {
			line += fmt.Sprintf("; still under %s", mLabel)
		}
	}
	return line, true
}

// EOLRecord is Document's target-level end-of-life object (D87). A pointer
// field on Document, present only when the scan found an answer: nil says
// nothing rather than a false "not EOL" when the target carries no distro
// identity, its release is not one the database covers, or the database has
// no EOL data at all — the same "never a silent skip" rule store.Meta.EOL's
// own doc comment states, carried through to the JSON document.
//
// Unlike the table's Line(), this is present whether or not EOL is true: a
// consumer scripting against the JSON document (e.g. "warn me when a target
// is within a year of EOL") needs the not-yet-EOL answer too, which a
// human-facing table line has no use printing.
type EOLRecord struct {
	DistroID string `json:"distroId"`
	Release  string `json:"release"`
	EOL      bool   `json:"eol"`
	EOLFrom  string `json:"eolFrom"`
	EOLLabel string `json:"eolLabel"`
	// StillMaintained, EOESFrom and EOESLabel are the Debian-LTS shape
	// EOLStatus.StillMaintained's own doc comment describes. No omitempty
	// on StillMaintained (false is a statement, same convention every other
	// bool on this document follows); EOESFrom/EOESLabel DO omit empty,
	// because most distros have no such phase at all (Alpine, Rocky,
	// AlmaLinux, Amazon Linux, Fedora), and an empty pair there is a fact
	// about the DISTRO, not about this particular scan.
	StillMaintained bool   `json:"stillMaintained"`
	EOESFrom        string `json:"eoesFrom,omitempty"`
	EOESLabel       string `json:"eoesLabel,omitempty"`
}

// Record builds Document's target-level eol object, or nil when Known is
// false — see EOLRecord's own doc comment for why nil, not a zero-value
// object, is what "no answer" must serialize as.
func (s EOLStatus) Record() *EOLRecord {
	if !s.Known {
		return nil
	}
	return &EOLRecord{
		DistroID:        s.DistroID,
		Release:         s.Release,
		EOL:             s.EOL,
		EOLFrom:         s.EOLFrom,
		EOLLabel:        s.EOLLabel,
		StillMaintained: s.StillMaintained,
		EOESFrom:        s.EOESFrom,
		EOESLabel:       s.EOESLabel,
	}
}

// Properties builds the SARIF invocation-level properties bag entry, or nil
// when Known is false — sarifInvocation.Properties' own "properties,
// omitempty" tag then drops the key entirely, the SARIF-native way of
// saying nothing rather than a false "not EOL" claim (Record()'s own
// reasoning, one renderer over).
//
// Nested under one "eol" key rather than several top-level ones: an
// invocation's properties bag is shared ground with anything else that
// ever needs to say something at that level, and a flat "eolFrom"/
// "release" pair would collide with a same-named key some future addition
// wants for an unrelated fact.
func (s EOLStatus) Properties() map[string]any {
	if !s.Known {
		return nil
	}
	eol := map[string]any{
		"distroId": s.DistroID,
		"release":  s.Release,
		"eol":      s.EOL,
	}
	// The rest is meaningful only once EOL is true, on Record()'s own
	// omitempty reasoning for EOESFrom/EOESLabel one level up: a current
	// release has no "reached end of X on Y" to state.
	if s.EOL {
		eol["eolFrom"] = s.EOLFrom
		eol["eolLabel"] = s.EOLLabel
		eol["stillMaintained"] = s.StillMaintained
		if s.EOESFrom != "" {
			eol["eoesFrom"] = s.EOESFrom
		}
		if s.EOESLabel != "" {
			eol["eoesLabel"] = s.EOESLabel
		}
	}
	return map[string]any{"eol": eol}
}
