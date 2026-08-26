package scancmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// clockNow is the seam for "today" (D87): EOL is derived by comparing the
// database's stored EOLFrom against the moment the scan runs, never a
// boolean trusted from the database itself (store.EOLRelease's own doc
// comment explains why: isEol is computed at db-build time and goes stale
// the moment the database outlives the day it was built). A test pins this
// to drive both sides of the boundary without waiting for a real date to
// pass.
var clockNow = time.Now

// eolCycle parses the RELEASE portion back out of an already-computed OSV
// ecosystem key ("Alpine:v3.19", "Ubuntu:22.04:LTS", "Red Hat:9", "Amazon
// Linux:2", "SLES:15.SP6", ...) rather than re-truncating
// pkgmeta.Distro.VersionID a second time.
//
// The two reads must not be independent: pkgmeta.Distro.Ecosystem() already
// decided exactly how much of VersionID survives into the key (D6) — Alpine
// keeps the dotted minor with a "v" prefix, Ubuntu appends ":LTS", RHEL/
// Rocky/AlmaLinux/Oracle Linux truncate to the bare major, and Amazon Linux/
// Fedora/SLES/openSUSE Leap keep VersionID's own shape verbatim. A second,
// independent truncation here could silently drift from that decision the
// day either side changes; parsing the same string Ecosystem() already
// produced is the only way the two cannot disagree.
//
// SLES is the one family whose key suffix needs reshaping, not just
// trimming: Ecosystem() folds VERSION_ID 15.6 into "SLES:15.SP6" (D77's
// key convention), while endoflife.date names the same release "15.6" — so
// ".SP" maps back to "." here, and the SP0 shape ("SLES:15", no dot)
// resolves as "15.0", which is endoflife.date's own name for the GA
// release. SLES 16+ keys keep VersionID verbatim and pass through.
func eolCycle(ecosystem string) (cycle string, ok bool) {
	_, rest, found := strings.Cut(ecosystem, ":")
	if !found || rest == "" {
		return "", false
	}
	// Ubuntu's ":LTS" is the only family with a second colon (D53); cutting
	// again is a no-op for every other family, since none of their release
	// suffixes contain ":" at all.
	release, _, _ := strings.Cut(rest, ":")
	if release == "" {
		return "", false
	}
	// Alpine is the one family whose release keeps a "v" that
	// endoflife.date's own release.name never carries ("v3.19" vs "3.19") —
	// every other family's suffix already matches endoflife.date verbatim.
	release = strings.TrimPrefix(release, "v")
	if strings.HasPrefix(ecosystem, "SLES:") {
		if i := strings.Index(release, ".SP"); i >= 0 {
			release = release[:i] + "." + release[i+3:]
		} else if !strings.Contains(release, ".") {
			release += ".0"
		}
	}
	// D96: Photon OS's own ecosystem key truncates VERSION_ID to the bare
	// major (pkgmeta.Distro.Ecosystem's "photon" case, following the D71/
	// D72/D94 shape) because that is the granularity Photon's own CVE feed
	// publishes at -- one file per major, never per minor. endoflife.date
	// names the SAME releases with the trailing ".0" kept ("3.0", "4.0",
	// "5.0", verified live 2026-08-26), the identical mismatch SLES's own
	// bare-major GA release has against "15.0" above. The fix is the same
	// shape: append ".0" when the key carried no dot, reshaping at the READ
	// side rather than widening the ecosystem key itself (which would
	// require every advisory range in the store to carry the redundant
	// ".0" too, for a key Photon never needs it for otherwise).
	if strings.HasPrefix(ecosystem, "Photon OS:") && !strings.Contains(release, ".") {
		release += ".0"
	}
	return release, true
}

// lookupEOL derives the scanned target's end-of-life status against now
// (scancmd.Run passes clockNow()), or explains why there is no answer —
// D87's three unanswerable shapes: no distro identity at all, a release
// this build's Ecosystem()/eolCycle cannot key, or a database that carries
// no EOL data (nil, whether because it predates D87 or was built with
// EOL_ENABLE=0).
//
// eolRows is Meta.EOL as read from the database that produced res — passed
// in rather than re-opened, since Run already has it open for the match
// itself.
func lookupEOL(distro *pkgmeta.Distro, eolRows []store.EOLRelease, now time.Time) report.EOLStatus {
	if distro == nil {
		return report.EOLStatus{Reason: "this target carries no distro identity"}
	}
	ecosystem, err := distro.Ecosystem()
	if err != nil {
		return report.EOLStatus{Reason: fmt.Sprintf(
			"distro %q release %q is not one this build recognizes: %v", distro.ID, distro.VersionID, err)}
	}
	cycle, ok := eolCycle(ecosystem)
	if !ok {
		return report.EOLStatus{Reason: fmt.Sprintf(
			"could not derive an end-of-life release cycle from ecosystem key %q", ecosystem)}
	}
	if eolRows == nil {
		return report.EOLStatus{Reason: "this database carries no end-of-life data; run `assay db update`"}
	}
	for _, row := range eolRows {
		if row.DistroID != distro.ID || row.Release != cycle {
			continue
		}
		return eolStatusFromRow(row, now)
	}
	return report.EOLStatus{Reason: fmt.Sprintf(
		"no end-of-life data for distro %q release %q", distro.ID, cycle)}
}

// dateLayout is every date field store.EOLRelease carries — endoflife.date
// publishes plain "YYYY-MM-DD" with no time or zone component.
const dateLayout = "2006-01-02"

// eolStatusFromRow turns one matched store.EOLRelease into a
// report.EOLStatus, deriving EOL and the still-maintained fact against now
// rather than trusting anything the row precomputed (row.IsMaintained is
// the one exception, trusted as published — see report.EOLStatus's own
// doc comment on StillMaintained for why that field specifically is sound
// to trust where isEol is not).
func eolStatusFromRow(row store.EOLRelease, now time.Time) report.EOLStatus {
	st := report.EOLStatus{
		Known: true, DistroID: row.DistroID, Release: row.Release,
		EOLFrom: row.EOLFrom, EOLLabel: row.EOLLabel,
		EOESFrom: row.EOESFrom, EOESLabel: row.EOESLabel,
	}
	if eolDate, perr := time.Parse(dateLayout, row.EOLFrom); perr == nil {
		// Strictly after: endoflife.date's own isEol semantics are
		// exclusive of the day EOLFrom itself names (measured against the
		// live API 2026-08-21, which does not flip isEol until the day
		// after eolFrom).
		st.EOL = now.After(eolDate)
	}
	// An unparseable or empty EOLFrom leaves st.EOL false (this cycle's
	// EOLFrom was never published, or endoflife.date's shape changed) —
	// the same "absent stays absent" discipline the rest of this project
	// applies to a missing fact, never a fabricated EOL date.
	eoesUnexpired := false
	if eoesDate, perr := time.Parse(dateLayout, row.EOESFrom); perr == nil {
		eoesUnexpired = now.Before(eoesDate)
	}
	st.StillMaintained = row.IsMaintained || eoesUnexpired
	return st
}
