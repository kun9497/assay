// Ubuntu fix-state stamping (D85). Canonical's own tracker knows the
// difference between "affected, no fix" and "the vendor decided not to fix
// this", and the OSV Ubuntu export does not carry it — every fix-less Ubuntu
// range comes out of record.go's convert() as advisory.FixStateUnknown. This
// file builds the (CVE, source package, release) -> {state, reason} lookup
// from a local clone of https://git.launchpad.net/ubuntu-cve-tracker (see
// ubuntu_spool.go for the clone/fetch step) and stamps convert()'s output
// from it, mirroring redhat/csaf.go's fixStateFor exactly: a small, closed
// vocabulary resolves to a FixState, and everything outside it means
// "nothing to stamp" rather than a guess (D52's rule, applied to a second
// source).
package osv

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// ubuntuCodenameRelease maps a bare mainline codename to the YY.MM release
// string OSV's own ecosystem keys carry (D6/D53's mainlineUbuntuKey). Not
// exhaustive by intent: every LTS back to the oldest release D53 itself
// tests (trusty, 14.04) plus the interim releases confirmed live in the
// tracker's own tree on 2026-08-21 -- oracular, plucky and questing per the
// design brief, and resolute alongside them, confirmed by
// esm-apps-resolute-supported.txt existing in that same tree listing (one
// letter past questing, and the samples show real package data against it --
// "resolute_pcre3: DNE", "resolute_openssl: released (3.0.8-1ubuntu2)" --
// not the placeholder shape an unreleased codename would have).
//
// An EOL'd interim (kinetic, lunar, mantic, ...) deliberately has no entry.
// No image this project can evaluate reports one of those as its release --
// pkgmeta.Distro.Ecosystem only ever resolves a VERSION_ID that exists on a
// running system -- so a stanza line naming one becomes an "unknown
// codename" tuple: counted by parseUbuntuTrackerFile, and harmless. The same
// choice D75 made for Fedora's own EOL'd releases.
var ubuntuCodenameRelease = map[string]string{
	"trusty":   "14.04",
	"xenial":   "16.04",
	"bionic":   "18.04",
	"focal":    "20.04",
	"jammy":    "22.04",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
	"questing": "25.10",
	"resolute": "26.04",
}

// ubuntuTrackerLineRe matches one stanza line naming a BARE mainline release
// -- "jammy_coreutils: ignored (end of standard support)". The anchor is
// what drops every lineage-prefixed row (D53) without a separate blacklist:
// "esm-infra/xenial_pcre3: ignored" fails to match at position 0 because the
// character after the longest run of [a-z] ("esm") is '-', not '_', and a
// Go regexp anchored with ^ never retries from a later position. The same
// reasoning drops "trusty/esm_coreutils", "fips-updates/jammy_openssl", and
// every other lineage spelling measured in the live export.
//
// The package-name group accepts the Debian source-package charset (digits,
// '+', '.', '-') because real names use all four -- "openssl1.0", "edk2",
// "pcre3". The state group is an unconstrained token rather than an
// enumerated alternation: ubuntuFixState is where the vocabulary is closed,
// so a tracker word this build does not recognize is a "nothing to stamp"
// tuple rather than a parse failure.
var ubuntuTrackerLineRe = regexp.MustCompile(`^([a-z]+)_([A-Za-z0-9][A-Za-z0-9+.-]*): (\S+)(?: \((.*)\))?$`)

// ubuntuTrackerCandidateRe reads the file's own "Candidate: CVE-2016-2781"
// line -- the authoritative CVE for every stanza line in the file, read from
// content rather than trusted from the filename, so a renamed or
// oddly-cased file still resolves correctly.
var ubuntuTrackerCandidateRe = regexp.MustCompile(`^Candidate:\s*(CVE-[0-9]{4}-[0-9]+)\s*$`)

// ubuntuCVERe recognizes a CVE identifier inside Advisory.Upstream (D3: OSV
// puts the CVE link there for a distro-authored record, not in Aliases).
// Measured 2026-08-10: 99.99% of Ubuntu records carry one; a record with
// none simply has nothing to stamp against, which firstUbuntuCVE's ok=false
// return already handles.
var ubuntuCVERe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)

// ubuntuMainlineReleaseRe pulls the YY.MM release back out of a mainline
// Ubuntu ecosystem key ("Ubuntu:22.04:LTS" or "Ubuntu:25.10"). A deliberate
// duplicate of mainlineUbuntuKey's own shape rather than a shared constant,
// for the identical reason mainlineUbuntuKey's own comment gives for not
// importing internal/version's copy: this decides what gets STAMPED, that
// one decides what gets STORED, and either could move without the other.
var ubuntuMainlineReleaseRe = regexp.MustCompile(`^Ubuntu:([0-9]{2}\.[0-9]{2})(?::LTS)?$`)

// ubuntuTrackerKey identifies one (CVE, source package, release) tuple --
// the exact granularity a tracker stanza line names, and the granularity
// convert() looks up at: a fix-less advisory.Range already knows its own
// ecosystem (hence release) and its Affected entry's own Name (already the
// source package for Ubuntu, per D8 -- OSV's Ubuntu affected[].name is
// authored against source packages, unlike an installed binary package).
type ubuntuTrackerKey struct {
	cve, pkg, release string
}

// ubuntuTrackerEntry is one tuple's raw tracker state, kept exactly as
// parsed. reason is carried here and nowhere further: see ubuntuFixState's
// own comment for why it never reaches advisory.Range, the same way Red
// Hat's own remediation category text never does.
type ubuntuTrackerEntry struct {
	state  string
	reason string
}

// ubuntuTracker is the lookup convert() stamps from. A nil *ubuntuTracker is
// a valid, always-empty one -- every caller that has not fetched or does not
// want the tracker (UBUNTU_TRACKER_ENABLE=0, or any pre-D85 test) passes nil
// straight through to stampUbuntuFixState, which must do nothing rather than
// panic.
type ubuntuTracker struct {
	entries map[ubuntuTrackerKey]ubuntuTrackerEntry
}

func newUbuntuTracker() *ubuntuTracker {
	return &ubuntuTracker{entries: map[ubuntuTrackerKey]ubuntuTrackerEntry{}}
}

func (t *ubuntuTracker) lookup(cve, pkg, release string) (ubuntuTrackerEntry, bool) {
	if t == nil {
		return ubuntuTrackerEntry{}, false
	}
	e, ok := t.entries[ubuntuTrackerKey{cve: cve, pkg: pkg, release: release}]
	return e, ok
}

// ubuntuStanza is one parsed line, before its codename has been resolved (or
// rejected) against ubuntuCodenameRelease.
type ubuntuStanza struct {
	release, pkg, state, reason string
}

// parseUbuntuTrackerLine parses one line of a tracker file body. Every other
// line in a real file (References, Description, Notes, Priority, CVSS
// vectors, blank lines, "Patches_pkg:" headers) simply fails to match and is
// ignored -- this function is a filter, not a line-type classifier.
func parseUbuntuTrackerLine(line string) (ubuntuStanza, bool) {
	m := ubuntuTrackerLineRe.FindStringSubmatch(line)
	if m == nil {
		return ubuntuStanza{}, false
	}
	return ubuntuStanza{release: m[1], pkg: m[2], state: m[3], reason: m[4]}, true
}

// parseUbuntuTrackerFile parses one CVE file's whole body into tracker,
// returning false when the file carries no readable "Candidate:" line (a
// malformed or unexpected file, counted by the caller as UbuntuFilesUnparsed
// rather than failing the whole build over one bad file the way a corrupted
// zip entry would for an OSV archive -- this is a git working tree with
// thousands of independently-authored files, not one atomic download).
//
// Stanza lines are buffered until the Candidate: line is found, rather than
// requiring it to appear first: every sample measured 2026-08-10 puts it on
// line 2, but nothing in the tracker's own format guarantees the order, and
// buffering costs nothing a CVE file's size (a few KB) would notice.
func parseUbuntuTrackerFile(data []byte, tracker *ubuntuTracker, st *stats) bool {
	var cve string
	var stanzas []ubuntuStanza
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if m := ubuntuTrackerCandidateRe.FindStringSubmatch(line); m != nil {
			cve = m[1]
			continue
		}
		if s, ok := parseUbuntuTrackerLine(line); ok {
			stanzas = append(stanzas, s)
		}
	}
	if cve == "" {
		return false
	}
	for _, s := range stanzas {
		release, ok := ubuntuCodenameRelease[s.release]
		if !ok {
			if st != nil {
				st.UbuntuUnknownCodename++
			}
			continue
		}
		tracker.entries[ubuntuTrackerKey{cve: cve, pkg: s.pkg, release: release}] =
			ubuntuTrackerEntry{state: s.state, reason: s.reason}
		if st != nil {
			st.UbuntuTuplesLoaded++
		}
	}
	return true
}

// parseUbuntuTracker walks active/ and retired/ under dir as ONE namespace
// (D85's brief: a CVE migrates between the two as it ages out of support,
// and a lookup must resolve identically from either). Either directory
// missing entirely is tolerated rather than fatal -- a shallow clone still
// under its first sync, or a future reorganisation of the tracker's own
// layout, should degrade to "fewer tuples loaded" rather than fail the whole
// database build; the archive-yielded-zero guard pattern used elsewhere
// (Fetch's own eco == "Alpine" check) is deliberately NOT copied here
// because zero tuples is not silent the way zero Alpine records would be --
// db status's coverage line says nothing about Ubuntu fix-state at all
// today, and the progress line this parse prints (loadUbuntuTracker) is
// unconditional, so a walk that found nothing is visible in the build log
// either way.
func parseUbuntuTracker(dir string, st *stats) (*ubuntuTracker, error) {
	tracker := newUbuntuTracker()
	for _, sub := range []string{"active", "retired"} {
		root := filepath.Join(dir, sub)
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("ubuntu tracker: read %s: %w", root, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(root, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("ubuntu tracker: read %s: %w", path, err)
			}
			if !parseUbuntuTrackerFile(data, tracker, st) && st != nil {
				st.UbuntuFilesUnparsed++
			}
		}
	}
	return tracker, nil
}

// ubuntuFixState maps one tracker state word to a FixState, the Ubuntu
// analogue of redhat/csaf.go's fixStateFor. Red Hat's remediation category
// IS the reason a package has no fix, and it is never stored as prose --
// only the FixState it resolves to (fixStateFor's own comment: "Red Hat said
// the package is affected and gave no reason ... left unstated rather than
// guessed at"). The tracker's parenthesized reason text gets the identical
// treatment here: parsed (parseUbuntuTrackerLine), kept on ubuntuTrackerEntry
// for this function's caller to look at, and never carried onto
// advisory.Range -- mirroring EXACTLY where redhat/csaf.go ~702-707 sets
// FixState on a fix-less range and nothing else.
//
// One real divergence from Red Hat, and it is why this function ignores
// entry.reason entirely rather than requiring one: stats.UnfixableUnstated is
// zero across Red Hat's whole archive (every one of its 1,282,093 unfixable
// tuples names a remediation category), while the tracker's own reason is
// absent on most `ignored` rows -- 5,352 bare vs 194 with prose, measured
// 2026-08-10. Requiring a reason before trusting the classification would
// silently narrow wont-fix to the minority of rows that happen to carry
// prose. The classification comes from the STATE WORD, not from whether a
// human explained it, so an empty reason classifies exactly as fast as a
// written one.
func ubuntuFixState(state string) (advisory.FixState, bool) {
	switch state {
	case "ignored":
		return advisory.FixStateWontFix, true
	case "needed", "needs-triage", "pending", "deferred":
		return advisory.FixStateNotFixed, true
	default:
		// released, DNE, not-affected, or any word this build does not
		// recognize: nothing to stamp, exactly as Red Hat's own default case
		// leaves FixStateUnknown in place rather than guessing (D17's rule
		// for absent severity, applied here to absent intent).
		return "", false
	}
}

// rangeIsFixless reports whether rng has no `fixed` event -- the same shape
// OSV and redhat/csaf.go both use to say "affected at every version": a
// range with a Fixed event is fixed by construction (D52), so FixState is
// stored only on the ones without one.
func rangeIsFixless(rng advisory.Range) bool {
	for _, ev := range rng.Events {
		if ev.Fixed != "" {
			return false
		}
	}
	return true
}

// ubuntuReleaseFromEcosystem pulls the YY.MM release out of a mainline
// Ubuntu ecosystem key, or reports false for anything else -- including
// every non-Ubuntu ecosystem convert() ever sees, which is what lets
// stampUbuntuFixState be called unconditionally per Affected entry without a
// separate "is this Ubuntu" guard at the call site.
func ubuntuReleaseFromEcosystem(eco string) (string, bool) {
	m := ubuntuMainlineReleaseRe.FindStringSubmatch(eco)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// firstUbuntuCVE returns the first CVE-shaped identifier in ids (Upstream,
// per D3), or false when none is present -- the 0.01% of Ubuntu records
// measured with no CVE linkage at all, which have nothing for
// stampUbuntuFixState to key a lookup on.
func firstUbuntuCVE(ids []string) (string, bool) {
	for _, id := range ids {
		if ubuntuCVERe.MatchString(id) {
			return id, true
		}
	}
	return "", false
}

// stampUbuntuFixState is D85's seam into convert(): called once per Affected
// entry, it stamps every fix-less range that the tracker names with a
// wont-fix or not-fixed tuple. tracker may be nil (lookup already handles
// that) and cve may be empty (checked here, since ubuntuTrackerKey has no
// concept of "no CVE" to fail a lookup against on its own).
//
// The state rides on the RANGE, never the Affected entry or the Advisory,
// for the identical reason D52 gives for Red Hat: the same package can be
// fixed on one release and permanently affected on another, and both ranges
// are emitted side by side -- only the range knows which it is.
func stampUbuntuFixState(aff *advisory.Affected, cve string, tracker *ubuntuTracker, st *stats) {
	if cve == "" {
		return
	}
	release, ok := ubuntuReleaseFromEcosystem(aff.Ecosystem)
	if !ok {
		return
	}
	for i := range aff.Ranges {
		rng := &aff.Ranges[i]
		if !rangeIsFixless(*rng) {
			continue
		}
		entry, found := tracker.lookup(cve, aff.Name, release)
		if !found {
			continue
		}
		fs, ok := ubuntuFixState(entry.state)
		if !ok {
			continue
		}
		rng.FixState = fs
		if st == nil {
			continue
		}
		switch fs {
		case advisory.FixStateWontFix:
			st.UbuntuStampedWontFix++
		case advisory.FixStateNotFixed:
			st.UbuntuStampedNotFixed++
		}
	}
}
