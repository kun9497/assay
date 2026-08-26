// Package osv converts OSV records into the internal advisory shape.
//
// OSV is the primary provider and passes through nearly unchanged (D1) — the
// internal type IS the OSV shape. What this package does is filter.
package osv

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// SourceName identifies records this provider supplied (D15's groundwork for
// splitting data by provider later).
const SourceName = "osv"

type rawRecord struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Modified  time.Time     `json:"modified"`
	Withdrawn *time.Time    `json:"withdrawn"`
	Aliases   []string      `json:"aliases"`
	Upstream  []string      `json:"upstream"`
	Related   []string      `json:"related"`
	Affected  []rawAffected `json:"affected"`
	Severity  []rawSeverity `json:"severity"`
}

type rawAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges   []rawRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type rawRange struct {
	Type   string     `json:"type"`
	Events []rawEvent `json:"events"`
}

type rawEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type rawSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// mainlineUbuntuKey is the only Ubuntu shape this build ingests: a long-term
// release carries the suffix, an interim one does not. It is deliberately a
// copy of the pattern in internal/version rather than an import — that one
// decides what a scan can COMPARE, this one decides what a build STORES, and
// a single shared constant would make the two look like one decision when
// either could legitimately move without the other.
var mainlineUbuntuKey = regexp.MustCompile(`^Ubuntu:[0-9]{2}\.[0-9]{2}(:LTS)?$`)

// ubuntuLineage reports whether a key names one of the Ubuntu lineages this
// build does not ingest — Pro, FIPS, FIPS-updates, FIPS-preview, Realtime,
// Nvidia-BlueField, and whatever OSV adds next.
//
// Written as "Ubuntu but not mainline" rather than as a list of the six
// families, because OSV's schema documents only the bare :Pro: prefix. The
// other spellings are convention, two non-canonical shapes are already in
// the live export (Ubuntu:22.04:LTS:for:NVIDIA:BlueField), and a list would
// silently start storing whatever family is invented next.
func ubuntuLineage(ecosystem string) bool {
	return strings.HasPrefix(ecosystem, "Ubuntu") && !mainlineUbuntuKey.MatchString(ecosystem)
}

// familyMatches reports whether a record's affected ecosystem key belongs to
// the family being fetched. Every ecosystem but Alpine matches by exact
// equality: "Go" must not start matching "GoFoo".
//
// Alpine is the one exception. There is a single archive ("Alpine/all.zip")
// for every release rather than one archive per release — unlike its
// ecosystem KEYS, which stay release-qualified (D6: "Alpine:v3.19", never a
// bare "Alpine"). wantEcosystem "Alpine" therefore has to match any
// "Alpine:vX.Y" entry the archive contains, not just an exact "Alpine" that
// never appears in real data. Narrowing this back to exact equality would
// match nothing at all and silently ingest zero Alpine records.
// foldPackagistEcosystem folds a package-repository-qualified Packagist key
// ("Packagist:https://packages.drupal.org/8", used for Drupal contrib
// modules) down to the plain "Packagist" family key before it is stored.
//
// familyMatches already prefix-matches the family, so a record naming this
// qualified key is ingested either way (matching alone is not the problem).
// The problem is what gets STORED: NormalizeName and EcosystemForPURLType
// only ever build the plain "Packagist" key from a purl or a package name —
// neither can construct "Packagist:https://packages.drupal.org/8" — so a
// lookup can never reach a record stored under the qualified key. Preserving
// it would be D13's "store losslessly" taken past the point it helps: the
// data would be there and permanently unreachable, which is worse than not
// storing the distinction at all.
//
// Measured 2026-08-18: 521 records in the Packagist archive carry this
// qualified ecosystem, every one a drupal/* package name. The fold cannot
// collide with an unrelated package: "drupal" is a vendor namespace reserved
// for Drupal on packages.org, so drupal/* never names anything else there.
//
// Packagist only — deliberately not generalized to every "family:qualifier"
// shape. Distro families (Alpine:v3.19, Debian:12, Red Hat:9, Ubuntu:24.04)
// carry their RELEASE in that position, and the release is part of the key by
// design (D6): folding those the same way would merge every release into one
// bucket and reintroduce the exact miss D6 exists to prevent. Packagist has
// no such release axis — the qualifier here names a secondary repository, not
// a version — so nothing depends on keeping it.
func foldPackagistEcosystem(ecosystem string) string {
	if rest, ok := strings.CutPrefix(ecosystem, "Packagist:"); ok && rest != "" {
		return "Packagist"
	}
	return ecosystem
}

func familyMatches(ecosystem, want string) bool {
	// The rule was written as a special case for "Alpine" and is general: a
	// distro archive is fetched under its family name and holds
	// release-qualified keys inside it (D6). Debian arrived and the hardcoded
	// name silently matched nothing, which the fetch guard caught — an archive
	// of 62,318 records yielding zero.
	//
	// Harmless for the language ecosystems: there is no "Go:1.22" key, so the
	// prefix clause never fires for them.
	if ecosystem == want || strings.HasPrefix(ecosystem, want+":") {
		return true
	}
	// D88: "one feed, two keys". Chainguard/all.zip is fetched under
	// "Chainguard" and is a measured STRICT superset of Wolfi/all.zip — every
	// CGA-* record is byte-identical between the two archives, and 23,961 of
	// them (2026-08-22) carry affected entries for BOTH ecosystems in one
	// document, with the Wolfi package set always a subset of that same
	// record's Chainguard package set (0 counterexamples). Wolfi/all.zip is
	// therefore never fetched at all (see Ecosystems), and a "Wolfi" affected
	// entry reached while fetching "Chainguard" has to be treated as belonging
	// to the family being fetched too — otherwise fetchOne's covered-keys loop
	// never marks "Wolfi" covered, Meta.Ecosystems omits it, and D20's
	// coverage check sends every Wolfi image straight to a skip despite the
	// data sitting in the store under exactly the key a Wolfi scan looks up.
	// Deliberately one-directional (a "Chainguard" want covers a "Wolfi" key,
	// never the reverse): nothing in this codebase ever fetches under "Wolfi".
	return want == "Chainguard" && ecosystem == "Wolfi"
}

// echoNotAffectedSentinel reports whether a range is Echo's own "this
// package was never affected" marker rather than a real vulnerable window --
// exactly one Fixed event in the range, and its value is the bare string
// "1". Measured 2026-08-26 against the live Echo/all.zip: 2,135 of Echo's
// fixed events carry this exact string (2,132 of them on package `linux`,
// e.g. ECHO-0066-dd81-6847, always paired with introduced:"0").
//
// Unlike Chainguard/Wolfi's fixed:"0" sentinel (D88), which is safe to keep
// and evaluate because "0" parses as the minimal real version under every
// registered comparer, Echo's "1" is NOT safe by the same accident: a
// genuine epoch-less 0.x deb version legitimately compares BELOW "1", so
// keeping the range would make [introduced 0, fixed 1) wrongly report that
// version as vulnerable and then fixed. convert (below) drops the whole
// range on this signal instead, with a counter.
//
// Deliberately exact string equality rather than a numeric or prefix
// comparison: a genuine fix at epoch 1 ("1:1.0-1") is a completely different
// string and must never match this, or every real epoch-1 fix Echo ever
// publishes would be discarded along with the sentinel.
func echoNotAffectedSentinel(rr rawRange) bool {
	var only string
	var n int
	for _, e := range rr.Events {
		if e.Fixed == "" {
			continue
		}
		n++
		only = e.Fixed
	}
	return n == 1 && only == "1"
}

// databaseOf returns the database that authored an advisory, read from its
// identifier's namespace.
//
// Resolved once, at ingest, rather than at query time: a prefix is a naming
// convention rather than a field, and these identifiers nest —
// ALPINE-CVE-2025-46394 is an ALPINE record whose subject has a CVE. A parser
// in the read path would have to get that right on every call, silently.
func databaseOf(id string) string {
	i := strings.Index(id, "-")
	if i <= 0 {
		return ""
	}
	return id[:i]
}

// distroAuthored reports whether database names a distro's own
// security-advisory namespace, as opposed to a language- or
// ecosystem-authored one.
//
// This is the scope D71 decision 1 drew, and D72 (AlmaLinux) is the record
// that could not ship without it: a distro-authored record's `related` field
// names OTHER identifiers for the SAME advisory — AlmaLinux's ALSA records
// carry their CVE nowhere else at all (measured 2026-08-19: aliases and
// upstream are empty on every one). GHSA and RUSTSEC also populate `related`,
// but for genuinely different, merely similar advisories; reading it there as
// an alias would fabricate a join between two distinct vulnerabilities. A
// global read was rejected for exactly that reason, so the field is only ever
// populated for the namespaces below.
//
// ALBA and ALEA are listed even though neither ever reaches this function in
// practice — Convert drops them before Database would matter (they are not
// vulnerability reports at all) — but a database prefix is cheap to name
// correctly and a future caller of distroAuthored should not have to
// rediscover that AlmaLinux's three namespaces are siblings.
//
// "CGA" is D88's addition, user-confirmed as a scope extension of the same
// D71 decision 1 rather than a new one: Chainguard's own advisories carry no
// CVE anywhere else. Measured 2026-08-22 across the live (non-withdrawn)
// corpus: aliases 0.2%, upstream 0% (the field is never populated at all,
// the same shape AlmaLinux's ALSA records have), related 99.7% with a CVE
// reachable on 95.9% of those. Without this, a CGA finding carries no CVE
// and no NVD/KISA rating join ever reaches it. related also carries sibling
// CGA ids and GHSA ids alongside the CVE — harmless to lookupIDs, since
// siblings and a record's own GHSA twin all describe the SAME advisory, not
// a different one the way a GHSA record's own `related` can (the hazard
// distroAuthored's scope exists to avoid in the first place).
func distroAuthored(database string) bool {
	switch database {
	case "ALPINE", "DEBIAN", "UBUNTU", "RLSA", "ALSA", "ALBA", "ALEA", "CGA":
		return true
	default:
		return false
	}
}

// vendorSeverityWordPrefix matches a distro summary's leading severity word —
// the RHSA convention AlmaLinux's ALSA summaries inherit byte-for-byte
// ("Important: openssh security update"), measured 2026-08-19 as the ONLY
// severity signal AlmaLinux's archive carries (0% CVSS anywhere). Anchored to
// the start of the string and to the four words severity.vendorSeverityWords
// actually recognizes, so a summary that merely happens to contain one of
// these words later in the sentence cannot trip it.
var vendorSeverityWordPrefix = regexp.MustCompile(`^(Critical|Important|Moderate|Low):`)

// vendorSeverityWord extracts the severity word from a distro summary's
// leading "Word:" prefix, or reports false when the summary carries none of
// the four recognized words there.
func vendorSeverityWord(summary string) (string, bool) {
	m := vendorSeverityWordPrefix.FindStringSubmatch(summary)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Convert parses one OSV record and keeps only the parts relevant to
// wantEcosystem. ok is false when the record is deliberately filtered out;
// err is non-nil only when the record is malformed. Distinguishing the two
// keeps "we chose to skip this" from looking like "the database is broken".
//
// A thin wrapper over convert with a nil *stats and a nil *ubuntuTracker:
// every pre-D82 caller (and every existing test in this package) calls
// Convert and does not want to know about module-stream counting or D85's
// Ubuntu fix-state stamping, so the signature that answers "did this record
// convert" stays exactly as it always was. fetchOne is the one caller that
// wants the counts and the tracker, and calls convert directly with both.
func Convert(data []byte, wantEcosystem string) (advisory.Advisory, bool, error) {
	return convert(data, wantEcosystem, nil, nil)
}

// convert is Convert's real body, plus D82's module-stream attachment and
// D85's Ubuntu fix-state stamping. st is nil from every caller that does not
// care about either's counts, and tracker is nil from every caller that has
// not fetched (or does not want) the Ubuntu CVE tracker (see Convert) --
// stampUbuntuFixState and ubuntuTracker.lookup both treat a nil tracker as
// "nothing to stamp" rather than panicking.
func convert(data []byte, wantEcosystem string, st *stats, tracker *ubuntuTracker) (advisory.Advisory, bool, error) {
	var r rawRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return advisory.Advisory{}, false, fmt.Errorf("decode osv record: %w", err)
	}
	if r.ID == "" {
		return advisory.Advisory{}, false, fmt.Errorf("osv record has no id")
	}

	// Withdrawn advisories were retracted upstream; reporting them is a plain
	// false positive. Dropped here rather than at query time so no lookup path
	// can forget the check (D16).
	if r.Withdrawn != nil {
		return advisory.Advisory{}, false, nil
	}

	kind := advisory.KindVulnerability
	if strings.HasPrefix(r.ID, "MAL-") {
		kind = advisory.KindMalicious
	}
	// Malicious-package reports are a different finding class with no severity
	// and no fixed version (D15). Kind is computed above and would be stored
	// faithfully; the filter is what changes when they are enabled.
	if kind != advisory.KindVulnerability {
		return advisory.Advisory{}, false, nil
	}

	db := databaseOf(r.ID)
	// D72: ALBA (bugfix) and ALEA (enhancement) errata name no vulnerability
	// at all. That is a different reason from MAL-* above — D15's Kind
	// machinery exists for a malicious-PACKAGE report, which IS a security
	// finding, only of a different class; ALBA/ALEA are AlmaLinux's own
	// bugfix and enhancement notices and were never vulnerability reports to
	// begin with, so they never reach Kind and are simpler to drop outright.
	// Mirrors the withdrawn/MAL-* pattern above: dropped at ingestion (D16),
	// so no query path can forget the check. Measured 2026-08-19: 979 ALBA +
	// 222 ALEA of AlmaLinux's 5,606 records.
	if db == "ALBA" || db == "ALEA" {
		return advisory.Advisory{}, false, nil
	}

	out := advisory.Advisory{
		ID:       r.ID,
		Database: db,
		Aliases:  r.Aliases,
		Upstream: r.Upstream,
		Source:   SourceName,
		Kind:     kind,
		Summary:  r.Summary,
		Modified: r.Modified,
	}
	// D3 revised by D71 decision 1, scoped to distro-authored records —
	// distroAuthored's own comment explains why a global read is rejected.
	if distroAuthored(db) {
		out.Related = r.Related
	}
	for _, sev := range r.Severity {
		out.Severity = append(out.Severity, advisory.Severity{Type: sev.Type, Score: sev.Score})
	}
	// D72: a distro-authored record with no CVSS entries at all states its
	// severity only as the summary's leading word. Stored losslessly as a
	// VENDOR_WORD severity entry (D13) rather than banded here, so
	// internal/severity stays the one place that turns a stored value into a
	// verdict — severity.vendorSeverityWords carries the RHSA word -> band
	// mapping this entry's Score will be read against.
	if len(out.Severity) == 0 && distroAuthored(db) {
		if word, ok := vendorSeverityWord(r.Summary); ok {
			out.Severity = append(out.Severity, advisory.Severity{Type: "VENDOR_WORD", Score: word})
		}
	}

	// D85: resolved once per record, from the SAME field D3 already reads for
	// the CVE join (Upstream), rather than once per Affected entry -- every
	// entry in one record shares one CVE. ok is discarded: a record with no
	// CVE-shaped upstream identifier (0.01% measured) simply has nothing for
	// stampUbuntuFixState to key a lookup on, which its own empty-cve guard
	// already handles.
	ubuntuCVE, _ := firstUbuntuCVE(out.Upstream)

	var matchesWanted bool
	for _, ra := range r.Affected {
		// Every entry is kept, including other ecosystems'. Stripping them made
		// the record lossy in a way that destroyed data: Fetch emits the same
		// advisory once per ecosystem, Put overwrites by ID, and the last pass
		// left a record holding only its own ecosystem's entries while the
		// earlier ecosystem's index still pointed at it. The matcher then
		// discarded every entry and reported nothing — no error, no skip.
		// Measured on the live Go dump: 15 of 8,497 records clobbered, 3 with
		// no GO- twin to rescue them.
		//
		// Selecting the right entries is the matcher's job, and it already
		// filters on ecosystem and name. This also restores D13.
		if ra.Package.Name == "" {
			continue
		}
		// The one exception to the paragraph above, and it is safe for the
		// reason that paragraph gives rather than in spite of it (D53).
		//
		// What made stripping lossy was that another PASS had already
		// indexed the entries being dropped. No pass ever indexes an Ubuntu
		// lineage key: Ecosystems never names one, familyMatches can never
		// return true for one, and version.For refuses to resolve one. An
		// entry dropped here is therefore unreachable by construction, not
		// merely unreached today.
		//
		// It is dropped on EVERY fetch rather than only the Ubuntu one, so
		// the invariant does not depend on pass ordering.
		//
		// This is also what makes the corpus affordable. Ubuntu records carry
		// 38.9 affected entries each against Debian's 3.4 — 6.03 GB unpacked
		// against 254 MB — and the multiplier is one entry per
		// (lineage x release x binary package), not longer version lists.
		if ubuntuLineage(ra.Package.Ecosystem) {
			continue
		}
		if familyMatches(ra.Package.Ecosystem, wantEcosystem) {
			matchesWanted = true
		}
		aff := advisory.Affected{
			// Drupal contrib records name "Packagist:<repository URL>"; folded
			// to plain "Packagist" here, at ingestion, so no lookup path has to
			// know the qualified shape exists (foldPackagistEcosystem's own
			// comment; same rationale as D16).
			Ecosystem: foldPackagistEcosystem(ra.Package.Ecosystem),
			Name:      ra.Package.Name,
			Versions:  ra.Versions, // verbatim: OSV publishes non-canonical forms (D13)
		}
		for _, rr := range ra.Ranges {
			typ := advisory.RangeType(strings.ToUpper(rr.Type))
			// GIT ranges carry commit SHAs, not versions.
			if typ == advisory.RangeGit {
				continue
			}
			// D92: Echo's not-affected sentinel is dropped whole, at
			// conversion (D16's spirit) -- see echoNotAffectedSentinel's own
			// comment for why "1" cannot be kept and evaluated the way
			// Chainguard/Wolfi's "0" is below. Scoped to Echo-family entries
			// only (familyMatches also matches "Echo:PyPi" etc., harmless: the
			// sentinel has only ever been measured on the bare "Echo" key). 165
			// SEMVER-typed Echo ranges also exist (Go modules under
			// pkg:deb/echo purls, introduced-only) -- dead weight, untouched
			// here, since they carry no Fixed event at all and never match.
			if familyMatches(ra.Package.Ecosystem, "Echo") && echoNotAffectedSentinel(rr) {
				if st != nil {
					st.EchoNotAffectedSentinel++
				}
				continue
			}
			rng := advisory.Range{Type: typ}
			for _, re := range rr.Events {
				// D35 repairs one documented Alpine typo here, at ingestion,
				// so no query path can forget it (D16's rule). Everything else
				// is stored exactly as published — including Chainguard/Wolfi's
				// fixed:"0" "never affected" sentinel (D88), stored losslessly
				// rather than dropped or special-cased here; see rangeeval.go's
				// Fixed-branch comment for why it is safe at the point that
				// actually reads it.
				rng.Events = append(rng.Events, advisory.Event{
					Introduced:   repairBound(ra.Package.Ecosystem, re.Introduced),
					Fixed:        repairBound(ra.Package.Ecosystem, re.Fixed),
					LastAffected: repairBound(ra.Package.Ecosystem, re.LastAffected),
					Limit:        repairBound(ra.Package.Ecosystem, re.Limit),
				})
			}
			if len(rng.Events) > 0 {
				aff.Ranges = append(aff.Ranges, rng)
			}
		}
		// D85: stamped before the empty check below, not after -- a fix-less
		// entry with Versions but no Ranges has nothing to stamp anyway
		// (stampUbuntuFixState only ever touches aff.Ranges), so the order is
		// only for reading top-to-bottom as "build the entry, then annotate
		// it" rather than any correctness reason. tracker == nil (Ubuntu not
		// fetched, or UBUNTU_TRACKER_ENABLE=0) makes this a no-op via
		// ubuntuTracker.lookup's own nil check; ubuntuReleaseFromEcosystem's
		// own false return is what makes it a no-op for every non-Ubuntu
		// entry convert() ever builds, Ubuntu fetch or not.
		if tracker != nil {
			stampUbuntuFixState(&aff, ubuntuCVE, tracker, st)
		}
		if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
			continue // nothing left to match on
		}
		out.Affected = append(out.Affected, aff)
	}

	// The record is dropped only when it says nothing about the ecosystem being
	// ingested. It is stored whole when it does.
	if len(out.Affected) == 0 || !matchesWanted {
		return advisory.Advisory{}, false, nil
	}
	// D82: Rocky Linux and AlmaLinux OSV carry no per-entry module-stream
	// attribution at all -- the only place either archive states which stream
	// an errata patches is its own summary. Runs only on a record that
	// survives the drop check above, so a record this fetch pass is not
	// keeping never contributes to st's counts.
	attachModuleStreams(&out, r.Summary, st)
	return out, true, nil
}

// moduleStreamSeverityPrefix strips a distro summary's leading severity word
// before D82's token extraction runs. Without stripping it first, the
// summary's own "Word:" prefix reads as a spurious first token
// ("Important:idm" out of "Important: idm:DL1 security update"), consuming
// the colon the real token needs -- and on a summary with no OTHER colon at
// all ("Important: varnish security update"), fabricating a token where none
// exists. The same four words vendorSeverityWordPrefix recognizes, but this
// copy also consumes the whitespace after the colon: vendorSeverityWordPrefix's
// only caller reads the word alone and does not care what follows it, while
// this one feeds what is left straight into moduleStreamTokenRe.
var moduleStreamSeverityPrefix = regexp.MustCompile(`^(?:Critical|Important|Moderate|Low):\s*`)

// moduleStreamTokenRe matches one "name:stream" token in a Rocky/AlmaLinux
// summary, already stripped of its severity prefix -- the RHSA title
// convention ("python38:3.8 security, bug fix, and enhancement update") that
// is the only place either archive states which module stream an errata
// patches. Measured 2026-08-20: OSV's own `affected` entries carry a bare
// module COMPONENT name (Judy under mariadb, not mariadb itself), so
// attribution can only ever be read here, at the record level, never per
// entry.
var moduleStreamTokenRe = regexp.MustCompile(`([A-Za-z][\w-]*):([A-Za-z0-9][\w.]*)`)

// moduleStreamTokens extracts every distinct "name:stream" token from a
// Rocky/AlmaLinux summary, in first-seen order. Zero tokens (no colon left
// once the severity prefix is stripped, e.g. "go-toolset security update")
// and two-plus distinct tokens (two streams named in one summary -- the
// idm:DL1 + idm:client shape, or two genuinely different modules like
// "python39:3.9 and python39-devel:3.9") both mean the record's module
// entries stay stream-less; attachModuleStreams is what decides that, this
// function only reports what the prose contains.
func moduleStreamTokens(summary string) []string {
	rest := moduleStreamSeverityPrefix.ReplaceAllString(summary, "")
	var tokens []string
	seen := map[string]bool{}
	for _, m := range moduleStreamTokenRe.FindAllStringSubmatch(rest, -1) {
		tok := m[1] + ":" + m[2]
		if seen[tok] {
			continue
		}
		seen[tok] = true
		tokens = append(tokens, tok)
	}
	return tokens
}

// moduleTaggedFixedEVR duplicates redhat.isModule / matcher.rpmModuleBuild /
// oracle.isModuleBuildEVR -- the same reason every one of those duplicates
// the others: this package cannot import across the provider/matcher
// boundary for one string check, and the two spellings ("module+el" Red
// Hat/Rocky, "module_el" AlmaLinux) are cheap to keep in sync by comment
// rather than by import.
func moduleTaggedFixedEVR(evr string) bool {
	return strings.Contains(evr, "module+el") || strings.Contains(evr, "module_el")
}

// affectedCarriesModuleTag reports whether any Fixed event in aff's ranges is
// a module-tagged build. D82 attaches a stream only to entries that pass
// this -- an ordinary, non-modular Rocky/AlmaLinux package must never gain a
// ModuleStream just because its record's summary happens to look like a
// module title.
func affectedCarriesModuleTag(aff advisory.Affected) bool {
	for _, rng := range aff.Ranges {
		for _, ev := range rng.Events {
			if ev.Fixed != "" && moduleTaggedFixedEVR(ev.Fixed) {
				return true
			}
		}
	}
	return false
}

// rockyOrAlmaEcosystem reports whether an Affected entry's own ecosystem key
// is a Rocky Linux or AlmaLinux release -- D82's scope, checked per entry
// rather than trusted from wantEcosystem: a record's Affected list can carry
// entries for other ecosystems too (TestConvert_KeepsForeignEcosystemEntries
// is why Convert never strips them), and only the Rocky/Alma ones are
// eligible for a summary-derived stream.
func rockyOrAlmaEcosystem(ecosystem string) bool {
	return familyMatches(ecosystem, "Rocky Linux") || familyMatches(ecosystem, "AlmaLinux")
}

// attachModuleStreams implements D82. Rocky Linux and AlmaLinux OSV records
// carry no per-entry module-stream attribution at all -- an affected entry's
// own name is a bare module COMPONENT ("Judy" under "mariadb"), never the
// module itself -- so the only place either archive states which stream an
// errata patches is its own summary, in the RHSA title convention
// ("Moderate: python38:3.8 security, bug fix, and enhancement update").
// Attribution is therefore RECORD-level: every module-tagged entry in a
// qualifying record gets the SAME stream, or none at all.
//
// Exactly one distinct token in the summary (after stripping the severity
// prefix) is attached to every module-tagged entry. Zero tokens or two-plus
// distinct tokens leave every module entry stream-less instead of guessing --
// deliberately conservative, the same call D80's matcher already makes for a
// stream-blind module bound: "python39:3.9 and python39-devel:3.9" names two
// modules and OSV cannot say which component belongs to which, and three
// real advisories name two streams of ONE module (idm:DL1 + idm:client) that
// cannot be split at all. Ordinary, non-module entries in the same record --
// Rocky/Alma or otherwise -- are never touched.
func attachModuleStreams(out *advisory.Advisory, summary string, st *stats) {
	var moduleEntries []int
	for i, aff := range out.Affected {
		if rockyOrAlmaEcosystem(aff.Ecosystem) && affectedCarriesModuleTag(aff) {
			moduleEntries = append(moduleEntries, i)
		}
	}
	if len(moduleEntries) == 0 {
		return
	}
	switch tokens := moduleStreamTokens(summary); len(tokens) {
	case 1:
		for _, i := range moduleEntries {
			out.Affected[i].ModuleStream = tokens[0]
		}
		if st != nil {
			st.ModuleEntriesStreamed += len(moduleEntries)
		}
	case 0:
		if st != nil {
			st.ModuleRecordsZeroToken++
		}
	default:
		if st != nil {
			st.ModuleRecordsMultiToken++
		}
	}
}

// stats counts what D82's module-stream attachment did across a fetch -- the
// same discipline every other provider's own stats struct exists for: a
// provider that silently narrows what it attaches looks exactly like one
// that is broken. nil is a valid *stats (every pre-D82 caller reaches convert
// through Convert, which passes nil) -- every increment site above guards on
// it.
type stats struct {
	ModuleEntriesStreamed   int // module-tagged Rocky/AlmaLinux entries that got a summary-derived ModuleStream (D82)
	ModuleRecordsZeroToken  int // qualifying records whose summary yielded no stream token
	ModuleRecordsMultiToken int // qualifying records whose summary yielded 2+ distinct stream tokens

	// D85: the Ubuntu CVE tracker's own counts. The first three are set once,
	// while parseUbuntuTracker walks active/+retired/ (before any archive is
	// fetched); the last two accumulate across every Ubuntu record convert()
	// stamps, the same way the D82 fields above accumulate across every
	// Rocky/AlmaLinux one.
	UbuntuTuplesLoaded    int // (CVE, srcpkg, release) tuples parsed from active/+retired/
	UbuntuFilesUnparsed   int // tracker files with no readable Candidate: CVE line
	UbuntuUnknownCodename int // stanza lines naming a codename outside ubuntuCodenameRelease
	UbuntuStampedWontFix  int // fix-less ranges stamped wont-fix from an `ignored` tuple
	UbuntuStampedNotFixed int // fix-less ranges stamped not-fixed from needed/needs-triage/pending/deferred

	// EchoNotAffectedSentinel is D92's own count: Echo ranges whose sole
	// Fixed event was the bare string "1" and were dropped at conversion
	// (echoNotAffectedSentinel's own comment). A build that stops seeing
	// this count on an Echo fetch is a build whose upstream shape changed.
	EchoNotAffectedSentinel int
}

func (s stats) String() string {
	return fmt.Sprintf(
		"module streams (D82): %d module-tagged Rocky/AlmaLinux entr(y/ies) streamed from summary prose, "+
			"%d record(s) left stream-less for no token, %d record(s) left stream-less for 2+ tokens; "+
			"ubuntu fix state (D85): %d range(s) stamped wont-fix, %d range(s) stamped not-fixed; "+
			"echo not-affected sentinel (D92): %d range(s) dropped for fixed:\"1\"",
		s.ModuleEntriesStreamed, s.ModuleRecordsZeroToken, s.ModuleRecordsMultiToken,
		s.UbuntuStampedWontFix, s.UbuntuStampedNotFixed, s.EchoNotAffectedSentinel)
}
