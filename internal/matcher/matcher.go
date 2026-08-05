// Package matcher decides whether an installed package is affected by a stored
// advisory, and records why.
package matcher

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
	"github.com/kun9497/assay/internal/version"
)

type Finding struct {
	Package  pkgmeta.Package
	Advisory advisory.Advisory
	// Evidence is on the type, not in a log line, because explainability is
	// goal #1 and anything left to logging effectively does not exist (D10).
	Evidence version.Evidence
	// MatchedName is the package name that reached the advisory. It differs
	// from Package.Name when the advisory was written against the source
	// package (D8) — an openssl advisory matching libssl3. Without it the
	// report claims a package is vulnerable and gives the reader no way to
	// check the claim against the advisory they look up.
	//
	// It lives here rather than on version.Evidence because the version package
	// compares versions; which name reached the advisory is a matcher fact.
	MatchedName string
	// Severity and Score are derived from the advisory's own CVSS vectors at
	// match time (D13), never read from a value baked in when the database
	// was built. A record carrying several vectors is banded by the highest
	// of them (severity.Highest) — a finding is as severe as its worst
	// rating, and taking the first vector would make the result depend on
	// OSV's serialization order rather than on the vulnerability. Advisories
	// with no scorable vector — roughly a quarter of the live database —
	// carry Severity == severity.Unknown, never a coerced low band (D17).
	//
	// Match is the only legitimate constructor of Finding, and it always sets
	// both fields. Building one any other way (tests included) must set them
	// explicitly: the zero value of Band is None, a real rating of 0.0, so an
	// unset Severity silently claims "rated harmless" rather than "unrated" —
	// and unlike Unknown, None sits inside the --fail-on ordering and escapes
	// Summary.UnknownSeverity, so the omission would be invisible to both.
	Severity severity.Band
	Score    float64
	// Ratings is what every database that described this vulnerability said
	// about it (D25). Never empty on a finding Match produced: a single-source
	// finding carries one rating, so no renderer has to tell "no source said
	// anything" apart from "we dropped them".
	//
	// As with Severity above, Match is the only legitimate constructor, and a
	// Finding built any other way — tests included — must populate this. The
	// zero value is an empty slice, which is the one state the renderers are
	// entitled to assume cannot happen.
	//
	// Severity and Score above are the highest across these, and Advisory and
	// Evidence are the record that set it. Keeping the rest is not a display
	// nicety — the sources land on different bands in 5,693 of the 8,893
	// measured multi-record groups, so a report that showed one source's
	// answer would be quietly presenting one authority's opinion as the
	// answer.
	Ratings []Rating
	// Identifiers is every name this finding answers to: the ID, aliases and
	// upstream of every record that joined it, sorted, including the displayed
	// advisory's own ID. A renderer showing "also known as" excludes whichever
	// one it is displaying; a lookup by identifier matches against the lot.
	//
	// It has to live on the finding rather than be read off Advisory, because
	// merging records is what D25 does: the moment two records become one
	// finding, the identifiers of the record that did not win stop being
	// reachable through Advisory. That was a real regression — a PYSEC ID
	// printed in the JSON's own ratings array could not be fed back to
	// --explain, which answered exit 2 for a scan that ran perfectly.
	//
	// Drawn from BOTH aliases and upstream (D3), unlike the grouping key,
	// which deliberately excludes upstream because OSV defines it as "derived
	// from" rather than "the same as". This is display and lookup, not
	// identity: showing a reader one extra identifier is noise, failing to
	// resolve one they were just handed is a defect.
	Identifiers []string
	// Enrichment is what other authorities wrote ABOUT this vulnerability in
	// prose — KISA's Korean headline, overview and notice link — joined on the
	// CVE exactly the way Ratings are (D3).
	//
	// It is display copy and nothing else, and that is the property to hold
	// hardest here: Severity, Score, the report's summary counts and every
	// exit code must be identical to the same scan against a database with no
	// enrichment at all. KISA describes much of its corpus in prose with no
	// ecosystem and no package name, so anything here that could move a gate
	// would be a source that cannot say which package is affected deciding
	// whether CI passes.
	//
	// Empty on most findings — the measured overlap between KISA's corpus and
	// the advisories this tool holds is 413 CVEs, 2.4% — so unlike Ratings,
	// absence is the ordinary case and a renderer must read nothing into it.
	Enrichment []Enrichment
}

// Enrichment is one authority's prose about the vulnerability a finding
// describes: a headline, an overview, and somewhere to read the rest.
//
// Deliberately not a Rating. A Rating carries a band and a score and can raise
// Finding.Severity; this carries neither and can raise nothing (D3).
//
// It also drops advisory.Enrichment's own CVE field. A finding is reached
// through any of the identifiers it answers to, and which one of them the
// prose happened to be filed under is not a fact a reader of the report can
// act on — while keeping it would make two records that say exactly the same
// thing (one KISA notice naming several CVEs produces one record per CVE)
// render as two, purely because the finding carried both CVEs.
type Enrichment struct {
	// Source is the authority that wrote it — "KISA" — the same name the store
	// keys the record under, so a report can say who is speaking rather than
	// presenting unattributed prose.
	Source  string
	Title   string
	Summary string
	URL     string
}

// Rating is one database's assessment of one vulnerability: what GHSA said, as
// distinct from what PYSEC said about the same CVE.
type Rating struct {
	// Database is the database that authored the record — "GHSA", "PYSEC",
	// "GO", "ALPINE" — not the provider that fetched it. Both exist and they
	// differ: Advisory.Source is "osv" for every record here.
	Database   string
	AdvisoryID string
	Severity   severity.Band
	Score      float64
	// Fixed is the fixed version THIS record gives, which is why the field is
	// on the rating and not on the finding. Taking it from the winning record
	// would make every source appear to agree about remediation when measured
	// disagreement is the common case.
	//
	// Empty on an annotation (D27). NVD was asked what a CVE is worth, not
	// which version fixes this package - filling it from the finding's own
	// evidence would have the report claim NIST published a remediation it
	// never published.
	Fixed string
	// URL is where a reader can check this rating, empty for an OSV record
	// because the advisory is already named. An annotation has no advisory to
	// name, so without this the per-source breakdown asserts what NIST says and
	// offers nowhere to verify it - explainability is goal #1, and it applies
	// to the sources as much as to the match.
	URL string
}

// beats reports whether cand should displace cur as the rating that sets the
// finding's band — and so as the record the report displays.
//
// A rated record always outranks an unrated one, because unknown sits outside
// the ordering rather than below it (D17): a source that rated nothing must
// not be able to present a critical finding as unrated. Among rated records
// the higher score wins.
//
// Equal standing is broken by name rather than left to arrival order. That is
// the whole point of D25 — a tie resolved by "whichever the index listed
// first" is the defect, not a harmless coin flip.
//
// One consequence is deliberate: a record banding this none (a real CVSS 0.0)
// outranks a sibling that rated nothing, so the finding reports none and stops
// counting toward --fail-on-unknown. That is the honest answer. Unknown means
// nobody assessed it, and here somebody did.
func beats(cand, cur Rating) bool {
	candUnrated := cand.Severity == severity.Unknown
	curUnrated := cur.Severity == severity.Unknown
	if candUnrated != curUnrated {
		return curUnrated
	}
	if !candUnrated && cand.Score != cur.Score {
		return cand.Score > cur.Score
	}
	if cand.Database != cur.Database {
		return cand.Database < cur.Database
	}
	return cand.AdvisoryID < cur.AdvisoryID
}

// Skipped is something the matcher could not evaluate. It exists so that "we
// could not tell" never renders as "nothing found".
//
// It is per (package, advisory), not per package. A package can produce a
// finding from one advisory and be unevaluable against another, and the second
// fact must survive the first — the unevaluated advisory may carry the higher
// severity or a higher fix floor, which would make the remediation shown next
// to the visible finding actively wrong.
type Skipped struct {
	Package pkgmeta.Package
	// AdvisoryID is empty when the whole package was skipped, e.g. because no
	// comparer is registered for its ecosystem.
	AdvisoryID string
	Reason     string
}

type Result struct {
	Findings []Finding
	Skipped  []Skipped
}

type Matcher struct {
	store store.Store
}

func New(s store.Store) *Matcher { return &Matcher{store: s} }

func (m *Matcher) Match(t pkgmeta.Target) (Result, error) {
	var res Result

	// Which ecosystems this database actually holds (D20). Read once, before
	// any lookup, because a lookup cannot answer the question: an ecosystem
	// that was never ingested returns exactly what a package with no advisories
	// returns, and calling that clean is the failure this whole tool exists to
	// avoid. Measured before this check existed — same package, same version,
	// only the Alpine release changed:
	//
	//	3.19.9 -> 1 finding
	//	3.25.0 -> "No known vulnerabilities found", exit 0
	covered, err := m.store.Covers()
	if err != nil {
		return Result{}, fmt.Errorf("read database coverage: %w", err)
	}

	for _, p := range t.Packages {
		cmp, ok := version.For(p.Ecosystem)
		if !ok {
			res.Skipped = append(res.Skipped, Skipped{
				Package: p,
				Reason:  fmt.Sprintf("no version comparer for ecosystem %q", p.Ecosystem),
			})
			continue
		}
		if !covered[p.Ecosystem] {
			// A whole-package skip, so the report counts it as not evaluated
			// and a scan where nothing else was checked exits 2 (D11).
			res.Skipped = append(res.Skipped, Skipped{
				Package: p,
				Reason: fmt.Sprintf("ecosystem %q is not in this database; "+
					"run `assay db update`", p.Ecosystem),
			})
			continue
		}

		// Distro advisories are written against SOURCE packages while what is
		// installed are binary packages (D8), so the source name is a second
		// lookup key. Both are queried because they coincide for most packages
		// and diverge for the ones that matter: alpine:3.19 has nine of fifteen
		// diverging, with libssl3 and libcrypto3 both sourced from openssl, so a
		// single openssl advisory is unreachable from either without this.
		//
		// No separate by-source index is needed. OSV puts the source name
		// directly in Affected[].Name — 32,069 of 33,589 Alpine affected entries
		// carry ?arch=source — which the ordinary advisory index already covers.
		// Slice 1 reserved a by-source bucket on the assumption it would be
		// required; measuring the data retired it.
		//
		// The version needs no adjustment: an Alpine binary package carries its
		// source package's version, which is what makes indirect matching sound.
		names := []string{p.Name}
		if p.Source != nil && p.Source.Name != "" && p.Source.Name != p.Name {
			names = append(names, p.Source.Name)
		}

		// The dedup maps below are per package, not per lookup name, so an
		// advisory reachable under both names is still one finding.
		seen := make(map[string]bool)
		// Skips are deduplicated separately from findings: `seen` is only set
		// on a hit, and the error path must not rely on it. One advisory can
		// carry several Affected entries for the same package — measured at
		// 145 of 313 real Django records — and the same advisory can appear
		// twice in a lookup result, so without this a single bad bound emits
		// byte-identical skips and buries the rest of the report.
		skipped := make(map[string]bool)
		// One vulnerability commonly has records under several IDs — OSV's Go
		// ecosystem carries both the GHSA and the GO- identifier for the same
		// issue, which doubled every Go finding in a real scan against grype.
		// group maps every identifier a matched record declares to the index of
		// the finding it belongs to, so a later record joins that finding
		// instead of starting a second one.
		//
		// Keyed on ANY shared identifier, not on the record's own ID. Records
		// that name each other are the easy case, and the live GHSA and PYSEC
		// records for one Django CVE do exactly that — each lists the other's
		// ID, checked against OSV. Records sharing only a CVE do not, and
		// keying on the record's own ID missed those entirely: one
		// vulnerability, two findings. It is also the only link a KISA record
		// will have with a GHSA one.
		//
		// A record naming identifiers from two groups merges them, rather than
		// joining the first and leaving the second standing. Attaching to the
		// first is the cheaper code and it looked adequate — a duplicate
		// finding is visible where a dropped one is not — but it leaves the
		// finding COUNT dependent on arrival order, which is the property D25
		// exists to establish. Given A(CVE-1), B(CVE-2), C(CVE-1, CVE-2):
		// arriving A, B, C yields two findings and C, A, B yields one.
		group := make(map[string]int)

		for _, lookupName := range names {
			wantName := pkgmeta.NormalizeName(p.Ecosystem, lookupName)
			candidates, err := m.store.Lookup(p.Ecosystem, lookupName)
			if err != nil {
				// A store error is not a clean result. Fail the whole scan
				// rather than reporting a subset that reads as "fewer
				// vulnerabilities".
				return Result{}, fmt.Errorf("lookup %s/%s: %w", p.Ecosystem, lookupName, err)
			}

			for _, a := range candidates {
				if seen[a.ID] {
					continue
				}
				for _, aff := range a.Affected {
					// The store is keyed on (ecosystem, name), so a returned
					// advisory can still carry entries for sibling packages — a Go
					// advisory naming both github.com/foo/bar and .../bar/v2, for
					// instance. Evaluating a v1 version against a v2 range would be
					// wrong, so entries that are not this package are skipped.
					//
					// This mirrors the store's key equality exactly. If either side
					// ever starts normalizing names, the two must change together
					// or this filter will silently discard real advisories.
					if aff.Ecosystem != p.Ecosystem ||
						pkgmeta.NormalizeName(aff.Ecosystem, aff.Name) != wantName {
						continue
					}
					hit, ev, err := version.AffectsVersion(cmp, p.Version, aff)
					if err != nil {
						// One advisory this package cannot be evaluated against.
						// Recorded against that advisory and the loop continues, so
						// a single malformed bound hides neither the other
						// advisories nor the fact that this one was unevaluable.
						if !skipped[a.ID] {
							skipped[a.ID] = true
							res.Skipped = append(res.Skipped, Skipped{
								Package:    p,
								AdvisoryID: a.ID,
								Reason:     fmt.Sprintf("comparing %s: %v", p.Version, err),
							})
						}
						continue
					}
					if hit {
						seen[a.ID] = true
						ids := identifiers(a)
						band, score := severity.Highest(vectorsOf(a))
						r := Rating{
							Database:   a.Database,
							AdvisoryID: a.ID,
							Severity:   band,
							Score:      score,
							Fixed:      ev.Fixed,
						}
						idx := -1
						for _, g := range groupsOf(group, ids) {
							if idx == -1 {
								idx = g
								continue
							}
							absorb(res.Findings, group, idx, g)
						}
						if idx == -1 {
							idx = len(res.Findings)
							res.Findings = append(res.Findings, Finding{
								Package:     p,
								Advisory:    a,
								Evidence:    ev,
								MatchedName: lookupName,
								Severity:    band,
								Score:       score,
								Ratings:     []Rating{r},
								Identifiers: lookupIDs(a),
							})
						} else {
							f := &res.Findings[idx]
							f.Ratings = append(f.Ratings, r)
							f.Identifiers = append(f.Identifiers, lookupIDs(a)...)
							if beats(r, winnerOf(*f)) {
								f.Advisory, f.Evidence = a, ev
								f.MatchedName = lookupName
								f.Severity, f.Score = band, score
							}
						}
						for _, id := range ids {
							group[id] = idx
						}
						break
					}
				}
			}
		}
	}

	// Drop the entries absorb emptied. Deferred to here because group's values
	// index this slice and stay valid only while it does not shift.
	live := res.Findings[:0]
	for _, f := range res.Findings {
		if len(f.Ratings) > 0 {
			live = append(live, f)
		}
	}
	res.Findings = live

	for i := range res.Findings {
		res.Findings[i].Identifiers = dedupSorted(res.Findings[i].Identifiers)
		if err := m.annotate(&res.Findings[i]); err != nil {
			return Result{}, err
		}
		sortRatings(res.Findings[i].Ratings)
	}
	sortFindings(res.Findings)
	sortSkipped(res.Skipped)
	return res, nil
}

// annotate attaches what other authorities said about this finding's CVEs:
// NVD's rating (D27) and KISA's prose (D3). It runs once per finding, after
// every OSV record has joined, because Identifiers is only complete then.
//
// The two are read in the same loop over the same identifiers, and that is the
// whole of what they share. A rating is an assessment and may raise the band; an
// enrichment is display copy and may raise nothing — Severity, Score, Advisory,
// Evidence and Ratings are untouched by the enrichment half below, so a scan
// against a database holding KISA's whole corpus reaches the same verdict as one
// against a database with no enrichment at all.
//
// The band can go up here and the displayed record cannot change. That is D25's
// rule narrowed by one word: the finding shows the *matched* record that set
// its band. An annotation carries a score and nothing else — no Evidence, no
// range we compared against, no fixed version — because the match came from OSV
// and NIST was asked only what the CVE is worth. Displaying it would put an
// advisory on screen with nothing behind it, against goal #1, so Advisory,
// Evidence and MatchedName are deliberately not touched below.
//
// Identifiers is already deduplicated, so one CVE is one store read even when a
// record names it in both aliases and upstream (D3). On a real scan this is one
// read per finding rather than one per alias.
func (m *Matcher) annotate(f *Finding) error {
	for _, id := range f.Identifiers {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		rs, err := m.store.RatingsFor(id)
		if err != nil {
			// Same reasoning as a failed Lookup: a store error is not a clean
			// result. Failing the whole scan beats reporting a finding whose
			// band is lower than the data would have made it.
			return fmt.Errorf("ratings for %s: %w", id, err)
		}
		for _, r := range rs {
			band, score := severity.Highest(vectorsOf(advisory.Advisory{Severity: r.Severity}))
			f.Ratings = append(f.Ratings, Rating{
				Database:   r.Source,
				AdvisoryID: r.CVE,
				Severity:   band,
				Score:      score,
				URL:        r.URL,
				// Fixed stays empty on purpose: see Rating.Fixed.
			})
			// The aggregate only, never the display. beats() decides whether
			// this outranks what is there, so unknown still sits outside the
			// ordering (D17) and a source that scored nothing cannot pull a
			// rated finding down.
			// winnerOf reads the DISPLAYED record's name alongside the
			// current band, so once an annotation has raised the band the two
			// halves no longer describe one record. That is deliberate and it
			// is harmless: the name is only consulted to break a tie between
			// equal scores, and a tie leaves Severity and Score unchanged
			// whichever side wins. Nothing downstream reads winnerOf after
			// this point - absorb and the join both run earlier.
			if beats(f.Ratings[len(f.Ratings)-1], winnerOf(*f)) {
				f.Severity, f.Score = band, score
			}
		}

		es, err := m.store.EnrichmentFor(id)
		if err != nil {
			// Fails the scan, like a failed Lookup or RatingsFor, and for a
			// reason that is NOT the one D3 governs. D3 is about what stored
			// enrichment may do to a verdict — nothing — and a read that
			// errored produced no enrichment to have an opinion. What it did
			// produce is evidence that the database this scan is reading is
			// damaged, and a damaged database is exactly what exit 2 means
			// (D11). Swallowing it would also be unreportable: the matcher has
			// no stderr, so "the prose could not be read" would reach nobody.
			return fmt.Errorf("enrichment for %s: %w", id, err)
		}
		for _, e := range es {
			// The band, the score, the displayed advisory and the ratings are
			// all deliberately untouched. Everything this loop may do is append
			// display copy.
			f.Enrichment = append(f.Enrichment, Enrichment{
				Source:  e.Source,
				Title:   e.Title,
				Summary: e.Summary,
				URL:     e.URL,
			})
		}
	}
	f.Enrichment = dedupSortedEnrichment(f.Enrichment)
	return nil
}

// dedupSortedEnrichment sorts a finding's enrichment by source and drops exact
// repeats.
//
// Sorted because the loop above appends in identifier order, so a finding
// carrying two enriched CVEs would otherwise present its prose in the order its
// identifiers happen to sort in — the same dependence on incidental ordering
// sortRatings exists to remove, one field over. Source is the key the brief
// names; the remaining fields follow it so the comparator is a total order and
// a genuine tie cannot be left to sort.Slice, which is not stable.
//
// Deduplicated because one KISA notice naming several CVEs becomes one stored
// record PER CVE (knvd.convert), all carrying the same title, summary and link.
// A finding that grouped two of those CVEs would print the same Korean
// paragraph twice, which reads as two authorities agreeing when it is one
// notice counted twice. Exact repeats only — two different notices about one
// CVE are two things a reader wants.
func dedupSortedEnrichment(es []Enrichment) []Enrichment {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		return a.Summary < b.Summary
	})
	// Compact removes ADJACENT repeats only, which is exactly right after a
	// sort keyed on every field: two equal entries cannot be separated by a
	// third that sorts between them.
	return slices.Compact(es)
}

// groupsOf returns the findings that ids already belong to, lowest index
// first, without repeats. More than one means this record links groups that
// were built separately.
//
// Sorted rather than returned in the order the identifiers happen to be listed
// on the record, so which finding absorbs the others is a property of the scan
// and not of how one advisory ordered its aliases.
func groupsOf(group map[string]int, ids []string) []int {
	var out []int
	for _, id := range ids {
		idx, ok := group[id]
		if !ok || slices.Contains(out, idx) {
			continue
		}
		out = append(out, idx)
	}
	sort.Ints(out)
	return out
}

// absorb folds the finding at src into the one at dst and empties src.
//
// The emptied entry is left in place and dropped after the package loop
// finishes, because every value in group is an index into this slice and
// removing an element here would silently repoint all of them.
func absorb(findings []Finding, group map[string]int, dst, src int) {
	d, s := &findings[dst], &findings[src]
	d.Ratings = append(d.Ratings, s.Ratings...)
	d.Identifiers = append(d.Identifiers, s.Identifiers...)
	if beats(winnerOf(*s), winnerOf(*d)) {
		d.Advisory, d.Evidence = s.Advisory, s.Evidence
		d.MatchedName = s.MatchedName
		d.Severity, d.Score = s.Severity, s.Score
	}
	s.Ratings = nil
	for id, idx := range group {
		if idx == src {
			group[id] = dst
		}
	}
}

// lookupIDs is every name a record answers to, for display and lookup rather
// than for grouping — so unlike identifiers() it includes upstream (D3).
//
// Which field carries the CVE depends on the ecosystem, and the two measured
// cases are exact mirror images: on the live Go dump all 8,510 records have an
// empty upstream and carry the CVE in aliases, while on the live Alpine dump
// all 4,405 have an empty aliases and carry it in upstream.
func lookupIDs(a advisory.Advisory) []string {
	out := make([]string, 0, 1+len(a.Aliases)+len(a.Upstream))
	out = append(out, a.ID)
	out = append(out, a.Aliases...)
	return append(out, a.Upstream...)
}

// dedupSorted sorts and removes blanks and repeats. Two records describing one
// vulnerability name most of the same identifiers, so the union is mostly
// overlap; sorting keeps the rendered list from depending on arrival order.
func dedupSorted(ids []string) []string {
	sort.Strings(ids)
	out := ids[:0]
	var prev string
	for i, id := range ids {
		if id == "" || (i > 0 && id == prev) {
			continue
		}
		prev = id
		out = append(out, id)
	}
	return out
}

// winnerOf is the rating that set a finding's band — the record it displays.
//
// Reconstructed from the finding rather than tracked beside it: Advisory,
// Severity and Score are only ever assigned together, so this is exact, and it
// leaves Ratings free to be sorted without disturbing anything.
func winnerOf(f Finding) Rating {
	return Rating{
		Database:   f.Advisory.Database,
		AdvisoryID: f.Advisory.ID,
		Severity:   f.Severity,
		Score:      f.Score,
	}
}

// vectorsOf unwraps the CVSS vector strings carried on an advisory. It does
// no picking of its own — severity.Highest already skips what does not score
// and takes the worst of what does — this only exists because Advisory.Severity
// is a slice of (type, vector) pairs and Highest wants the vectors alone.
func vectorsOf(a advisory.Advisory) []string {
	vectors := make([]string, 0, len(a.Severity))
	for _, s := range a.Severity {
		vectors = append(vectors, s.Score)
	}
	return vectors
}

// identifiers returns the IDs that denote the same vulnerability as a: its own
// and its aliases.
//
// Upstream is deliberately excluded. OSV defines it as "derived from", not as
// identity, so a record can declare an upstream it is not the same
// vulnerability as.
//
// The reason for excluding it changed when findings started keeping every
// record's rating. It used to be a false-negative argument — a wrongly joined
// record was dropped and its advisory never reported. That is no longer true:
// a joined record contributes a Rating carrying its own severity and fixed
// version, so nothing disappears. What survives is the weaker but still
// sufficient argument that merging two distinct vulnerabilities into one
// finding reports one row where two are owed, and understates the work.
//
// Upstream is still read for the KISA join (D3), which asks a different
// question: which records describe the same CVE, not which are the same
// finding. Measured on the live Go dump, upstream is empty on all 8,510
// records while aliases already carry the CVE, GO- and BIT- identifiers, so
// leaving it out costs nothing today either.
func identifiers(a advisory.Advisory) []string {
	ids := make([]string, 0, 1+len(a.Aliases))
	ids = append(ids, a.ID)
	ids = append(ids, a.Aliases...)
	return ids
}

// Sorting keeps output deterministic and diffable, which is design goal #3.
//
// Both comparators key all the way down to something that distinguishes any
// two distinct entries. A partial key would leave ties to sort.Slice, which is
// not stable, so two runs over identical input could order them differently —
// the exact churn the goal forbids. SliceStable is used as well, so that even
// a genuine tie resolves the same way every time.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		if a.Advisory.ID != b.Advisory.ID {
			return a.Advisory.ID < b.Advisory.ID
		}
		if a.Package.PURL != b.Package.PURL {
			return a.Package.PURL < b.Package.PURL
		}
		// Two installs of one package at one version share a purl and differ
		// only in where they were found — nested node_modules produce exactly
		// that. Location is the last thing that tells them apart.
		return locationKey(a.Package) < locationKey(b.Package)
	})
}

// sortRatings orders a finding's ratings by database, then by advisory ID.
//
// Without it they would come out in whichever order the package index listed
// the records — reintroducing, in the output, the exact dependence on
// incidental ordering that D25 removes from the verdict. Two records from one
// database are possible (a database can issue a second record for the same
// CVE), so the ID is needed to make this a total order.
func sortRatings(rs []Rating) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Database != rs[j].Database {
			return rs[i].Database < rs[j].Database
		}
		return rs[i].AdvisoryID < rs[j].AdvisoryID
	})
}

func sortSkipped(ss []Skipped) {
	sort.SliceStable(ss, func(i, j int) bool {
		a, b := ss[i], ss[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Package.PURL != b.Package.PURL {
			return a.Package.PURL < b.Package.PURL
		}
		return locationKey(a.Package) < locationKey(b.Package)
	})
}

// locationKey renders every location a package was found at into one
// comparable string, so the comparators above are genuinely total orders.
//
// Reading only Locations[0] would leave two installs that agree on their first
// location but differ later comparing equal, and their order would then depend
// on input order surviving unchanged. LayerDigest is included because image
// scanning will populate it, and two copies of a package in different layers
// are different findings.
func locationKey(p pkgmeta.Package) string {
	var b strings.Builder
	for i, l := range p.Locations {
		if i > 0 {
			b.WriteString("\x00")
		}
		b.WriteString(l.Path)
		b.WriteString("\x00")
		b.WriteString(l.LayerDigest)
	}
	return b.String()
}
