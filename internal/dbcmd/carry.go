package dbcmd

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// carryNow is the seam for "today" in the entry-level rule's past-EOL
// judgement (D110), the same shape as scancmd's clockNow (D87): EOL is derived
// by comparing a catalog row's last end date against the moment the build
// runs, so a test pins it to drive both sides of the boundary.
var carryNow = time.Now

// mergeAffected is the one write carry-forward makes, held in a variable so a
// test can observe the batch sizes it is called with -- "merges are batched"
// (D57) is otherwise invisible from the outside, since one big transaction
// stores exactly the same records.
var mergeAffected = (*store.Bolt).MergeAffected

// carryResult is what carryForward did, for the lines Update prints after it.
type carryResult struct {
	// ran is whether the seed's records were read at all. They are read on
	// every seeded, non-ratings-only build, even with nothing to carry,
	// because the per-key count lines take their old counts from that pass;
	// without it there are no seed counts to print against.
	ran bool
	// records is how many records carry-forward wrote (inserted or merged
	// into); added is how many of those this run had not emitted at all.
	records, added int
	// seedCounts is the seed's advisory count per key, once per record per
	// key -- AdvisoryCounts' rule, gathered in the same pass.
	seedCounts map[string]int
}

// sharedKeys names every ecosystem key more than one provider declared this
// run, one message per key, sorted so the refusal reads the same every night.
func sharedKeys(providers map[string]store.Provenance) []string {
	owners := map[string][]string{}
	for _, name := range sortedKeys(providers) {
		for _, eco := range providers[name].Ecosystems {
			// A provider that lists a key twice is not two providers.
			if o := owners[eco]; len(o) > 0 && o[len(o)-1] == name {
				continue
			}
			owners[eco] = append(owners[eco], name)
		}
	}
	var out []string
	for _, eco := range sortedKeys(owners) {
		names := owners[eco]
		if len(names) < 2 {
			continue
		}
		list := strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
		out = append(out, fmt.Sprintf("providers %s both declare %s", list, eco))
	}
	return out
}

// pastEOLKeys builds the set of ecosystem keys whose release is past the LAST
// of its end dates (EOLFrom, EOASFrom, EOESFrom) as of now, from this build's
// D87 catalog rows, each mapped to that latest date. Each row is turned
// into a key through pkgmeta.Distro.Ecosystem() -- the function a scan keys
// its own packages with -- and never by string surgery on key names: a key
// spelled here any other way could drift from the one advisories are stored
// under (SLES's ".SP" fold, Ubuntu's ":LTS", Alpine's "v") and silently
// restore nothing, or restore the wrong release.
//
// The question here is "has the upstream fully stopped", not "did standard
// support end", so EOLFrom alone is the wrong date. Debian 12 is past its
// EOLFrom (security support, 2026-06-10) yet Debian LTS maintains it to 2028,
// and a narrowing on it is a correction that must stand; Debian 11's LTS
// ended 2026-08-31, and only then did its OSV entries leave. The latest
// published phase end tells the two apart where EOLFrom cannot. A row with
// only EOLFrom (Amazon Linux 2's shape) is judged by that one date.
// IsMaintained is deliberately not consulted: endoflife.date sets it under a
// third party's extended support too (see store.EOLRelease), which is exactly
// the misfire that would freeze a key the upstream still serves.
//
// A row Ecosystem() rejects is skipped and counted, not guessed at. A date
// that is empty or does not parse is ignored, and a row with none that
// parses is not past EOL: an unpublished date is not evidence the release
// ended, and a live key's entries are never restored. "Past" is strictly
// after, endoflife.date's own isEol semantics, the same comparison
// scancmd.eolStatusFromRow makes.
func pastEOLKeys(rows []store.EOLRelease, now time.Time) (map[string]string, int) {
	past := map[string]string{}
	rejected := 0
	for _, row := range rows {
		key, err := pkgmeta.Distro{ID: row.DistroID, VersionID: row.Release}.Ecosystem()
		if err != nil {
			rejected++
			continue
		}
		var last time.Time
		lastRaw := ""
		for _, raw := range []string{row.EOLFrom, row.EOASFrom, row.EOESFrom} {
			d, err := time.Parse("2006-01-02", raw)
			if err != nil {
				continue
			}
			if lastRaw == "" || d.After(last) {
				last, lastRaw = d, raw
			}
		}
		if lastRaw == "" || !now.After(last) {
			continue
		}
		past[key] = lastRaw
	}
	return past, rejected
}

// freezeSince is the freeze time for key: the seed's existing Frozen[key] if
// it had one -- the FIRST night the key's data stopped arriving, carried
// unchanged on every later night rather than refreshed (D12) -- otherwise the
// seed provider's DataAsOf, when the data being carried was last current.
func freezeSince(seedMeta store.Meta, name, key string) time.Time {
	if p, ok := seedMeta.Providers[name]; ok && slices.Contains(p.Ecosystems, key) {
		if since, ok := p.Frozen[key]; ok {
			return since
		}
		return p.DataAsOf
	}
	// The key's seed owner under another name: a provider rename between two
	// builds. Its provenance is still the truest date there is.
	for _, n := range sortedKeys(seedMeta.Providers) {
		p := seedMeta.Providers[n]
		if slices.Contains(p.Ecosystems, key) {
			if since, ok := p.Frozen[key]; ok {
				return since
			}
			return p.DataAsOf
		}
	}
	// No seed provider declared it at all. The seed's build time is an upper
	// bound on how fresh its data can be, which errs old, never fresh.
	return seedMeta.BuiltAt
}

// carryForward is D110. Two rules, one read of the seed's records:
//
//   - Whole-key. A key a provider that RAN declared in the seed and did not
//     declare this run is copied from the seed in full -- each seed record cut
//     down to its entries under that key, so a record the provider stopped
//     emitting under a live key does not come back there (D16) -- and stays
//     declared, marked Frozen. A provider that did not run, or whose fetch
//     failed (that aborted the build before this, R1), carries nothing: the
//     publish guard's refusal is the right answer to a broken run.
//   - Entry-level, past EOL only. For a key this run's provider still
//     declares whose release is past the last of its end dates (see
//     pastEOLKeys) in THIS build's D87 catalog, a
//     seed record carrying an entry under it that this run re-emitted
//     WITHOUT one gets the seed's entries for that key back. A seed record
//     this run did not re-emit at all is a withdrawal (D16) and is not
//     inserted. A live key not past EOL is never touched: a record narrowing
//     on a maintained release is the upstream correcting itself (Canonical's
//     tracker, D85), measured as every live-key entry removal but Debian:11's
//     in 28 days.
//
// The seed is read by its by-id records, never its index (store.EachAdvisory),
// so a seed one schema behind is carried from like a current one. It is read
// on every call, even when no key needs carrying, because the per-key count
// lines take their old counts from this pass; a 1.5M-record pass costs
// ~18.6 s, accepted for a signal that must not go silent. Writes go
// through MergeAffected in batches of putBatchSize (D57) -- the largest key
// in the database cannot be merged in one transaction.
//
// running is updated in place: a whole-key key is appended to its provider's
// Ecosystems, and every key carry-forward wrote to gets Frozen[key].
func carryForward(seedPath, label string, w *store.Bolt, running map[string]store.Provenance, seedMeta store.Meta, eolRows []store.EOLRelease, stderr io.Writer) (carryResult, error) {
	// owner is who declared each key this run; unique, because Update refused
	// a shared key before calling this.
	owner := map[string]string{}
	for name, prov := range running {
		for _, eco := range prov.Ecosystems {
			owner[eco] = name
		}
	}

	whole := map[string]string{} // key -> the provider that ran and stopped emitting it
	for _, name := range sortedKeys(running) {
		seedProv, ok := seedMeta.Providers[name]
		if !ok {
			continue
		}
		for _, eco := range seedProv.Ecosystems {
			if _, live := owner[eco]; !live {
				whole[eco] = name
			}
		}
	}

	entry := map[string]string{} // live, past-EOL key -> its last end date
	if len(eolRows) == 0 {
		// EOL_ENABLE=0 (a failed EOL fetch aborts the build, D87, so it never
		// reaches here). Without a catalog no key can be judged past EOL, and
		// guessing would restore narrowings on live keys.
		fmt.Fprintln(stderr, "entry-level carry-forward skipped: this build has no end-of-life rows (EOL_ENABLE=0), so no key can be judged past EOL; whole-key carry-forward still runs")
	} else {
		past, rejected := pastEOLKeys(eolRows, carryNow())
		if rejected > 0 {
			fmt.Fprintf(stderr, "entry-level carry-forward: %d end-of-life row(s) name no ecosystem key this build can derive; skipped\n", rejected)
		}
		for key, from := range past {
			if _, live := owner[key]; live {
				entry[key] = from
			}
		}
	}

	// No early return when nothing needs carrying: the same pass gathers the
	// seed counts printKeyCounts reports against, and those lines are the
	// nightly's erosion signal on every seeded build, not only on one that
	// carried.
	src, err := store.OpenSeedRecords(seedPath)
	if err != nil {
		return carryResult{}, fmt.Errorf("open seed %s: %w", label, err)
	}
	defer src.Close()

	res := carryResult{ran: true, seedCounts: map[string]int{}}
	wholeN := map[string]int{}
	restored := map[string]int{}
	withdrawn := map[string]int{}
	pending := make([]advisory.Advisory, 0, putBatchSize)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		added, err := mergeAffected(w, pending)
		res.added += added
		res.records += len(pending)
		pending = pending[:0]
		return err
	}

	err = src.EachAdvisory(func(a advisory.Advisory) error {
		// The record's keys in first-appearance order, so the entries a merge
		// appends land in the order the seed held them, not map order.
		var keys []string
		for _, aff := range a.Affected {
			if !slices.Contains(keys, aff.Ecosystem) {
				keys = append(keys, aff.Ecosystem)
			}
		}
		var carried []advisory.Affected
		for _, key := range keys {
			res.seedCounts[key]++
			if _, ok := whole[key]; ok {
				wholeN[key]++
				carried = append(carried, entriesUnder(a, key)...)
			}
		}
		var eol []string
		for _, key := range keys {
			if _, ok := entry[key]; ok {
				eol = append(eol, key)
			}
		}
		if len(eol) > 0 {
			cur, found, err := w.Advisory(a.ID)
			if err != nil {
				return err
			}
			for _, key := range eol {
				switch {
				case !found:
					withdrawn[key]++
				case slices.ContainsFunc(cur.Affected, func(x advisory.Affected) bool { return x.Ecosystem == key }):
					// Re-emitted with the key: the fresh entry wins.
				default:
					restored[key]++
					carried = append(carried, entriesUnder(a, key)...)
				}
			}
		}
		if len(carried) == 0 {
			return nil
		}
		c := a
		c.Affected = carried
		pending = append(pending, c)
		if len(pending) < putBatchSize {
			return nil
		}
		return flush()
	})
	if err == nil {
		err = flush()
	}
	if err != nil {
		return res, err
	}

	setFrozen := func(name, key string) time.Time {
		prov := running[name]
		frozen := make(map[string]time.Time, len(prov.Frozen)+1)
		for k, v := range prov.Frozen {
			frozen[k] = v
		}
		since := freezeSince(seedMeta, name, key)
		frozen[key] = since
		prov.Frozen = frozen
		running[name] = prov
		return since
	}
	for _, key := range sortedKeys(whole) {
		name := whole[key]
		prov := running[name]
		ecos := append(slices.Clone(prov.Ecosystems), key)
		slices.Sort(ecos)
		prov.Ecosystems = ecos
		running[name] = prov
		since := setFrozen(name, key)
		fmt.Fprintf(stderr, "%s emitted nothing for %s; carried %d advisories from seed %s, frozen since %s\n",
			name, key, wholeN[key], label, since.Format("2006-01-02"))
	}
	for _, key := range sortedKeys(entry) {
		if restored[key] == 0 && withdrawn[key] == 0 {
			continue
		}
		var parts []string
		if restored[key] > 0 {
			since := setFrozen(owner[key], key)
			parts = append(parts, fmt.Sprintf("restored its entry on %d advisories re-emitted without it, frozen since %s",
				restored[key], since.Format("2006-01-02")))
		}
		if withdrawn[key] > 0 {
			parts = append(parts, fmt.Sprintf("%d not re-emitted at all, left withdrawn (D16)", withdrawn[key]))
		}
		fmt.Fprintf(stderr, "%s (past EOL since %s): %s\n", key, entry[key], strings.Join(parts, "; "))
	}
	return res, nil
}

// entriesUnder is a's Affected entries under key, in their stored order.
func entriesUnder(a advisory.Advisory, key string) []advisory.Affected {
	var out []advisory.Affected
	for _, aff := range a.Affected {
		if aff.Ecosystem == key {
			out = append(out, aff)
		}
	}
	return out
}

// printKeyCounts prints one line per seed key whose advisory count this build
// differs from the seed's -- the nightly log is the consumer. It is how erosion
// on a LIVE key stays visible although D110 deliberately does not reverse it:
// Debian:11's 94% loss would have read "Debian:11: 46365 -> 2562".
//
// The old counts come from carry-forward's own read of the seed rather than
// a second 18-second read, which is why that read happens on every seeded
// build. carry.ran is false only when there was no seed to read.
func printKeyCounts(w *store.Bolt, carry carryResult, providers map[string]store.Provenance, stderr io.Writer) error {
	if !carry.ran {
		return nil
	}
	_, counts, err := w.AdvisoryCounts()
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(carry.seedCounts) {
		old, now := carry.seedCounts[key], counts[key]
		if old == now {
			continue
		}
		suffix := ""
		for _, name := range sortedKeys(providers) {
			if since, ok := providers[name].Frozen[key]; ok {
				suffix = ", frozen since " + since.Format("2006-01-02")
				break
			}
		}
		fmt.Fprintf(stderr, "%s: %d -> %d advisories (%+d%s)\n", key, old, now, now-old, suffix)
	}
	return nil
}
