package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

var (
	bucketAdvisories = []byte("advisories") // "<ecosystem>\x00<name>"   -> []advisory ID
	bucketByID       = []byte("by-id")      // "<advisory ID>"           -> the record, once
	bucketMeta       = []byte("meta")
	bucketRatings    = []byte("ratings")    // "<CVE>\x00<Source>" -> the Rating record, once
	bucketEnrichment = []byte("enrichment") // "<CVE>\x00<Source>" -> the Enrichment record, once
)

var allBuckets = [][]byte{bucketAdvisories, bucketByID, bucketMeta, bucketRatings, bucketEnrichment}

// keySep is NUL because no real ecosystem or package identifier can contain
// one. A printable separator would collide: distro ecosystem keys already
// carry a colon internally (Alpine:v3.19).
const keySep = "\x00"

type Bolt struct {
	db *bolt.DB
}

// Drift in either interface should fail the build here, not at the first
// caller that happens to assign one.
var (
	_ Store  = (*Bolt)(nil)
	_ Writer = (*Bolt)(nil)
)

// Open opens an existing database read-only. A missing or schema-mismatched
// database is an error, never an empty result: the scan path must exit 2 with
// instructions rather than reporting a clean scan it did not perform (D14).
func Open(path string) (*Bolt, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%w at %s", ErrNotFound, path)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	b := &Bolt{db: db}
	m, err := b.Meta()
	if err != nil {
		db.Close()
		return nil, err
	}
	// The metadata record is written once, last, by SetMeta. Its absence means
	// the build did not finish — and an unfinished database is the dangerous
	// case, because its buckets exist and its lookups succeed with empty
	// results. Requiring the record makes "complete" structural rather than
	// something an external temp-file-and-rename discipline has to guarantee.
	if m.Schema == 0 {
		db.Close()
		return nil, fmt.Errorf("%w at %s: no metadata record, so the last `assay db build` or `assay db update` did not finish", ErrIncomplete, path)
	}
	if m.Schema != SchemaVersion {
		db.Close()
		return nil, fmt.Errorf("%w: found v%d, want v%d", ErrSchemaMismatch, m.Schema, SchemaVersion)
	}
	return b, nil
}

// Create makes a fresh database for writing. Callers build into a temporary
// path and rename over the live database so a concurrent scan never observes a
// partial write.
func Create(path string) (*Bolt, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	// Only the bucket structure is created here. The schema is deliberately
	// NOT stamped now: it is written by SetMeta, so its presence is proof the
	// build ran to completion rather than proof that Create was called.
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Bolt{db: db}, nil
}

func (b *Bolt) Close() error { return b.db.Close() }

// Covers reports the ecosystem keys this database holds (D20).
//
// It reads the persisted set rather than scanning the index, because "has at
// least one record" is not the question: records keep affected entries for
// ecosystems that were never fetched, so an index scan says yes for archives
// nobody downloaded.
func (b *Bolt) Covers() (map[string]bool, error) {
	m, err := b.Meta()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(m.Ecosystems))
	for _, e := range m.Ecosystems {
		out[e] = true
	}
	return out, nil
}

// Put stores one advisory once in by-id and appends its ID to the lookup key of
// every package it affects. Storing IDs rather than records is what keeps the
// database from growing by the 1.44x measured duplication factor.
// PutMany stores a batch of advisories in ONE transaction (D57).
//
// Put opens a write transaction per advisory, and a full build makes about
// 150,000 of them. Two costs come off in a batch. The commits: bolt fsyncs on
// each one, so the count is paid in disk round trips. And the index
// read-modify-write: appendID unmarshals the existing ID list for a key,
// scans it, appends and re-marshals, and inside one transaction those pages
// stay in memory across the batch instead of being re-read per advisory.
//
// ALL OR NOTHING, deliberately. A partial batch would leave a database that
// looks complete and holds less, which is the failure this project ranks
// worst — so the transaction rolls back whole and the caller fails the build.
// Put's per-advisory granularity is the thing being traded away, and that is
// the right trade only because a build that loses records is not a build
// anyone should publish.
//
// The batch is bounded by the caller, not here: bolt holds a transaction's
// dirty pages in memory until commit, so an unbounded one would grow with
// the corpus.
func (b *Bolt) PutMany(as []advisory.Advisory) error {
	if len(as) == 0 {
		return nil
	}
	// Marshalled before the transaction opens. A write transaction blocks
	// every other writer for as long as it is held, and JSON encoding is
	// not work that needs the lock.
	blobs := make([][]byte, len(as))
	for i, a := range as {
		blob, err := json.Marshal(a)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", a.ID, err)
		}
		blobs[i] = blob
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		byID := tx.Bucket(bucketByID)
		idx := tx.Bucket(bucketAdvisories)
		for i, a := range as {
			if err := byID.Put([]byte(a.ID), blobs[i]); err != nil {
				return err
			}
			for _, aff := range a.Affected {
				if aff.Ecosystem == "" || aff.Name == "" {
					continue
				}
				key := aff.Ecosystem + keySep + pkgmeta.NormalizeName(aff.Ecosystem, aff.Name)
				if err := appendID(idx, key, a.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (b *Bolt) Put(a advisory.Advisory) error {
	blob, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", a.ID, err)
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketByID).Put([]byte(a.ID), blob); err != nil {
			return err
		}
		idx := tx.Bucket(bucketAdvisories)
		for _, aff := range a.Affected {
			if aff.Ecosystem == "" || aff.Name == "" {
				continue
			}
			key := aff.Ecosystem + keySep + pkgmeta.NormalizeName(aff.Ecosystem, aff.Name)
			if err := appendID(idx, key, a.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

func appendID(bk *bolt.Bucket, key, id string) error {
	var ids []string
	if raw := bk.Get([]byte(key)); raw != nil {
		if err := json.Unmarshal(raw, &ids); err != nil {
			return fmt.Errorf("decode index %q: %w", key, err)
		}
		for _, existing := range ids {
			if existing == id {
				return nil
			}
		}
	}
	ids = append(ids, id)
	blob, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return bk.Put([]byte(key), blob)
}

// PutRating stores one authority's opinion about a CVE, keyed on (CVE,
// Source) so several authorities can rate the same CVE and a re-Put of the
// same source replaces its record rather than duplicating it. Severity is
// stored exactly as given -- a CVSS vector, never a computed band (D13) -- so
// a scoring fix later is a code change, not a database rebuild.
func (b *Bolt) PutRating(r advisory.Rating) error {
	blob, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal rating %s/%s: %w", r.CVE, r.Source, err)
	}
	key := r.CVE + keySep + r.Source
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRatings).Put([]byte(key), blob)
	})
}

// PutEnrichment stores one authority's prose about a CVE, keyed on (CVE,
// Source) exactly like PutRating -- so several authorities can describe the
// same CVE and a re-Put of the same source replaces its record rather than
// duplicating it.
func (b *Bolt) PutEnrichment(e advisory.Enrichment) error {
	blob, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal enrichment %s/%s: %w", e.CVE, e.Source, err)
	}
	key := e.CVE + keySep + e.Source
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketEnrichment).Put([]byte(key), blob)
	})
}

func (b *Bolt) SetMeta(m Meta) error {
	m.Schema = SchemaVersion
	// Coverage is the union of what each provider reported (D20). It is not
	// derived from what Put indexed: records keep affected entries for
	// ecosystems that were never fetched, so that set over-claims.
	seen := map[string]struct{}{}
	for _, prov := range m.Providers {
		for _, e := range prov.Ecosystems {
			seen[e] = struct{}{}
		}
	}
	m.Ecosystems = slices.Sorted(maps.Keys(seen))

	return b.db.Update(func(tx *bolt.Tx) error {
		// Databases (D25) is read from what this build actually stored, not
		// from provider self-report: each record names only its own
		// authoring database, so there is nothing to over-claim the way a
		// stored ecosystem entry can.
		//
		// This scan adds a new way for SetMeta to fail: a record that will
		// not decode aborts an otherwise-finished build (the temp-file build
		// in dbcmd.Update discards it and leaves the live database
		// untouched). That is deliberate, not incidental — a build that
		// cannot read back what it just wrote is not one a scan should ever
		// see, and refusing here is the same "fail loudly" rule Lookup
		// applies to a dangling index entry.
		dbs := map[string]struct{}{}
		if err := tx.Bucket(bucketByID).ForEach(func(id, blob []byte) error {
			var a advisory.Advisory
			if err := json.Unmarshal(blob, &a); err != nil {
				return fmt.Errorf("decode advisory %q: %w", id, err)
			}
			// Database is empty here only if it was never set. In practice
			// that cannot happen today: databaseOf returns "" only for an ID
			// with no dash (or one starting with a dash), and Convert
			// rejects an empty ID before Database is ever computed, so every
			// record osv/record.go emits has a non-empty Database. Guarded
			// explicitly anyway because this scan does not know how a
			// record was built — a future provider that leaves Database
			// unset would otherwise pollute this set with an unlabelled ""
			// entry. If that happens, the fix is a skip counter next to the
			// one D20 already keeps for coverage, not a silent drop here.
			if a.Database != "" {
				dbs[a.Database] = struct{}{}
			}
			return nil
		}); err != nil {
			return err
		}
		m.Databases = slices.Sorted(maps.Keys(dbs))

		// RatingCounts (D27) is read from the ratings bucket actually
		// stored, not from annotator self-report, exactly the reasoning
		// above for Databases: a rating's Source is the tail of its own key
		// ("<CVE>\x00<Source>"), so trusting a self-reported count would let
		// an annotator that ran and rated nothing (or fewer than it claims)
		// still make db status assert a source that rated something — the
		// same over-claim D20 refuses to let a stored ecosystem entry make.
		//
		// Derived from the key alone, never by decoding each stored blob —
		// see countBySource, which both this and the enrichment count below
		// go through.
		counts, err := countBySource(tx.Bucket(bucketRatings))
		if err != nil {
			return err
		}
		m.RatingCounts = counts

		// EnrichmentCounts (D3) is derived exactly as RatingCounts is, and for
		// exactly the reason above: a third source kind arriving next to the
		// one that already over-claimed gets the derived treatment from the
		// start rather than after the same review finds it again.
		enriched, err := countBySource(tx.Bucket(bucketEnrichment))
		if err != nil {
			return err
		}
		m.EnrichmentCounts = enriched

		blob, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put([]byte("meta"), blob)
	})
}

// countBySource counts a bucket's entries per authoring source, reading the
// source out of the key ("<CVE>\x00<Source>") rather than decoding each
// stored blob: PutRating and PutEnrichment both build the key that way, so
// there is nothing in the value this scan needs.
//
// Shared by the ratings and enrichment buckets because they are keyed
// identically and the rule is the same one (counts are derived, never
// self-reported). This is not the shared-comparer mistake D9 forbids —
// nothing here is per-ecosystem, and there is no upstream disagreement for a
// single implementation to paper over.
//
// An entry whose key carries no separator, or an empty source, is skipped
// rather than counted under "": a key that shape cannot have been written by
// either Put method, and inventing an unnamed source for it would put a
// nameless row in `db status`.
func countBySource(bk *bolt.Bucket) (map[string]int, error) {
	counts := map[string]int{}
	err := bk.ForEach(func(k, _ []byte) error {
		_, source, ok := bytes.Cut(k, []byte(keySep))
		if ok && len(source) > 0 {
			counts[string(source)]++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}

// StripEnrichment empties the enrichment bucket of the database at path, and
// removes the metadata describing it (D29).
//
// KISA's site is all-rights-reserved with no 공공누리 mark. That does not
// restrict scanning with the data; it restricts REDISTRIBUTING it, and
// `db push` redistributes. So `db build` fills this bucket, `db push` strips
// it from the copy it packs, and `db update` therefore never delivers it.
//
// It lives here rather than in dbcmd because the bucket names are this
// package's, and a caller reaching for bbolt directly to delete one would put
// the on-disk shape in two places.
//
// The bucket is recreated EMPTY rather than left absent. EnrichmentFor and
// EachEnrichment dereference it directly, so a database with no enrichment
// bucket at all would panic on the first lookup instead of answering
// "nothing" — and the artifact this produces is what every `db update` user
// then scans with.
//
// The metadata goes with it. Leaving Meta.Enrichment behind would publish an
// artifact naming a source and a count for a bucket it deliberately does not
// carry, which is the same over-claim `db status` has already been fixed for
// twice, arriving this time through the publish path.
//
// THIS IS NOT ENOUGH ON ITS OWN TO MAKE A FILE PUBLISHABLE. Deleting a bucket
// frees its pages; it does not zero them, and the records stay legible in the
// file's bytes. Every caller that publishes must follow this with CompactInto,
// which copies the live data out into a fresh file -- see its doc comment for
// the measurement.
func StripEnrichment(path string) error {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return fmt.Errorf("open %s for stripping: %w", path, err)
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketEnrichment) != nil {
			if err := tx.DeleteBucket(bucketEnrichment); err != nil {
				return fmt.Errorf("delete enrichment bucket: %w", err)
			}
		}
		if _, err := tx.CreateBucketIfNotExists(bucketEnrichment); err != nil {
			return fmt.Errorf("recreate enrichment bucket: %w", err)
		}
		bk := tx.Bucket(bucketMeta)
		if bk == nil {
			return ErrNotFound
		}
		raw := bk.Get([]byte("meta"))
		if raw == nil {
			// No metadata record means the build never finished, and Open
			// refuses such a database anyway. Nothing to un-claim.
			return nil
		}
		var m Meta
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("decode metadata: %w", err)
		}
		m.Enrichment, m.EnrichmentCounts = nil, nil
		blob, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return bk.Put([]byte("meta"), blob)
	})
}

// compactTxMaxSize bounds one write transaction during CompactInto, so a
// 244 MB database does not have to fit in a single transaction's memory.
// bbolt commits and reopens whenever the running total would exceed it.
const compactTxMaxSize = 64 << 10

// CompactInto writes a fresh database at dst holding the LIVE data of the
// database at src, and nothing else. dst must not already exist -- bbolt's
// Compact creates each bucket as it walks, which fails against a file that
// already has them.
//
// This exists because StripEnrichment alone does not make a file publishable
// (D29). DeleteBucket FREES the pages that held those records; it does not
// zero them, and dbartifact.Pack gzips the whole file, freed pages included.
// A final review measured it against this tree: a database with 200
// enrichment records, stripped in place, still yielded 546 occurrences of
// their text in the 131,072-byte result -- recoverable from the published
// layer with `gunzip` and `strings`. Reading the stripped file back through
// EnrichmentFor said "nothing", because the bucket API is the level above
// where the data survives.
//
// Copying live data OUT is what fixes that: Compact walks src's live pages
// into a new file, and a page freed by the strip is not a live page. So the
// order is load-bearing -- strip src first, compact second. Compacting before
// the strip would faithfully copy the records across.
func CompactInto(dst, src string) error {
	// Read-only: the source here is the caller's staged copy, but nothing
	// about producing a publishable file should be able to write to it.
	srcDB, err := bolt.Open(src, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("open %s to compact: %w", src, err)
	}
	defer srcDB.Close()
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("compact into %s: file already exists", dst)
	}
	dstDB, err := bolt.Open(dst, 0o600, nil)
	if err != nil {
		return fmt.Errorf("create %s to compact into: %w", dst, err)
	}
	if err := bolt.Compact(dstDB, srcDB, compactTxMaxSize); err != nil {
		dstDB.Close()
		return fmt.Errorf("compact %s into %s: %w", src, dst, err)
	}
	// Closed explicitly rather than deferred, and its error returned: this is
	// the point the publishable bytes reach the disk, and a caller that packs
	// a file whose last commit failed publishes a truncated database.
	if err := dstDB.Close(); err != nil {
		return fmt.Errorf("close %s after compacting: %w", dst, err)
	}
	return nil
}

func (b *Bolt) setSchemaForTest(v int) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		blob, err := json.Marshal(Meta{Schema: v})
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put([]byte("meta"), blob)
	})
}

// Lookup answers for one name. A caller matching a distro package calls this
// twice -- once with the binary name, once with the source name (D8) -- because
// OSV writes the source name into Affected[].Name, which Put already indexes.
func (b *Bolt) Lookup(ecosystem, name string) ([]advisory.Advisory, error) {
	return b.resolve(bucketAdvisories, ecosystem+keySep+pkgmeta.NormalizeName(ecosystem, name))
}

func (b *Bolt) resolve(index []byte, key string) ([]advisory.Advisory, error) {
	var out []advisory.Advisory
	err := b.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(index).Get([]byte(key))
		if raw == nil {
			return nil
		}
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return fmt.Errorf("decode index %q: %w", key, err)
		}
		byID := tx.Bucket(bucketByID)
		for _, id := range ids {
			blob := byID.Get([]byte(id))
			if blob == nil {
				// A dangling index entry means the database is inconsistent.
				// Fail loudly rather than returning a short list that reads as
				// "fewer vulnerabilities".
				return fmt.Errorf("index %q references missing advisory %q", key, id)
			}
			var a advisory.Advisory
			if err := json.Unmarshal(blob, &a); err != nil {
				return fmt.Errorf("decode advisory %q: %w", id, err)
			}
			out = append(out, a)
		}
		return nil
	})
	return out, err
}

// RatingsFor answers every authority's opinion about one CVE, sorted by
// Source so two runs against the same database agree. An unrated CVE is a
// normal answer -- the matcher asks this for every finding -- so it returns
// an empty slice and a nil error rather than treating a miss as a failure.
func (b *Bolt) RatingsFor(cve string) ([]advisory.Rating, error) {
	prefix := []byte(cve + keySep)
	var out []advisory.Rating
	err := b.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRatings).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var r advisory.Rating
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("decode rating %q: %w", k, err)
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The explicit sort is redundant against a bbolt cursor today -- keys are
	// stored in byte order and Source is the tail of "<CVE>\x00<Source>", so a
	// Seek over one CVE's prefix already yields entries ordered by Source.
	// Kept anyway: it makes the guarantee a property of RatingsFor's contract
	// rather than an accident of the key layout, so a future change to the key
	// shape (or to how entries are collected) cannot silently reintroduce
	// nondeterminism.
	slices.SortFunc(out, func(a, b advisory.Rating) int {
		return strings.Compare(a.Source, b.Source)
	})
	return out, nil
}

// EachRating walks every stored rating in key order, which is what a
// seeded build copies forward. Key order is bbolt's own byte order, so
// two runs over the same database visit the same sequence -- this adds no
// nondeterminism to a build (see Meta's own sorted fields for why that
// matters).
func (b *Bolt) EachRating(fn func(advisory.Rating) error) error {
	return b.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRatings).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r advisory.Rating
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("decode rating %q: %w", k, err)
			}
			if err := fn(r); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnrichmentFor answers every authority's prose about one CVE, sorted by
// Source so two runs against the same database agree. An un-enriched CVE is a
// normal answer -- the matcher asks this for every finding, and most CVEs
// have no Korean notice -- so it returns an empty slice and a nil error
// rather than treating a miss as a failure.
func (b *Bolt) EnrichmentFor(cve string) ([]advisory.Enrichment, error) {
	prefix := []byte(cve + keySep)
	var out []advisory.Enrichment
	err := b.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEnrichment).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var e advisory.Enrichment
			if err := json.Unmarshal(v, &e); err != nil {
				return fmt.Errorf("decode enrichment %q: %w", k, err)
			}
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Redundant against bbolt's byte-ordered keys today -- Source is the tail
	// of "<CVE>\x00<Source>", so a Seek over one CVE's prefix already yields
	// entries in Source order -- kept for the same reason RatingsFor keeps
	// its own: the guarantee belongs to EnrichmentFor's contract, not to an
	// accident of the key layout that a future change could undo silently.
	slices.SortFunc(out, func(a, b advisory.Enrichment) int {
		return strings.Compare(a.Source, b.Source)
	})
	return out, nil
}

// EachEnrichment walks every stored enrichment in key order, which is what a
// seeded build copies forward -- the same reasoning as EachRating, one bucket
// over.
func (b *Bolt) EachEnrichment(fn func(advisory.Enrichment) error) error {
	return b.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketEnrichment).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e advisory.Enrichment
			if err := json.Unmarshal(v, &e); err != nil {
				return fmt.Errorf("decode enrichment %q: %w", k, err)
			}
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	})
}

func (b *Bolt) Meta() (Meta, error) {
	var m Meta
	err := b.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMeta)
		if bk == nil {
			return ErrNotFound
		}
		// A zero Meta when the record is absent is the signal Open relies on:
		// there is deliberately no fallback that could report a schema for a
		// database that never finished building.
		if raw := bk.Get([]byte("meta")); raw != nil {
			return json.Unmarshal(raw, &m)
		}
		return nil
	})
	return m, err
}

// RecordCount reports how many advisories are stored, independent of how many
// index entries point at them.
func (b *Bolt) RecordCount() int {
	var n int
	_ = b.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucketByID).Stats().KeyN
		return nil
	})
	return n
}
