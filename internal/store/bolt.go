package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	bolt "go.etcd.io/bbolt"

	"github.com/kun9497/assay/internal/advisory"
)

var (
	bucketAdvisories = []byte("advisories") // "<ecosystem>\x00<name>"   -> []advisory ID
	bucketBySource   = []byte("by-source")  // "<ecosystem>\x00<source>" -> []advisory ID
	bucketByID       = []byte("by-id")      // "<advisory ID>"           -> the record, once
	bucketMeta       = []byte("meta")
)

var allBuckets = [][]byte{bucketAdvisories, bucketBySource, bucketByID, bucketMeta}

const keySep = "\x00"

type Bolt struct {
	db *bolt.DB
}

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
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return tx.Bucket(bucketMeta).Put([]byte("schema"),
			[]byte(strconv.Itoa(SchemaVersion)))
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Bolt{db: db}, nil
}

func (b *Bolt) Close() error { return b.db.Close() }

// Put stores one advisory once in by-id and appends its ID to the lookup key of
// every package it affects. Storing IDs rather than records is what keeps the
// database from growing by the 1.44x measured duplication factor.
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
			if err := appendID(idx, aff.Ecosystem+keySep+aff.Name, a.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// PutSourceIndex records that an advisory is keyed on a source package (D8).
func (b *Bolt) PutSourceIndex(ecosystem, sourceName, id string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return appendID(tx.Bucket(bucketBySource), ecosystem+keySep+sourceName, id)
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

func (b *Bolt) SetMeta(m Meta) error {
	m.Schema = SchemaVersion
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte("meta"), blob)
	})
}

// Commit flushes and closes the write handle.
func (b *Bolt) Commit() error { return b.db.Close() }

func (b *Bolt) setSchemaForTest(v int) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		blob, err := json.Marshal(Meta{Schema: v})
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put([]byte("meta"), blob)
	})
}

func (b *Bolt) Lookup(ecosystem, name string) ([]advisory.Advisory, error) {
	return b.resolve(bucketAdvisories, ecosystem+keySep+name)
}

func (b *Bolt) LookupBySource(ecosystem, sourceName string) ([]advisory.Advisory, error) {
	return b.resolve(bucketBySource, ecosystem+keySep+sourceName)
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

func (b *Bolt) Meta() (Meta, error) {
	var m Meta
	err := b.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMeta)
		if bk == nil {
			return ErrNotFound
		}
		if raw := bk.Get([]byte("meta")); raw != nil {
			return json.Unmarshal(raw, &m)
		}
		if raw := bk.Get([]byte("schema")); raw != nil {
			v, err := strconv.Atoi(string(raw))
			if err != nil {
				return err
			}
			m.Schema = v
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
