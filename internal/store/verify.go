package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"

	bolt "go.etcd.io/bbolt"
)

// ErrDamaged marks a database whose contents are not the ones its build
// recorded (D173).
var ErrDamaged = errors.New("vulnerability database is damaged")

// ErrNoDigests marks a database built before contents were recorded.
var ErrNoDigests = errors.New("vulnerability database records no content digests")

// dataBuckets is what the digests cover: everything but the metadata record
// that holds them, which `db update` rewrites after the build (D127).
var dataBuckets = [][]byte{bucketAdvisories, bucketByID, bucketRatings, bucketEnrichment}

// bucketDigest is the sha256 over a bucket's entries in key order, each length
// given before its bytes so no two different contents spell one stream. Over
// the entries rather than the file: `db push` compacts and strips, and
// `db update` writes a record into what it pulled, so a file hash names a
// file no one else has.
//
// Keys must ascend. They do in any healthy tree, and a damaged branch page
// that points back at a page already read would otherwise be walked forever.
func bucketDigest(bk *bolt.Bucket) (digest string, entries int, err error) {
	h := sha256.New()
	var n [8]byte
	write := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var prev []byte
	if bk != nil {
		c := bk.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if entries > 0 && bytes.Compare(k, prev) <= 0 {
				return "", entries, fmt.Errorf("key %q is out of order", k)
			}
			prev = append(prev[:0], k...)
			write(k)
			write(v)
			entries++
		}
	}
	return hex.EncodeToString(h.Sum(nil)), entries, nil
}

// recordDigests fills m.Digests from what tx holds.
func recordDigests(tx *bolt.Tx, m *Meta) error {
	m.Digests = make(map[string]string, len(dataBuckets))
	for _, name := range dataBuckets {
		d, _, err := bucketDigest(tx.Bucket(name))
		if err != nil {
			return fmt.Errorf("digest bucket %s: %w", name, err)
		}
		m.Digests[string(name)] = d
	}
	return nil
}

// Verify reads every entry and compares it with the digests the build
// recorded, returning how many entries it read. bbolt checksums no data page,
// so a page damaged on disk after the install makes lookups miss, with no
// error: a scan of it reads clean (QA 2026-11-20).
//
// A damaged page can also make bbolt panic, or read past the file through its
// memory map; both are the damage being looked for and are returned as it.
func (b *Bolt) Verify() (entries int, err error) {
	m, err := b.Meta()
	if err != nil {
		return 0, err
	}
	if len(m.Digests) == 0 {
		return 0, ErrNoDigests
	}
	err = guarded(func() error {
		return b.db.View(func(tx *bolt.Tx) error {
			for _, name := range dataBuckets {
				got, n, err := bucketDigest(tx.Bucket(name))
				if err != nil {
					return fmt.Errorf("%w: bucket %s: %v", ErrDamaged, name, err)
				}
				entries += n
				if want := m.Digests[string(name)]; got != want {
					return fmt.Errorf("%w: bucket %s does not hold what its build recorded (%d entries read)", ErrDamaged, name, n)
				}
			}
			return nil
		})
	})
	return entries, err
}

// guarded runs read and returns a panic or a memory fault in it as
// ErrDamaged. bbolt trusts its pages, so a damaged one reaches it as an
// out-of-range slice or an address outside the map.
func guarded(read func() error) (err error) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: reading it failed: %v", ErrDamaged, r)
		}
	}()
	return read()
}
