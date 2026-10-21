package store

import (
	"errors"
	"os"
	"time"
)

// ArtifactRecord is what `db update` pulled (D120): the reference it was asked
// for, the manifest digest it got, and when. Since D127 it lives in the
// database's own Meta (Meta.Artifact, written by SetArtifact into the
// unpacked database before it is installed), so the record and the database
// it names are one file: a scan reads both in one open and can never pair a
// database with a record from a different pull. A database with none reports
// no artifact rather than guessing.
//
// It used to be a sidecar, <dbPath>.artifact.json, on the reasoning that the
// database inside the artifact was sealed before publishing and could not
// know its own digest. True of the publisher — but the pull unpacks and opens
// the database before installing it anyway, and that is where the record now
// goes. The sidecar's two renames (database, then record) left a window in
// which a scan read the new database with the old record, and an interrupted
// pull, or the manual move the install-failure message suggests, left that
// pairing in place for good (2026-10-20 external review, #7).
type ArtifactRecord struct {
	Reference string    `json:"reference"`
	Digest    string    `json:"digest"`
	PulledAt  time.Time `json:"pulledAt"`
}

// LegacyArtifactRecordPath is where a pull before D127 left its sidecar. It is
// never read any more: a sidecar beside a database is exactly the pairing
// nothing can vouch for, so it is only ever removed.
func LegacyArtifactRecordPath(dbPath string) string { return dbPath + ".artifact.json" }

// RemoveLegacyArtifactRecord removes a pre-D127 sidecar beside dbPath. One that
// is not there is not an error: the point is only that none survives to be
// mistaken for current.
func RemoveLegacyArtifactRecord(dbPath string) error {
	if err := os.Remove(LegacyArtifactRecordPath(dbPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
