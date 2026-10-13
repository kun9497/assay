package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// ArtifactRecord is what `db update` pulled (D120): the reference it was asked
// for, the manifest digest it got, and when. It lives beside the database as
// <dbPath>.artifact.json, written under D116's writer lock by the pull that
// installed the database and removed by `db build`, so a scan can name the
// artifact its database came from — and a database with no such file reports
// none rather than guessing.
//
// A sidecar rather than a Meta field: the database inside the artifact was
// sealed before it was published and cannot know the digest of the artifact
// it was then packed into.
type ArtifactRecord struct {
	Reference string    `json:"reference"`
	Digest    string    `json:"digest"`
	PulledAt  time.Time `json:"pulledAt"`
}

// ArtifactRecordPath is where the record for dbPath lives.
func ArtifactRecordPath(dbPath string) string { return dbPath + ".artifact.json" }

// WriteArtifactRecord writes rec beside dbPath, through a temp file and a
// rename so a reader never sees half of one.
func WriteArtifactRecord(dbPath string, rec ArtifactRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	path := ArtifactRecordPath(dbPath)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// RemoveArtifactRecord removes the record beside dbPath. One that is not there
// is not an error: the point is only that none survives.
func RemoveArtifactRecord(dbPath string) error {
	if err := os.Remove(ArtifactRecordPath(dbPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ReadArtifactRecord reads the record beside dbPath. ok is false, with a nil
// error, when there is none. A record that exists and does not parse, or names
// no digest, is an error: the caller reports no artifact and says why, rather
// than naming one it cannot vouch for.
func ReadArtifactRecord(dbPath string) (rec ArtifactRecord, ok bool, err error) {
	data, err := os.ReadFile(ArtifactRecordPath(dbPath))
	if errors.Is(err, os.ErrNotExist) {
		return ArtifactRecord{}, false, nil
	}
	if err != nil {
		return ArtifactRecord{}, false, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return ArtifactRecord{}, false, fmt.Errorf("parse artifact record: %w", err)
	}
	if rec.Digest == "" {
		return ArtifactRecord{}, false, errors.New("artifact record names no digest")
	}
	return rec, true, nil
}
