package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadTargets_ValidFile(t *testing.T) {
	path := writeFile(t, `[
		{"name": "alpine319", "tag": "alpine:3.19", "ref": "mirror.gcr.io/library/alpine@sha256:aaa", "minAgree": 1, "minFindings": 1, "maxFindings": 25},
		{"name": "wolfi", "tag": "wolfi-base:latest", "ref": "cgr.dev/chainguard/wolfi-base@sha256:bbb", "minAgree": 0, "minFindings": 0, "maxFindings": 25}
	]`)

	targets, err := loadTargets(path)
	if err != nil {
		t.Fatalf("loadTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
	if targets[0].Name != "alpine319" || targets[0].Ref != "mirror.gcr.io/library/alpine@sha256:aaa" {
		t.Errorf("targets[0] = %+v, unexpected", targets[0])
	}
}

func TestLoadTargets_MissingFile(t *testing.T) {
	_, err := loadTargets(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("loadTargets of a missing file: want an error, got nil")
	}
}

func TestLoadTargets_InvalidJSON(t *testing.T) {
	path := writeFile(t, `not json at all`)
	if _, err := loadTargets(path); err == nil {
		t.Fatal("loadTargets of invalid JSON: want an error, got nil")
	}
}

func TestLoadTargets_EmptyArray(t *testing.T) {
	path := writeFile(t, `[]`)
	if _, err := loadTargets(path); err == nil {
		t.Fatal("loadTargets of an empty array: want an error, got nil")
	}
}

func TestLoadTargets_EntryMissingName(t *testing.T) {
	path := writeFile(t, `[{"ref": "example.com/img@sha256:aaa"}]`)
	if _, err := loadTargets(path); err == nil {
		t.Fatal("loadTargets with a nameless entry: want an error, got nil")
	}
}

func TestLoadTargets_EntryMissingRef(t *testing.T) {
	path := writeFile(t, `[{"name": "no-ref"}]`)
	if _, err := loadTargets(path); err == nil {
		t.Fatal("loadTargets with a refless entry: want an error, got nil")
	}
}

func TestLoadTargets_DuplicateName(t *testing.T) {
	path := writeFile(t, `[
		{"name": "dup", "ref": "example.com/a@sha256:aaa"},
		{"name": "dup", "ref": "example.com/b@sha256:bbb"}
	]`)
	if _, err := loadTargets(path); err == nil {
		t.Fatal("loadTargets with a duplicate name: want an error, got nil")
	}
}

func TestLoadTargets_MaxNotEvaluatedOmittedDefaultsToZero(t *testing.T) {
	path := writeFile(t, `[{"name": "x", "ref": "example.com/x@sha256:aaa"}]`)
	targets, err := loadTargets(path)
	if err != nil {
		t.Fatalf("loadTargets: %v", err)
	}
	if targets[0].MaxNotEvaluated != 0 {
		t.Errorf("MaxNotEvaluated = %d, want 0 when omitted from the file", targets[0].MaxNotEvaluated)
	}
}
