package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/dbcmd/trust"
	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

var (
	t0      = time.Date(2026, 10, 23, 6, 40, 0, 0, time.UTC)
	builtAt = time.Date(2026, 10, 23, 6, 10, 0, 0, time.UTC)
	asOf    = time.Date(2024, 10, 15, 0, 0, 0, 0, time.UTC)
)

// publish pushes an assay-db-shaped artifact (the bytes need not be a
// database: status reads only the manifest's annotations) and, when key is
// non-nil, signs it. It trusts key for the test's duration.
func publish(t *testing.T, key *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	host := trusttest.NewRegistry(t, nil)
	ref := host + "/assay-db:v9"
	return ref, pushTo(t, ref, key)
}

var blockSig atomic.Bool

// pushTo pushes an assay-db-shaped artifact to ref, signs it when key is
// non-nil, and returns its digest.
func pushTo(t *testing.T, ref string, key *ecdsa.PrivateKey) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(src, []byte("not read"), 0o600); err != nil {
		t.Fatal(err)
	}
	img, err := dbartifact.Pack(src, dbartifact.Meta{SchemaVersion: 9, BuiltAt: builtAt, DataAsOf: asOf, DataAsOfSource: "amazon"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		trusttest.SignArtifact(t, key, r, d)
	}
	return d.String()
}

func trustKey(t *testing.T, key *ecdsa.PrivateKey) {
	t.Helper()
	old := trustedKeys
	pub := &key.PublicKey
	trustedKeys = func() []trust.PublicKey { return []trust.PublicKey{{ID: trust.KeyID(pub), Key: pub}} }
	t.Cleanup(func() { trustedKeys = old })
}

func fixedNow(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func runStatus(t *testing.T, args ...string) (Status, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "status.json")
	var stdout, stderr bytes.Buffer
	if code := run(append(args, "-out", out), &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("status.json is not JSON: %v\n%s", err, b)
	}
	return s, stderr.String()
}

func writePrev(t *testing.T, s Status) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "prev.json")
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The ordinary night: the publish succeeded, so the live tag is described,
// signed by the trusted key, and the run is both the last run and the last
// success.
func TestRun_DescribesASignedArtifactAfterASuccessfulRun(t *testing.T) {
	key := trusttest.NewKey(t)
	trustKey(t, key)
	fixedNow(t, t0)
	ref, digest := publish(t, key)

	s, _ := runStatus(t, "-ref", ref, "-workflow", "db-publish", "-result", "success", "-run-url", "https://example.test/runs/1")
	if s.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", s.SchemaVersion)
	}
	p := s.Published
	if p == nil {
		t.Fatal("published is missing")
	}
	if p.Digest != digest || p.Reference != ref {
		t.Errorf("published = %s@%s, want %s@%s", p.Reference, p.Digest, ref, digest)
	}
	if !p.BuiltAt.Equal(builtAt) || !p.DataAsOf.Equal(asOf) || p.DataAsOfSource != "amazon" || p.SchemaVersion != 9 {
		t.Errorf("published metadata = %+v", p)
	}
	if !p.Signed || p.SignedBy != trust.KeyID(&key.PublicKey) {
		t.Errorf("signed = %v by %q, want true by %s", p.Signed, p.SignedBy, trust.KeyID(&key.PublicKey))
	}
	if !p.ObservedAt.Equal(t0) {
		t.Errorf("observedAt = %v, want %v", p.ObservedAt, t0)
	}
	if s.LastRun == nil || s.LastRun.Result != "success" || s.LastRun.Workflow != "db-publish" || s.LastRun.URL != "https://example.test/runs/1" || !s.LastRun.FinishedAt.Equal(t0) {
		t.Errorf("lastRun = %+v", s.LastRun)
	}
	if s.LastSuccess == nil || s.LastSuccess.URL != "https://example.test/runs/1" {
		t.Errorf("lastSuccess = %+v, want this run", s.LastSuccess)
	}
}

// A failed night records the failure as the last run and keeps the last
// success from the previous status: that date is what a monitor alerts on,
// and a failure must not move it.
func TestRun_AFailedRunKeepsThePreviousLastSuccess(t *testing.T) {
	key := trusttest.NewKey(t)
	trustKey(t, key)
	fixedNow(t, t0)
	ref, _ := publish(t, key)
	before := t0.Add(-24 * time.Hour)
	prev := writePrev(t, Status{SchemaVersion: 1, LastSuccess: &Run{Workflow: "db-publish", Result: "success", FinishedAt: before, URL: "https://example.test/runs/0"}})

	s, _ := runStatus(t, "-ref", ref, "-prev", prev, "-workflow", "db-publish", "-result", "failure", "-run-url", "https://example.test/runs/1")
	if s.LastRun == nil || s.LastRun.Result != "failure" {
		t.Errorf("lastRun = %+v, want the failure", s.LastRun)
	}
	if s.LastSuccess == nil || !s.LastSuccess.FinishedAt.Equal(before) || s.LastSuccess.URL != "https://example.test/runs/0" {
		t.Errorf("lastSuccess = %+v, want the previous one kept", s.LastSuccess)
	}
	// The live tag is still described: after a failed night it is the
	// previous night's artifact, and that is exactly what customers get.
	if s.Published == nil || !s.Published.Signed {
		t.Errorf("published = %+v, want the live artifact described", s.Published)
	}
}

// The registry cannot be read: the status is still written, the previous
// description of the artifact is kept, and the error is recorded beside it
// rather than replacing it with nothing.
func TestRun_AnUnreadableRegistryKeepsThePreviousDescription(t *testing.T) {
	fixedNow(t, t0)
	old := &Artifact{Reference: "ghcr.io/kun9497/assay-db:v9", Digest: "sha256:aaaa", Signed: true, SignedBy: "9b71ca8e11cf3bcf", ObservedAt: t0.Add(-time.Hour)}
	prev := writePrev(t, Status{SchemaVersion: 1, Published: old})

	s, stderr := runStatus(t, "-ref", "127.0.0.1:1/assay-db:v9", "-prev", prev, "-workflow", "db-publish", "-result", "failure", "-run-url", "u")
	if s.Published == nil || s.Published.Digest != "sha256:aaaa" || !s.Published.ObservedAt.Equal(old.ObservedAt) {
		t.Errorf("published = %+v, want the previous description kept", s.Published)
	}
	if s.PublishedError == "" {
		t.Error("publishedError is empty, want the registry error recorded")
	}
	if !strings.Contains(stderr, "warning") {
		t.Errorf("stderr does not warn that the artifact could not be read:\n%s", stderr)
	}
}

// An unsigned live digest is the outage D137 made possible; the status says
// so plainly instead of omitting the field.
func TestRun_AnUnsignedArtifactIsReportedUnsigned(t *testing.T) {
	trustKey(t, trusttest.NewKey(t))
	fixedNow(t, t0)
	ref, _ := publish(t, nil)

	s, _ := runStatus(t, "-ref", ref, "-workflow", "db-publish", "-result", "success", "-run-url", "u")
	if s.Published == nil || s.Published.Signed || s.Published.SignedBy != "" {
		t.Errorf("published = %+v, want signed=false", s.Published)
	}
	if !strings.Contains(s.Published.SignatureError, "not signed") {
		t.Errorf("signatureError = %q, want the reason", s.Published.SignatureError)
	}
	b, _ := json.Marshal(s)
	if !strings.Contains(string(b), `"signed":false`) {
		t.Errorf("signed:false is omitted from the JSON:\n%s", b)
	}
}

func TestRun_RejectsAnUnknownResult(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-workflow", "db-publish", "-result", "maybe", "-out", filepath.Join(t.TempDir(), "s.json")}, &stdout, &stderr); code != 2 {
		t.Errorf("run with -result maybe = %d, want 2", code)
	}
}

// lastRun and lastSuccess are the nightly publish's alone. A db-sign run
// (dispatched by hand to fix an unsigned digest) refreshes the artifact's
// description -- so `signed` turns true at once -- but must not move
// lastSuccess, or one manual success would hide a week of failed nightlies
// from the monitor that alerts on it.
func TestRun_OnlyDBPublishMovesTheRunFields(t *testing.T) {
	key := trusttest.NewKey(t)
	trustKey(t, key)
	fixedNow(t, t0)
	ref, _ := publish(t, key)
	before := t0.Add(-72 * time.Hour)
	nightly := &Run{Workflow: "db-publish", Result: "failure", FinishedAt: before, URL: "n"}
	good := &Run{Workflow: "db-publish", Result: "success", FinishedAt: before.Add(-24 * time.Hour), URL: "g"}
	prev := writePrev(t, Status{SchemaVersion: 1, LastRun: nightly, LastSuccess: good})

	s, _ := runStatus(t, "-ref", ref, "-prev", prev, "-workflow", "db-sign", "-result", "success", "-run-url", "s")
	if s.LastRun == nil || s.LastRun.URL != "n" || s.LastSuccess == nil || s.LastSuccess.URL != "g" {
		t.Errorf("lastRun = %+v, lastSuccess = %+v; a db-sign run moved the nightly's fields", s.LastRun, s.LastSuccess)
	}
	if s.Published == nil || !s.Published.Signed {
		t.Errorf("published = %+v, want the freshly signed artifact described", s.Published)
	}
}

// A signature that could not be FETCHED (a 403, a 5xx after retries) says
// nothing about whether the artifact is signed. Publishing signed:false
// for it would announce an outage that is not happening, so the whole read
// counts as failed: the previous description is kept beside the error.
func TestRun_ATransientSignatureFetchKeepsThePreviousDescription(t *testing.T) {
	key := trusttest.NewKey(t)
	trustKey(t, key)
	fixedNow(t, t0)
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, ".sig") && r.Method == http.MethodGet && blockSig.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref := host + "/assay-db:v9"
	pushTo(t, ref, key)
	blockSig.Store(true)
	t.Cleanup(func() { blockSig.Store(false) })
	old := &Artifact{Reference: ref, Digest: "sha256:prev", Signed: true, SignedBy: "k", ObservedAt: t0.Add(-time.Hour)}
	prev := writePrev(t, Status{SchemaVersion: 1, Published: old})

	s, _ := runStatus(t, "-ref", ref, "-prev", prev, "-workflow", "db-publish", "-result", "success", "-run-url", "u")
	if s.Published == nil || s.Published.Digest != "sha256:prev" || !s.Published.Signed {
		t.Errorf("published = %+v, want the previous signed description kept", s.Published)
	}
	if !strings.Contains(s.PublishedError, "403") {
		t.Errorf("publishedError = %q, want the 403 recorded", s.PublishedError)
	}
}

// A successful read clears an error a previous run recorded, so the file
// never shows a fresh description beside a stale complaint.
func TestRun_ASuccessfulReadClearsThePreviousError(t *testing.T) {
	key := trusttest.NewKey(t)
	trustKey(t, key)
	fixedNow(t, t0)
	ref, digest := publish(t, key)
	prev := writePrev(t, Status{SchemaVersion: 1, PublishedError: "GET ...: 503"})

	s, _ := runStatus(t, "-ref", ref, "-prev", prev, "-workflow", "db-publish", "-result", "success", "-run-url", "u")
	if s.PublishedError != "" || s.Published == nil || s.Published.Digest != digest {
		t.Errorf("publishedError = %q, published = %+v; want the error cleared by the fresh read", s.PublishedError, s.Published)
	}
}
