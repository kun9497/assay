package dbcmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// publishOldShapedArtifact packs a REAL schema-`schema`-shaped bolt file
// (buildOldShapedSeed, dbcmd_test.go) under a dbartifact.Meta annotation
// naming that same schema, and pushes it to ref.
//
// store.Create followed by patching only the manifest annotation would leave
// the CURRENT composite-key index shape underneath an old schema label and
// prove nothing about store.OpenSeedRatings actually accepting the artifact
// PullSeed downloads -- the same reasoning buildOldShapedSeed's own doc
// comment gives for why dbcmd's own D67 tests build a real old-shaped file
// rather than a relabeled current one.
func publishOldShapedArtifact(t *testing.T, ref string, schema int, advs []advisory.Advisory, ratings []advisory.Rating) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.db")
	buildOldShapedSeed(t, path, advs, ratings, schema)

	img, err := dbartifact.Pack(path, dbartifact.Meta{
		SchemaVersion: schema,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(mustRef(t, ref), img); err != nil {
		t.Fatal(err)
	}
}

// TestPullSeed_FallsBackToThePreviousSchemaWhenTheCurrentTagDoesNotExistYet
// is the D-seed-bootstrap hazard's own reproduction: the registry holds only
// the tag one schema version back, the state a brand new schema's tag has on
// its own first day, before its own first push. This is what broke the first
// :v9 publish, because the nightly workflow always seeds from
// `assay db ref` -- this binary's own schema tag.
func TestPullSeed_FallsBackToThePreviousSchemaWhenTheCurrentTagDoesNotExistYet(t *testing.T) {
	host := registryHost(t)
	prevRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion-1)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	publishOldShapedArtifact(t, prevRef, store.SchemaVersion-1,
		[]advisory.Advisory{{ID: "GHSA-old-shape", Database: "GHSA", Source: "osv",
			Kind:     advisory.KindVulnerability,
			Affected: []advisory.Affected{{Ecosystem: "Go", Name: "old"}}}},
		[]advisory.Rating{{CVE: "CVE-2026-SEEDED-OLD-SCHEMA", Source: "NVD"}})

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	code := PullSeed(context.Background(), dst, curRef, &out, &errOut)
	if code != 0 {
		t.Fatalf("PullSeed with only the previous schema published = %d, want 0 (stderr: %s)",
			code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "the previous schema") {
		t.Errorf("stderr does not say it fell back to the previous schema:\n%s", errOut.String())
	}
	// Names WHICH artifact it fell back to, or an operator cannot tell this
	// apart from some other failure that happens to mention "schema".
	if !strings.Contains(errOut.String(), fmt.Sprintf("v%d", store.SchemaVersion-1)) {
		t.Errorf("stderr does not name the previous schema's tag:\n%s", errOut.String())
	}

	// The pulled file lands at dbPath...
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("PullSeed did not install a file at dbPath: %v", err)
	}
	// ...and is readable exactly the way dbcmd.Update's own ratings-copy
	// block reads a --seed input: through OpenSeedRatings, never Open.
	db, err := store.OpenSeedRatings(dst)
	if err != nil {
		t.Fatalf("the pulled fallback seed does not open via OpenSeedRatings: %v", err)
	}
	defer db.Close()
	if rs, err := db.RatingsFor("CVE-2026-SEEDED-OLD-SCHEMA"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-SEEDED-OLD-SCHEMA) = %v, %v; the fallback artifact's "+
			"rating did not land at dbPath", rs, err)
	}
}

// TestPullSeed_NoFallbackWhenTheCurrentTagExists is the ordinary case: once a
// schema's own tag has been published at least once, PullSeed must behave
// like an unremarkable pull and never mention the fallback it did not take.
func TestPullSeed_NoFallbackWhenTheCurrentTagExists(t *testing.T) {
	host := registryHost(t)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)
	seed(t, curRef, time.Time{}, 5) // Push always stamps the CURRENT schema.

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	code := PullSeed(context.Background(), dst, curRef, &out, &errOut)
	if code != 0 {
		t.Fatalf("PullSeed with the current tag already published = %d, want 0 (stderr: %s)",
			code, errOut.String())
	}
	if strings.Contains(errOut.String(), "previous schema") {
		t.Errorf("PullSeed fell back to the previous schema even though the current tag "+
			"exists:\n%s", errOut.String())
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatalf("the pulled current-schema seed does not open via the exact-match Open: %v", err)
	}
	db.Close()
}

// TestPullSeed_ExitsTwoWhenNeitherTagExists: an entirely empty registry --
// nothing published under either tag, or any tag -- must fail exactly as
// Pull does today, not loop or hang looking for a baseline that does not
// exist. The repo itself does not exist here, so the underlying registry
// error is NAME_UNKNOWN rather than MANIFEST_UNKNOWN; either way there is no
// fallback to attempt.
func TestPullSeed_ExitsTwoWhenNeitherTagExists(t *testing.T) {
	host := registryHost(t)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	code := PullSeed(context.Background(), dst, curRef, &out, &errOut)
	if code != 2 {
		t.Errorf("PullSeed against an empty registry = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused PullSeed left a file behind at dbPath")
	}
}

// TestPullSeed_ExitsTwoWhenTheFallbackAlsoDoesNotExist covers the other half
// of "any other fetch error, or MANIFEST_UNKNOWN on the fallback too, fails
// exactly like Pull does today": the repo exists (something unrelated was
// published under it, so the FIRST attempt's error really is
// MANIFEST_UNKNOWN and the fallback really is attempted), but neither the
// current nor the previous schema's tag was ever pushed. The fallback
// attempt must fail plainly rather than looping to N-2 or masking the error.
func TestPullSeed_ExitsTwoWhenTheFallbackAlsoDoesNotExist(t *testing.T) {
	host := registryHost(t)
	// Publishing at an unrelated tag makes the REPOSITORY exist without
	// touching the current or previous schema's tag, so the first fetch
	// below genuinely hits MANIFEST_UNKNOWN (not NAME_UNKNOWN) and the
	// retry branch is the one actually exercised.
	seed(t, fmt.Sprintf("%s/assay-db:v1", host), time.Time{}, 1)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	code := PullSeed(context.Background(), dst, curRef, &out, &errOut)
	if code != 2 {
		t.Errorf("PullSeed with neither the current nor previous tag published = %d, want 2 (stderr: %s)",
			code, errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused PullSeed left a file behind at dbPath")
	}
}

// TestPullSeed_RefusesAnArtifactTwoSchemasBehindAtThePreviousTag: the
// fallback tag existing is not enough on its own -- what it holds must still
// satisfy the seed contract (SchemaVersion or SchemaVersion-1,
// store.OpenSeedRatings, D67). An artifact two schemas behind is outside
// that contract and must be refused with Pull's own wording for an old
// schema, not silently accepted because SOME artifact was found at the
// fallback tag.
func TestPullSeed_RefusesAnArtifactTwoSchemasBehindAtThePreviousTag(t *testing.T) {
	host := registryHost(t)
	prevRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion-1)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)

	publishOldShapedArtifact(t, prevRef, store.SchemaVersion-2, nil,
		[]advisory.Rating{{CVE: "CVE-2026-TOO-OLD", Source: "NVD"}})

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	code := PullSeed(context.Background(), dst, curRef, &out, &errOut)
	if code != 2 {
		t.Errorf("PullSeed against a fallback artifact two schemas behind = %d, want 2 (stderr: %s)",
			code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "upgrade the publisher") {
		t.Errorf("stderr does not use Pull's existing wording for an artifact older than "+
			"this assay reads:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused PullSeed left a file behind at dbPath")
	}
}

// TestPullSeed_DoesNotFallBackOnANonManifestError is the other half of
// PullSeed's own doc comment: "On a fetch error for ref whose message names
// MANIFEST_UNKNOWN, it retries ONCE against the previous schema's tag ...
// Any other fetch error ... fails exactly as Pull does." No existing test
// ever drives a fetch error that is NOT MANIFEST_UNKNOWN (or its cousin
// NAME_UNKNOWN, both of which name a genuinely missing manifest), so nothing
// holds the narrowing: widening the trigger to every fetch error means a
// transient network, auth, or 5xx failure against a current tag that DOES
// exist and is perfectly readable silently substitutes the stale N-1 tag
// instead, printing "does not exist yet; seeding from ..., the previous
// schema" -- a false statement about why the fetch actually failed.
//
// The registry here answers every request normally except a GET/HEAD for
// the CURRENT schema's manifest, which always 500s -- an error whose message
// contains neither MANIFEST_UNKNOWN nor NAME_UNKNOWN. The previous schema's
// tag is seeded and perfectly valid, which makes this the sharpest form of
// the defect: a broadened guard does not merely fail differently, it
// SUCCEEDS by installing the stale seed. Exit code and "file installed or
// not" are therefore the observable difference, not just stderr wording.
func TestPullSeed_DoesNotFallBackOnANonManifestError(t *testing.T) {
	curTag := fmt.Sprintf("v%d", store.SchemaVersion)
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/assay-db/manifests/"+curTag, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	mux.Handle("/", registry.New())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Host

	prevRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion-1)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)
	// Genuinely valid and installable -- so a silent fallback would SUCCEED,
	// not merely fail on a different message.
	seed(t, prevRef, time.Time{}, 5)

	dst := filepath.Join(t.TempDir(), "seed.db")
	var out, errOut bytes.Buffer
	code := PullSeed(context.Background(), dst, curRef, &out, &errOut)
	if code != 2 {
		t.Errorf("PullSeed on a 500 fetching the current tag = %d, want 2 -- a 500 is not "+
			"a missing manifest and must not fall back to the stale previous schema "+
			"(stderr: %s)", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "the previous schema") {
		t.Errorf("PullSeed fell back to the previous schema on a non-manifest error -- "+
			"a false statement about why the fetch failed:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused PullSeed installed a file from the stale fallback")
	}
}
