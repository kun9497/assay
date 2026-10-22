package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// D137: a scan's provenance says whether the database behind its verdict
// was verified, carrying the record's two fields through and omitting them
// when the record has neither (a database pulled before D137, or built).
func TestNewDatabaseProvenance_CarriesSignedByAndUnverified(t *testing.T) {
	rec := store.ArtifactRecord{Reference: "ghcr.io/kun9497/assay-db:v14", Digest: "sha256:" + strings.Repeat("ab", 32),
		PulledAt: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)}

	signed := rec
	signed.SignedBy = "9b71ca8e11cf3bcf"
	d := NewDatabaseProvenance(store.Meta{Artifact: &signed})
	if d.Artifact == nil || d.Artifact.SignedBy != "9b71ca8e11cf3bcf" || d.Artifact.Unverified {
		t.Fatalf("artifact provenance = %+v, want SignedBy carried", d.Artifact)
	}
	b, _ := json.Marshal(d.Artifact)
	if !strings.Contains(string(b), `"signedBy":"9b71ca8e11cf3bcf"`) || strings.Contains(string(b), "unverified") {
		t.Errorf("json = %s, want signedBy present and unverified omitted", b)
	}

	unverified := rec
	unverified.Unverified = true
	d = NewDatabaseProvenance(store.Meta{Artifact: &unverified})
	b, _ = json.Marshal(d.Artifact)
	if !d.Artifact.Unverified || !strings.Contains(string(b), `"unverified":true`) || strings.Contains(string(b), "signedBy") {
		t.Errorf("json = %s, want unverified:true and signedBy omitted", b)
	}

	d = NewDatabaseProvenance(store.Meta{Artifact: &rec})
	b, _ = json.Marshal(d.Artifact)
	if strings.Contains(string(b), "signedBy") || strings.Contains(string(b), "unverified") {
		t.Errorf("json = %s, want neither field for a record with no signing state", b)
	}
}
