package dbcmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// closingProvider is fakeProvider plus a Provenance.Closed, the shape
// amazon.Fetch returns when D113 left a topic out of its DataAsOf.
type closingProvider struct {
	fakeProvider
	closed map[string]time.Time
}

func (c closingProvider) Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	prov, err := c.fakeProvider.Fetch(ctx, emit)
	prov.Closed = c.closed
	return prov, err
}

// TestStatus_D113_ListsClosedTopics drives the whole path a closed topic takes
// to a reader: a provider reports it, Update stores it, Status prints it. The
// provider's DATA AS OF no longer includes these topics, and without this
// line the exclusion would be visible only in a build log nobody rereads.
func TestStatus_D113_ListsClosedTopics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	quiet := time.Date(2023, 9, 25, 22, 0, 0, 0, time.UTC)
	p := closingProvider{
		fakeProvider: fakeProvider{name: "Amazon Linux ALAS", covers: []string{"Amazon Linux:2"},
			advs: []advisory.Advisory{{
				ID: "ALAS2-2026-0001", Database: "ALAS2", Source: "amazon", Kind: advisory.KindVulnerability,
				Affected: []advisory.Affected{{Ecosystem: "Amazon Linux:2", Name: "corepkg"}},
			}}},
		// Two topics with different last dates: the line states the newer
		// one, which is true of both ("nothing since").
		closed: map[string]time.Time{"selinux-ng": quiet, "mono": quiet.AddDate(0, -2, 0)},
	}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", false, []provider.Provider{p}, nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	const want = "closed:     Amazon Linux ALAS: 2 topic(s) closed (no advisory since 2023-09-25), " +
		"not counted in its DATA AS OF: mono, selinux-ng\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("status does not list the closed topics\nwant: %q\ngot:\n%s", want, out.String())
	}
}

// TestStatus_D113_NoClosedLineWhenNothingIsClosed: like frozen:, the line is
// printed only when there is something to say — "none" on every database
// would be noise.
func TestStatus_D113_NoClosedLineWhenNothingIsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-noclosed", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", false, []provider.Provider{p}, nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if strings.Contains(out.String(), "closed:") {
		t.Errorf("a database with nothing closed prints a closed line:\n%s", out.String())
	}
}
