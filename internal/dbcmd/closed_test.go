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

// D115: db status prints a renamed: line from the providers' declarations,
// and a key the build applied the declaration to is not frozen -- no special
// code removes it from frozen:, the carry-forward simply never froze it. A
// store written directly, so this holds for a pulled artifact too (one this
// machine never built).
func TestStatus_D115_ListsRenamedKeysAndNotFrozen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Echo:PyPI", "Go"}, Renamed: map[string]string{"Echo:PyPi": "Echo:PyPI"}},
		"zz-src": {Ecosystems: []string{"New:Spelling"}, Renamed: map[string]string{"Old:Spelling": "New:Spelling"},
			Frozen: map[string]time.Time{"New:Spelling": time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d:\n%s", code, errOut.String())
	}
	const want = "\nrenamed:    Echo:PyPi -> Echo:PyPI (osv), Old:Spelling -> New:Spelling (zz-src)\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("status lacks %q:\n%s", want, out.String())
	}
	// frozen: lists only what Frozen holds -- the successor here, never a
	// renamed old key.
	if want := "\nfrozen:     New:Spelling since 2026-06-30 (zz-src)\n"; !strings.Contains(out.String(), want) {
		t.Errorf("status lacks %q:\n%s", want, out.String())
	}
}

func TestStatus_D115_NoRenamedLineWhenNothingIsDeclared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-norename", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
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
	if strings.Contains(out.String(), "renamed:") {
		t.Errorf("a database with no declaration prints a renamed line:\n%s", out.String())
	}
}
