package dbcmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// statusJSONFixture writes a database whose Meta exercises every part of the
// JSON document: a pulled and signed artifact, two providers between them
// holding a frozen key, a rename and a closed topic, a rating source that
// rated something and one that ran and rated nothing, an enricher that failed
// partway, and EOL rows.
func statusJSONFixture(t *testing.T, artifact *store.ArtifactRecord) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	day := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-json", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "example.com/m"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRatings([]advisory.Rating{{CVE: "CVE-2026-1", Source: "NVD"}, {CVE: "CVE-2026-2", Source: "NVD"},
		// A source with stored ratings and no self-report: the table still gives
		// it a row, with no date and no source.
		{CVE: "CVE-2026-3", Source: "GHSA"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutEnrichment(advisory.Enrichment{CVE: "CVE-2026-1", Source: "KISA", Title: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 10, 20, 3, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{
			"osv": {Source: "https://osv.test/", DataAsOf: day(10, 19), Records: 40,
				Ecosystems: []string{"Go", "Debian:11"},
				Frozen:     map[string]time.Time{"Debian:11": day(8, 19)},
				Renamed:    map[string]string{"Echo:PyPi": "Echo:PyPI"}},
			"amazon": {Source: "https://alas.test/", DataAsOf: day(10, 18), Records: 7,
				Ecosystems: []string{"Amazon Linux:2"},
				Closed:     map[string]time.Time{"mono": day(7, 25), "selinux-ng": day(9, 25)}},
		},
		Ratings: map[string]store.Provenance{
			"NVD":  {Source: "https://nvd.test/", DataAsOf: day(10, 19), Window: "last 120 days"},
			"EPSS": {Source: "https://epss.test/", DataAsOf: day(10, 19)},
		},
		Enrichment: map[string]store.Provenance{
			"KISA": {Source: "https://kisa.test/", DataAsOf: day(10, 18), Error: "boom"},
		},
		EOL:           []store.EOLRelease{{DistroID: "alpine", Release: "3.19"}, {DistroID: "alpine", Release: "3.20"}},
		EOLProvenance: &store.Provenance{DataAsOf: day(10, 17)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if artifact != nil {
		if err := store.SetArtifactAt(path, *artifact); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestStatusJSON_TheWholeDocument pins the document byte for byte, so every
// field name, every omission and every ordering is part of what the test
// holds: a consumer parses these names, and docs/compatibility.md promises
// they change only with a schemaVersion bump.
func TestStatusJSON_TheWholeDocument(t *testing.T) {
	path := statusJSONFixture(t, &store.ArtifactRecord{
		Reference: "ghcr.io/kun9497/assay-db:v9", Digest: "sha256:" + strings.Repeat("ab", 32),
		PulledAt: time.Date(2026, 10, 21, 1, 2, 3, 0, time.UTC), SignedBy: "9b71ca8e11cf3bcf",
	})
	var out, errOut bytes.Buffer
	if code := StatusJSON(path, &out, &errOut); code != 0 {
		t.Fatalf("StatusJSON = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	quoted, _ := json.Marshal(path)
	want := `{
  "schemaVersion": 1,
  "path": ` + string(quoted) + `,
  "schema": 9,
  "builtAt": "2026-10-20T03:00:00Z",
  "artifact": {
    "reference": "ghcr.io/kun9497/assay-db:v9",
    "digest": "sha256:` + strings.Repeat("ab", 32) + `",
    "pulledAt": "2026-10-21T01:02:03Z",
    "signature": "verified",
    "signedBy": "9b71ca8e11cf3bcf"
  },
  "ecosystems": [
    "Amazon Linux:2",
    "Debian:11",
    "Go"
  ],
  "databases": [
    "GHSA"
  ],
  "eol": {
    "releases": 2,
    "distros": 1,
    "dataAsOf": "2026-10-17T00:00:00Z"
  },
  "providers": [
    {
      "name": "amazon",
      "dataAsOf": "2026-10-18T00:00:00Z",
      "records": 7,
      "source": "https://alas.test/",
      "ecosystems": [
        "Amazon Linux:2"
      ],
      "closed": [
        {
          "topic": "mono",
          "lastAdvisory": "2026-07-25T00:00:00Z"
        },
        {
          "topic": "selinux-ng",
          "lastAdvisory": "2026-09-25T00:00:00Z"
        }
      ]
    },
    {
      "name": "osv",
      "dataAsOf": "2026-10-19T00:00:00Z",
      "records": 40,
      "source": "https://osv.test/",
      "ecosystems": [
        "Debian:11",
        "Go"
      ],
      "frozen": [
        {
          "key": "Debian:11",
          "since": "2026-08-19T00:00:00Z"
        }
      ],
      "renamed": [
        {
          "from": "Echo:PyPi",
          "to": "Echo:PyPI"
        }
      ]
    }
  ],
  "ratingSources": [
    {
      "name": "EPSS",
      "dataAsOf": "2026-10-19T00:00:00Z",
      "records": 0,
      "source": "https://epss.test/"
    },
    {
      "name": "GHSA",
      "records": 1
    },
    {
      "name": "NVD",
      "dataAsOf": "2026-10-19T00:00:00Z",
      "records": 2,
      "covered": "last 120 days",
      "source": "https://nvd.test/"
    }
  ],
  "enrichmentSources": [
    {
      "name": "KISA",
      "dataAsOf": "2026-10-18T00:00:00Z",
      "records": 1,
      "error": "boom",
      "source": "https://kisa.test/"
    }
  ]
}
`
	if got := out.String(); got != want {
		t.Errorf("StatusJSON document differs\n--- got\n%s\n--- want\n%s", got, want)
	}
	if errOut.Len() != 0 {
		t.Errorf("a clean run wrote to stderr: %q", errOut.String())
	}
}

// TestStatusJSON_ArtifactStates: the three things a record can say about a
// signature, each spelled out rather than inferred from an absent field --
// D137's own rule for `db status`, where an old record prints no signed:
// line rather than a guess. A database built locally has no artifact at all.
func TestStatusJSON_ArtifactStates(t *testing.T) {
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		rec  *store.ArtifactRecord
		want string // a fragment of the artifact object, or "" for none
	}{
		{"unverified", &store.ArtifactRecord{Reference: "mirror.test/db:v9", Digest: "sha256:cd", PulledAt: at, Unverified: true},
			`"signature": "unverified"` + "\n"},
		{"predates signing", &store.ArtifactRecord{Reference: "mirror.test/db:v9", Digest: "sha256:cd", PulledAt: at},
			`"signature": "unrecorded"` + "\n"},
		{"built locally", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := StatusJSON(statusJSONFixture(t, tc.rec), &out, &errOut); code != 0 {
				t.Fatalf("StatusJSON = %d (stderr %s)", code, errOut.String())
			}
			s := out.String()
			if tc.want == "" {
				if strings.Contains(s, `"artifact"`) {
					t.Errorf("a built database names an artifact:\n%s", s)
				}
				return
			}
			if !strings.Contains(s, tc.want) || strings.Contains(s, `"signedBy"`) {
				t.Errorf("artifact does not say %s (and only that):\n%s", tc.want, s)
			}
		})
	}
}

// TestStatusJSON_WithoutDatabase: the refusal is the table's (exit 2, the
// fix on stderr) and stdout stays empty, so a consumer piping it into a
// parser sees no document rather than half of one.
func TestStatusJSON_WithoutDatabase(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := StatusJSON(filepath.Join(t.TempDir(), "absent.db"), &out, &errOut); code != 2 {
		t.Errorf("StatusJSON(absent) = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "db update") {
		t.Errorf("stderr does not say how to fix it:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("the error path wrote to stdout: %q", out.String())
	}
}

// TestStatusJSON_AnEmptyDatabaseHasEmptyLists: a database with no providers
// or sources still gives arrays, never null, so a consumer can range over
// every list without a nil check -- and an absent date is left out.
func TestStatusJSON_AnEmptyDatabaseHasEmptyLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := StatusJSON(path, &out, &errOut); code != 0 {
		t.Fatalf("StatusJSON = %d (stderr %s)", code, errOut.String())
	}
	s := out.String()
	if strings.Contains(s, `"builtAt"`) {
		t.Errorf("an unknown build time is printed rather than left out:\n%s", s)
	}
	for _, want := range []string{`"ecosystems": []`, `"databases": []`, `"providers": []`,
		`"ratingSources": []`, `"enrichmentSources": []`, `"eol": {
    "releases": 0,
    "distros": 0
  }`} {
		if !strings.Contains(s, want) {
			t.Errorf("document does not contain %s:\n%s", want, s)
		}
	}
}

// TestStatusJSON_AnUnknownFreezeDateIsLeftOut: carry-forward freezes a key
// at the seed's DataAsOf, which osv leaves zero when any ecosystem had no
// date (osv/fetch.go). The document leaves the date out rather than
// printing year 1, the rule every date in it follows.
func TestStatusJSON_AnUnknownFreezeDateIsLeftOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{BuiltAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Debian:11"},
			Frozen: map[string]time.Time{"Debian:11": {}},
			Closed: map[string]time.Time{"topic": {}}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := StatusJSON(path, &out, &errOut); code != 0 {
		t.Fatalf("StatusJSON = %d (stderr %s)", code, errOut.String())
	}
	s := out.String()
	if strings.Contains(s, "0001-01-01") || !strings.Contains(s, `"key": "Debian:11"`) || !strings.Contains(s, `"topic": "topic"`) {
		t.Errorf("an unknown date is printed, or its entry dropped:\n%s", s)
	}
}
