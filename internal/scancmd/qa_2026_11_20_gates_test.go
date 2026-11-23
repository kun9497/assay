package scancmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-20: three ways a scan said less than it knew.

// ratedDB is a database with one Alpine advisory and the given rating
// sources recorded in its metadata.
func ratedDB(t *testing.T, sources ...string) string {
	t.Helper()
	path := alpineVEXDB(t)
	if len(sources) == 0 {
		return path
	}
	// Rewritten with the sources: SetMeta replaces the record.
	dst := filepath.Join(t.TempDir(), "rated.db")
	w, err := store.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	ratings := map[string]store.Provenance{}
	for _, s := range sources {
		ratings[s] = store.Provenance{Source: "https://example.test/" + s, DataAsOf: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19"}}},
		Ratings:   ratings,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dst
}

func emptyAlpineSBOM(t *testing.T) string {
	t.Helper()
	return writeSBOM(t, "cyclonedx", `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":"zlib","version":"1.3.1-r0","purl":"pkg:apk/alpine/zlib@1.3.1-r0?arch=x86_64&distro=alpine-3.19.9"}]}`)
}

// --fail-on-kev and --fail-on-epss against a database that carries no such
// source can never fire. --fail-on-eol has always said so for its own
// question (D87); these two passed every scan in silence.
func TestRun_AGateTheDatabaseCannotAnswerSaysSo(t *testing.T) {
	half := 0.5
	sbom := emptyAlpineSBOM(t)
	const kevWarn, epssWarn = "warning: --fail-on-kev given, but this database carries no KEV catalog", "warning: --fail-on-epss given, but this database carries no EPSS scores"
	for _, tc := range []struct {
		name         string
		db           string
		opts         Options
		wantK, wantE bool
	}{
		{"kev armed, no source", ratedDB(t), Options{FailOnKEV: true}, true, false},
		{"epss armed, no source", ratedDB(t), Options{FailOnEPSS: &half}, false, true},
		{"both armed, no source", ratedDB(t), Options{FailOnKEV: true, FailOnEPSS: &half}, true, true},
		{"neither armed", ratedDB(t), Options{}, false, false},
		{"kev armed, source present", ratedDB(t, kevSource), Options{FailOnKEV: true}, false, false},
		{"epss armed, source present", ratedDB(t, epssSource), Options{FailOnEPSS: &half}, false, false},
		{"kev armed, only epss present", ratedDB(t, epssSource), Options{FailOnKEV: true}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.IgnoreFile = IgnoreNone
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), tc.db, sbom, tc.opts, &out, &errOut); code != 0 {
				t.Fatalf("Run = %d, want 0: the warning is not a verdict (stderr: %s)", code, errOut.String())
			}
			if got := strings.Contains(errOut.String(), kevWarn); got != tc.wantK {
				t.Errorf("KEV warning present = %v, want %v:\n%s", got, tc.wantK, errOut.String())
			}
			if got := strings.Contains(errOut.String(), epssWarn); got != tc.wantE {
				t.Errorf("EPSS warning present = %v, want %v:\n%s", got, tc.wantE, errOut.String())
			}
		})
	}
}

// The readers decode one JSON value. Two documents in one file -- `>>` where
// a CI step meant `>` -- used to be scanned as the first alone, exit 0, while
// the provenance record hashed both.
func TestRun_ContentAfterAnSBOMsDocumentIsRefused(t *testing.T) {
	db := alpineVEXDB(t)
	clean := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":"zlib","version":"1.3.1-r0","purl":"pkg:apk/alpine/zlib@1.3.1-r0?arch=x86_64&distro=alpine-3.19.9"}]}`
	vulnerable := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":"busybox","version":"1.36.1-r1","purl":"pkg:apk/alpine/busybox@1.36.1-r1?arch=x86_64&distro=alpine-3.19.9"}]}`
	spdx := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
 {"SPDXID":"SPDXRef-p","name":"zlib","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/alpine/zlib@1.3.1-r0?arch=x86_64&distro=alpine-3.19.9"}]}]}`

	run := func(format, doc string) (int, string) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, writeSBOM(t, format, doc), Options{IgnoreFile: IgnoreNone, FailOnUnknown: true}, &out, &errOut)
		return code, errOut.String()
	}
	for name, tc := range map[string]struct{ format, doc string }{
		"a second CycloneDX document": {"cyclonedx", clean + vulnerable},
		"a second, on its own line":   {"cyclonedx", clean + "\n" + vulnerable},
		"stray bytes":                 {"cyclonedx", clean + "GARBAGE<<<"},
		"a second SPDX document":      {"spdx", spdx + spdx},
	} {
		t.Run(name, func(t *testing.T) {
			code, stderr := run(tc.format, tc.doc)
			if code != 2 || !strings.Contains(stderr, "content follows the document's JSON value") {
				t.Fatalf("exit=%d, want 2 with the reason\nstderr: %s", code, stderr)
			}
		})
	}
	// Whitespace after the document is how every editor and `echo` ends a
	// file, and is not content.
	for name, doc := range map[string]string{"nothing": clean, "a newline": clean + "\n", "blank lines and tabs": clean + "\r\n\t \n"} {
		if code, stderr := run("cyclonedx", doc); code != 0 {
			t.Errorf("%s after the document: exit=%d, want 0\nstderr: %s", name, code, stderr)
		}
	}
}

// A tar entry's name is the image's text. One holding a newline used to
// start a line of stderr with whatever followed it -- "error: ..." -- which
// is the line the provenance sidecar records as the cause of an exit 2.
func TestRun_AnUnreadPathCannotStartALineOfStderr(t *testing.T) {
	newline := string(rune(0x0a))
	forged := "usr/lib/node_modules/a" + newline + "error: FORGED BY THE IMAGE/package.json"
	target := p4Archive(t, p4Tar(t,
		p4Entry{name: osReleasePath, body: osReleaseAlpine319},
		p4Entry{name: apkDBPath, body: apkOneRecord},
		p4Entry{name: forged, link: "/nowhere/package.json"},
	))
	_, _, stderr, _ := p4Scan(t, testDB(t), target, Options{IgnoreFile: IgnoreNone})
	for _, line := range strings.Split(stderr, newline) {
		if strings.HasPrefix(line, "error: FORGED") {
			t.Fatalf("the image started a line of stderr: %q\n%s", line, stderr)
		}
	}
	if !strings.Contains(stderr, "not read: usr/lib/node_modules/a"+string(rune(0x5c))+"x0aerror: FORGED BY THE IMAGE/package.json") {
		t.Errorf("stderr does not show the path with its newline spelled out:\n%s", stderr)
	}
}
