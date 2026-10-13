package scancmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// D120/D121 caller tests added in review: each holds a path the first round
// left open — a machine path reaching the sidecar through an exit-2 error, a
// refused credential recorded as none, a policy or waiver field nothing
// read, and the index digest an image-scoped statement can name.

// D120's "no working directory", on an exit 2. A discovered .assay.yaml that
// fails to load is refused with an error naming the file, and that error is
// what the sidecar records — but the discovered path is absolute: the
// working directory, and the username inside it. The record names the file
// the way waivers.ignoreFile already does, as the default name; stderr does
// too, since the file is by definition in the directory the scan ran from.
func TestRun_D120_BrokenDiscoveredIgnoreFileNamesNoWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".assay.yaml"),
		[]byte("ignore:\n  - vulnerability: "+provCVE+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	side := filepath.Join(dir, "prov.json")

	_, stderr, code := provRun(t, db, sbom, Options{ProvenanceFile: side})
	if code != 2 {
		t.Fatalf("Run = %d, want 2 for a reasonless discovered rule\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "\nerror: .assay.yaml: ignore rule 1 has no reason") {
		t.Errorf("stderr does not name the discovered file by its default name:\n%s", stderr)
	}
	sc := readSidecar(t, side)
	if e, _ := at(t, sc, "run", "error").(string); !strings.HasPrefix(e, ".assay.yaml: ignore rule 1 has no reason") {
		t.Errorf("run.error = %q, want the refusal naming .assay.yaml", e)
	}
	walkStrings(sc, func(s string) {
		for _, f := range []string{work, wd, filepath.ToSlash(work)} {
			if strings.Contains(strings.ToLower(s), strings.ToLower(f)) {
				t.Errorf("sidecar string %q contains the working directory %q", s, f)
			}
		}
	})
}

// The same rule for every other machine path an exit-2 error can carry that
// the caller never typed: the working directory, the home directory, and the
// credential locations D118 reads from the environment. Each is replaced by a
// name for what it is, the longest first so a path inside another is named
// for the more specific one.
func TestRecorder_ErrorTextHidesMachinePaths(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	wd := filepath.Join(home, "proj")
	runtimeDir := filepath.Join(root, "run", "user", "1000")
	authFile := filepath.Join(root, "etc", "auth.json")
	dockerCfg := filepath.Join(root, "ci", "docker")
	for _, d := range []string{wd, runtimeDir, dockerCfg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("REGISTRY_AUTH_FILE", authFile)
	t.Setenv("DOCKER_CONFIG", dockerCfg)
	t.Chdir(wd)
	db := filepath.Join(home, "cache", "vulnerability.db")

	for _, tt := range []struct{ line, want string }{
		{"open " + db + ": denied", "open <database>: denied"},
		{"read " + filepath.Join(wd, "x.yaml") + ": bad", "read " + filepath.Join("<cwd>", "x.yaml") + ": bad"},
		{"read docker config: open " + filepath.Join(home, ".docker", "config.json") + ": denied",
			"read docker config: open " + filepath.Join("<home>", ".docker", "config.json") + ": denied"},
		{"parse podman auth file " + authFile + ": not valid JSON at byte 1",
			"parse podman auth file <REGISTRY_AUTH_FILE>: not valid JSON at byte 1"},
		{"read " + filepath.Join(runtimeDir, "containers", "auth.json") + ": denied",
			"read " + filepath.Join("<XDG_RUNTIME_DIR>", "containers", "auth.json") + ": denied"},
		{"read " + filepath.Join(dockerCfg, "config.json") + ": denied",
			"read " + filepath.Join("<DOCKER_CONFIG>", "config.json") + ": denied"},
		// Only at a component boundary: a sibling sharing the home
		// directory's prefix is another path, while a sentence's closing
		// period ends one.
		{"read " + home + "2: denied", "read " + home + "2: denied"},
		{"no package database in " + wd + ".", "no package database in <cwd>."},
	} {
		r := newRecorder(db, "t", Options{}, io.Discard, io.Discard)
		fmt.Fprintf(r.stderr, "error: %s\n", tt.line)
		if got := r.errorText(); got != tt.want {
			t.Errorf("errorText(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// The credential half through Run: a podman auth file named by
// REGISTRY_AUTH_FILE that is not JSON stops a registry scan with an error
// naming the file, and the sidecar names the variable instead.
func TestRun_D120_BrokenPodmanAuthFileIsNotInTheSidecar(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	ref := pushImage(t, ar.host, "library/alpine:3.19",
		vexRegistryImage(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkThreePackages}))
	auth := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(auth, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_AUTH_FILE", auth)
	side := filepath.Join(t.TempDir(), "prov.json")

	var out, errOut bytes.Buffer
	code := Run(context.Background(), testDB(t), ref, Options{ProvenanceFile: side}, &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), auth) {
		t.Fatalf("Run = %d, want 2 with the auth file named on stderr\nstderr: %s", code, errOut.String())
	}
	e, _ := at(t, readSidecar(t, side), "run", "error").(string)
	if strings.Contains(e, auth) || !strings.Contains(e, "<REGISTRY_AUTH_FILE>") {
		t.Errorf("run.error = %q, want the auth file named by its variable", e)
	}
}

// D120 names a 401 as an exit the sidecar must explain, and target names the
// D118 credential source. A credential that was offered and refused on the
// manifest is still the source that was offered — stderr says so — and the
// record must not call it "none".
func TestRun_D120_RefusedCredentialIsRecordedBySource(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, dockerConfig, host string)
		want  string
	}{
		{"environment", func(t *testing.T, _, _ string) {
			t.Setenv("ASSAY_REGISTRY_AUTH_TOKEN", regToken)
		}, "environment"},
		{"docker config", func(t *testing.T, dc, host string) {
			writeAuthsFile(t, filepath.Join(dc, "config.json"), host, regUser, regWrongPass)
		}, "docker-config"},
		{"anonymous", func(*testing.T, string, string) {}, "none"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dc := isolateCredentials(t)
			ar := newAuthRegistry(t, acceptBasic)
			ref := ar.push(t)
			tt.setup(t, dc, ar.host)
			side := filepath.Join(t.TempDir(), "prov.json")

			var out, errOut bytes.Buffer
			code := Run(context.Background(), testDB(t), ref, Options{ProvenanceFile: side}, &out, &errOut)
			if code != 2 || !strings.Contains(errOut.String(), "answered 401 Unauthorized") {
				t.Fatalf("Run = %d, want 2 on a 401\nstderr: %s", code, errOut.String())
			}
			sc := readSidecar(t, side)
			if got := at(t, sc, "provenance", "target", "registryCredentials"); got != tt.want {
				t.Errorf("target.registryCredentials = %v, want %q\nstderr: %s", got, tt.want, errOut.String())
			}
			assertNoSecrets(t, out.String(), errOut.String())
		})
	}
}

// Every gate that can move the exit code is in policy (D120). Each is set
// alone, and its key must read differently from a run with none set — so
// dropping any one from policyOf, or renaming its JSON key, turns a row red.
// The sidecar is read rather than the report because some gates refuse this
// database (no EOL data) and end the scan before any report.
func TestRun_D120_PolicyRecordsEveryGate(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	policy := func(t *testing.T, opts Options) map[string]any {
		t.Helper()
		opts.ProvenanceFile = filepath.Join(t.TempDir(), "prov.json")
		provRun(t, db, sbom, opts)
		p, ok := at(t, readSidecar(t, opts.ProvenanceFile), "provenance", "policy").(map[string]any)
		if !ok {
			t.Fatal("sidecar has no policy object")
		}
		return p
	}
	base := policy(t, Options{})
	epss := 0.5
	for _, tt := range []struct {
		key  string
		opts Options
		want any
	}{
		{"failOnUnknown", Options{FailOnUnknown: true}, true},
		{"failOnIncomplete", Options{FailOnIncomplete: true}, true},
		{"failOnIncompleteTarget", Options{FailOnIncompleteTarget: true}, true},
		{"failOnUnfixable", Options{FailOnUnfixable: true}, true},
		{"failOnUnfixableWontFix", Options{FailOnUnfixableWontFix: true}, true},
		{"failOnKev", Options{FailOnKEV: true}, true},
		{"failOnEol", Options{FailOnEOL: true}, true},
		{"failOnEpss", Options{FailOnEPSS: &epss}, 0.5},
		{"dbMaxRatingAge", Options{DBMaxRatingAge: 72 * time.Hour}, "72h0m0s"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := policy(t, tt.opts)[tt.key]
			if !ok || got != tt.want {
				t.Errorf("policy.%s = %v (present %v), want %v", tt.key, got, ok, tt.want)
			}
			if reflect.DeepEqual(base[tt.key], tt.want) {
				t.Errorf("policy.%s reads %v with no gate set too; the row proves nothing", tt.key, base[tt.key])
			}
		})
	}
}

// The skipped and out-of-scope counts reach both the stderr summary and the
// waiver record: one statement skipped for having no reason, one scoped to an
// image in a scan of an SBOM.
func TestRun_D120_VEXSkippedAndOutOfScopeAreCounted(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	vexPath := filepath.Join(dir, "vex.json")
	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/skip",` +
		`"author":"D120 Test","timestamp":"2026-10-13T00:00:00Z","version":1,"statements":[` +
		`{"vulnerability":{"name":"` + provCVE + `"},"products":[{"@id":"` + provPURL + `"}],"status":"not_affected"},` +
		`{"vulnerability":{"name":"` + provCVE + `"},"products":[{"@id":"pkg:oci/other@sha256:` +
		strings.Repeat("0", 64) + `","subcomponents":[{"@id":"` + provPURL + `"}]}],` +
		`"status":"not_affected","justification":"vulnerable_code_not_present"}]}`
	if err := os.WriteFile(vexPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	side := filepath.Join(dir, "prov.json")
	_, stderr, _ := provRun(t, db, sbom, Options{VEXFiles: []string{vexPath}, ProvenanceFile: side})
	if !strings.Contains(stderr, "(1 name an image that is not this target, 1 skipped)") {
		t.Errorf("stderr summary does not count one out of scope and one skipped:\n%s", stderr)
	}
	v := at(t, readSidecar(t, side), "provenance", "waivers", "vex", 0)
	if at(t, v, "skipped") != 1.0 || at(t, v, "outOfScope") != 1.0 || at(t, v, "statements") != 2.0 {
		t.Errorf("waivers.vex[0] = %v, want 2 statements, 1 skipped, 1 out of scope", v)
	}
}

// D121 through Run, by index digest. A statement may name the multi-arch
// index a tag points at rather than the platform's manifest; D119 records
// both, and either identifies the image. Pushed as a one-entry index so the
// manifest digest differs from the index digest the statement names.
func TestRun_VEXImageScopeByIndexDigest(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	db := alpineVEXDB(t)
	img := vexRegistryImage(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkThreePackages})
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	p := v1.Platform{OS: cf.OS, Architecture: cf.Architecture}
	setHost(t, p.OS+"/"+p.Architecture)
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}})
	ref := pushIndex(t, ar.host, "library/alpine:3.19", idx)
	indexDigest := digestOf(t, idx)

	vexPath := writeVEX(t, stmt("CVE-2031-9002", product("pkg:oci/alpine@"+indexDigest, libssl3PURL)))
	doc, stderr := scanVEXJSON(t, db, ref, vexPath)
	if doc.Image == nil || doc.Image.IndexDigest != indexDigest || doc.Image.ManifestDigest == indexDigest {
		t.Fatalf("image record = %+v, want the index digest beside a different manifest digest", doc.Image)
	}
	if sup := suppressedPairs(doc); !sup[pair{"libssl3", "CVE-2031-9002"}] || len(doc.Suppressed) != 1 {
		t.Errorf("a statement scoped to the index digest: suppressed = %v, want exactly libssl3/CVE-2031-9002\nstderr: %s",
			sup, stderr)
	}
}
