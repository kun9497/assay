package scancmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// D118's caller tests. Every one goes through Run against a real registry
// behind HTTP auth, because the defect this project repeats is a helper that is
// well tested while nothing calls it: a keychain with perfect unit tests and no
// remote.WithAuthFromKeychain on the pull would pass every test in
// internal/source and still scan nothing private.
//
// The credential values are chosen so no other text in the output contains
// them — a leak assertion that passes because the value never had a chance to
// appear proves nothing, and one that fails on the image reference would be
// noise.
const (
	regUser      = "u-q7Zr"
	regPass      = "pw-K9xT2mLq"
	regToken     = "tok-W4vB8nRe"
	regWrongPass = "pw-WRONG-5hJd"
)

// authRegistry is go-containerregistry's in-memory registry behind a gate that
// admits only the Authorization header accept approves, answering everything
// else with a Basic challenge the way a real htpasswd registry:2 does.
type authRegistry struct {
	host string
	// requests counts what reached the gate once it was locked — the
	// half-set tests assert it stayed zero, i.e. no request left the scan.
	requests atomic.Int64
	locked   atomic.Bool
}

func newAuthRegistry(t *testing.T, accept func(authz string) bool) *authRegistry {
	t.Helper()
	ar := &authRegistry{}
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ar.locked.Load() {
			ar.requests.Add(1)
			if !accept(r.Header.Get("Authorization")) {
				w.Header().Set("WWW-Authenticate", `Basic realm="assay-test"`)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
				return
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	ar.host = strings.TrimPrefix(srv.URL, "http://")
	return ar
}

// push publishes the Alpine 3.19 fixture with one apk package — a real
// scannable image, so success means cataloged and matched, not merely pulled —
// and then locks the gate.
func (ar *authRegistry) push(t *testing.T) string {
	t.Helper()
	ref := ar.host + "/private/alpine:3.19"
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, alpineImage(t)); err != nil {
		t.Fatalf("push: %v", err)
	}
	ar.locked.Store(true)
	return ref
}

func alpineImage(t *testing.T) v1.Image {
	t.Helper()
	raw := buildTar(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkOneRecord})
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	// The registry path selects linux/<host arch> (hostPlatform), so the
	// config has to say it.
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", runtime.GOARCH
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func acceptBasic(authz string) bool { return authz == basicHeader(regUser, regPass) }

// isolateCredentials points every credential source at an empty temp location,
// so the developer's own ~/.docker and podman login never answer for a test.
// DOCKER_CONFIG is always set explicitly: docker/cli caches its config
// directory per process, so relying on HOME alone would read whatever the
// first test in the binary saw.
func isolateCredentials(t *testing.T) (dockerConfig string) {
	t.Helper()
	home := t.TempDir()
	dockerConfig = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("DOCKER_CONFIG", dockerConfig)
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	for _, v := range []string{"ASSAY_REGISTRY_AUTH_USERNAME", "ASSAY_REGISTRY_AUTH_PASSWORD",
		"ASSAY_REGISTRY_AUTH_TOKEN", "ASSAY_REGISTRY_AUTH_AUTHORITY"} {
		t.Setenv(v, "")
	}
	return dockerConfig
}

// writeAuthsFile writes docker's config format — {"auths":{host:{"auth":…}}}
// — which is also podman's auth.json.
func writeAuthsFile(t *testing.T, path, host, user, pass string) {
	t.Helper()
	enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	body := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, enc)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runScan(t *testing.T, target string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), testDB(t), target, Options{}, &out, &errOut)
	return out.String(), errOut.String(), code
}

// assertNoSecrets holds D118's "never the value" on both streams: the
// password, the token, the username (a value too), and the encoded auth field.
func assertNoSecrets(t *testing.T, stdout, stderr string) {
	t.Helper()
	for _, s := range []string{regUser, regPass, regToken, regWrongPass,
		base64.StdEncoding.EncodeToString([]byte(regUser + ":" + regPass)),
		base64.StdEncoding.EncodeToString([]byte(regUser + ":" + regWrongPass))} {
		if strings.Contains(stdout, s) || strings.Contains(stderr, s) {
			t.Errorf("a credential value appeared in the output\nstdout: %s\nstderr: %s", stdout, stderr)
		}
	}
}

func wantScanned(t *testing.T, stdout, stderr string, code int) {
	t.Helper()
	if code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "1 package") {
		t.Errorf("stdout = %q, want the one apk package evaluated", stdout)
	}
}

func sourceLine(host, source string) string {
	return "registry credentials for " + host + ": from " + source + "\n"
}

func TestRun_RegistryAnonymousAgainstAuthIsExit2WithGuidance(t *testing.T) {
	isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)

	out, errOut, code := runScan(t, ref)
	if code != 2 {
		t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
	}
	// Each half of the guidance asserted as a phrase that can only come from
	// the guidance itself: the ref also contains the host, so "registry HOST"
	// and "docker login HOST" pin the AuthError's own wording, not the URL.
	for _, want := range []string{
		"registry " + ar.host + " answered 401 Unauthorized",
		"no credentials were offered",
		"`docker login " + ar.host + "`",
		"ASSAY_REGISTRY_AUTH_USERNAME and ASSAY_REGISTRY_AUTH_PASSWORD",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(errOut, "registry credentials for") {
		t.Errorf("an anonymous pull printed a credential source line:\n%s", errOut)
	}
	if out != "" {
		t.Errorf("stdout = %q, want nothing on an exit-2 scan", out)
	}
}

func TestRun_RegistryEnvironmentBasic(t *testing.T) {
	isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
	t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regPass)

	out, errOut, code := runScan(t, ref)
	wantScanned(t, out, errOut, code)
	if !strings.Contains(errOut, sourceLine(ar.host, "the environment")) {
		t.Errorf("stderr lacks the environment source line:\n%s", errOut)
	}
	assertNoSecrets(t, out, errOut)
}

func TestRun_RegistryEnvironmentToken(t *testing.T) {
	isolateCredentials(t)
	ar := newAuthRegistry(t, func(a string) bool { return a == "Bearer "+regToken })
	ref := ar.push(t)
	t.Setenv("ASSAY_REGISTRY_AUTH_TOKEN", regToken)

	out, errOut, code := runScan(t, ref)
	wantScanned(t, out, errOut, code)
	if !strings.Contains(errOut, sourceLine(ar.host, "the environment")) {
		t.Errorf("stderr lacks the environment source line:\n%s", errOut)
	}
	assertNoSecrets(t, out, errOut)
}

func TestRun_RegistryDockerConfig(t *testing.T) {
	dc := isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	writeAuthsFile(t, filepath.Join(dc, "config.json"), ar.host, regUser, regPass)

	out, errOut, code := runScan(t, ref)
	wantScanned(t, out, errOut, code)
	if !strings.Contains(errOut, sourceLine(ar.host, "the docker config")) {
		t.Errorf("stderr lacks the docker config source line:\n%s", errOut)
	}
	assertNoSecrets(t, out, errOut)
}

// The case DefaultKeychain alone gets wrong (D118's second measurement): a
// docker config for any other registry makes the library ignore podman's file.
//
// "no docker config" is the other half: there the library WOULD read podman's
// file itself, and the source line must still say podman — an answer that came
// through DefaultKeychain's fallback would be reported as the docker config's.
func TestRun_RegistryPodmanFileBesideAnUnrelatedDockerConfig(t *testing.T) {
	for _, via := range []string{"REGISTRY_AUTH_FILE", "XDG_RUNTIME_DIR", "no docker config"} {
		t.Run(via, func(t *testing.T) {
			dc := isolateCredentials(t)
			ar := newAuthRegistry(t, acceptBasic)
			ref := ar.push(t)
			if via != "no docker config" {
				writeAuthsFile(t, filepath.Join(dc, "config.json"), "other.example.com", "x", "y")
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "auth.json")
			if via == "XDG_RUNTIME_DIR" {
				if err := os.MkdirAll(filepath.Join(dir, "containers"), 0o700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "containers", "auth.json")
				t.Setenv("XDG_RUNTIME_DIR", dir)
			} else {
				t.Setenv("REGISTRY_AUTH_FILE", path)
			}
			writeAuthsFile(t, path, ar.host, regUser, regPass)

			out, errOut, code := runScan(t, ref)
			wantScanned(t, out, errOut, code)
			if !strings.Contains(errOut, sourceLine(ar.host, "the podman auth file")) {
				t.Errorf("stderr lacks the podman source line:\n%s", errOut)
			}
			assertNoSecrets(t, out, errOut)
		})
	}
}

// D118's first measurement: a stale docker login for the same host must not
// shadow the credential the job states in its environment.
func TestRun_RegistryEnvironmentBeatsAStaleDockerConfig(t *testing.T) {
	dc := isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	writeAuthsFile(t, filepath.Join(dc, "config.json"), ar.host, regUser, regWrongPass)
	t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
	t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regPass)

	out, errOut, code := runScan(t, ref)
	wantScanned(t, out, errOut, code)
	if !strings.Contains(errOut, sourceLine(ar.host, "the environment")) {
		t.Errorf("stderr lacks the environment source line:\n%s", errOut)
	}
	assertNoSecrets(t, out, errOut)
}

// A stale docker login alone is a 401 that names the docker config as what
// was offered — the reader is sent to the login, not to the registry.
func TestRun_RegistryStaleDockerConfigNamesItsSource(t *testing.T) {
	dc := isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	writeAuthsFile(t, filepath.Join(dc, "config.json"), ar.host, regUser, regWrongPass)

	out, errOut, code := runScan(t, ref)
	if code != 2 {
		t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
	}
	if !strings.Contains(errOut, "to the credentials offered from the docker config") {
		t.Errorf("stderr does not name the docker config as the source offered:\n%s", errOut)
	}
	assertNoSecrets(t, out, errOut)
}

func TestRun_RegistryAuthorityScopedElsewhereIsNotOffered(t *testing.T) {
	isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
	t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regPass)
	t.Setenv("ASSAY_REGISTRY_AUTH_AUTHORITY", "registry.example.com")

	out, errOut, code := runScan(t, ref)
	if code != 2 {
		t.Fatalf("Run = %d, want 2: a credential scoped to another registry was offered here\nstderr: %s", code, errOut)
	}
	for _, want := range []string{
		"no credentials were offered",
		"scoped by ASSAY_REGISTRY_AUTH_AUTHORITY to registry.example.com",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	assertNoSecrets(t, out, errOut)
}

// An authority naming the target's registry is honoured — the scoped path
// offers the credential, not only refuses it elsewhere.
func TestRun_RegistryAuthorityMatchingTheTargetIsOffered(t *testing.T) {
	isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
	t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regPass)
	t.Setenv("ASSAY_REGISTRY_AUTH_AUTHORITY", ar.host)

	out, errOut, code := runScan(t, ref)
	wantScanned(t, out, errOut, code)
	if !strings.Contains(errOut, sourceLine(ar.host, "the environment")) {
		t.Errorf("stderr lacks the environment source line:\n%s", errOut)
	}
}

func TestRun_RegistryHalfSetEnvironmentIsExit2BeforeAnyRequest(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]string
		want []string
	}{
		{"username alone", map[string]string{"ASSAY_REGISTRY_AUTH_USERNAME": regUser},
			[]string{"ASSAY_REGISTRY_AUTH_USERNAME is set without ASSAY_REGISTRY_AUTH_PASSWORD"}},
		{"password alone", map[string]string{"ASSAY_REGISTRY_AUTH_PASSWORD": regPass},
			[]string{"ASSAY_REGISTRY_AUTH_PASSWORD is set without ASSAY_REGISTRY_AUTH_USERNAME"}},
		{"token with username", map[string]string{"ASSAY_REGISTRY_AUTH_TOKEN": regToken,
			"ASSAY_REGISTRY_AUTH_USERNAME": regUser},
			[]string{"ASSAY_REGISTRY_AUTH_TOKEN is set together with"}},
		{"token with password", map[string]string{"ASSAY_REGISTRY_AUTH_TOKEN": regToken,
			"ASSAY_REGISTRY_AUTH_PASSWORD": regPass},
			[]string{"ASSAY_REGISTRY_AUTH_TOKEN is set together with"}},
		{"token with both", map[string]string{"ASSAY_REGISTRY_AUTH_TOKEN": regToken,
			"ASSAY_REGISTRY_AUTH_USERNAME": regUser, "ASSAY_REGISTRY_AUTH_PASSWORD": regPass},
			[]string{"ASSAY_REGISTRY_AUTH_TOKEN is set together with"}},
		{"authority alone", map[string]string{"ASSAY_REGISTRY_AUTH_AUTHORITY": "registry.example.com"},
			[]string{"ASSAY_REGISTRY_AUTH_AUTHORITY is set without a credential"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dc := isolateCredentials(t)
			ar := newAuthRegistry(t, acceptBasic)
			ref := ar.push(t)
			// A valid docker login is present, so "fell back to the next
			// source" would succeed — exit 2 here is the half-set check, not a
			// 401.
			writeAuthsFile(t, filepath.Join(dc, "config.json"), ar.host, regUser, regPass)
			for k, v := range tc.set {
				t.Setenv(k, v)
			}

			out, errOut, code := runScan(t, ref)
			if code != 2 {
				t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(errOut, w) {
					t.Errorf("stderr lacks %q:\n%s", w, errOut)
				}
			}
			if n := ar.requests.Load(); n != 0 {
				t.Errorf("%d request(s) reached the registry; a half-set credential must stop the scan first", n)
			}
			assertNoSecrets(t, out, errOut)
		})
	}
}

func TestRun_RegistryWrongPasswordIsExit2AndNeverPrinted(t *testing.T) {
	isolateCredentials(t)
	ar := newAuthRegistry(t, acceptBasic)
	ref := ar.push(t)
	t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
	t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regWrongPass)

	out, errOut, code := runScan(t, ref)
	if code != 2 {
		t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
	}
	if !strings.Contains(errOut, "to the credentials offered from the environment") {
		t.Errorf("stderr does not name the environment as the source offered:\n%s", errOut)
	}
	if ar.requests.Load() == 0 {
		t.Fatal("no request reached the registry; the wrong password was never sent, so its absence from the output proves nothing")
	}
	assertNoSecrets(t, out, errOut)
}

// The air-gapped path never consults the chain (D14, D118): a garbage half-set
// environment that stops a registry scan cold is invisible to an archive or a
// layout scan.
func TestRun_LocalImagesNeverConsultTheChain(t *testing.T) {
	isolateCredentials(t)
	t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
	t.Setenv("ASSAY_REGISTRY_AUTH_AUTHORITY", "::not a host::")

	img := alpineImage(t)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	tagged, err := name.ParseReference("scancmd-test:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(tarPath, tagged, img); err != nil {
		t.Fatal(err)
	}
	layoutDir := filepath.Join(t.TempDir(), "layout")
	lp, err := layout.Write(layoutDir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AppendImage(img); err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{"docker-archive:" + tarPath, "oci-dir:" + layoutDir} {
		t.Run(strings.SplitN(target, ":", 2)[0], func(t *testing.T) {
			out, errOut, code := runScan(t, target)
			wantScanned(t, out, errOut, code)
			if strings.Contains(errOut, "ASSAY_REGISTRY_AUTH") || strings.Contains(errOut, "registry credentials") {
				t.Errorf("a local image scan consulted the credential chain:\n%s", errOut)
			}
		})
	}

	// The same environment does stop a registry scan, so the subtests above
	// pass because the chain was not consulted, not because this environment
	// is acceptable.
	_, errOut, code := runScan(t, "127.0.0.1:1/never/reached:latest")
	if code != 2 || !strings.Contains(errOut, "ASSAY_REGISTRY_AUTH_USERNAME is set without") {
		t.Errorf("Run(registry) = %d, want 2 on the half-set check\nstderr: %s", code, errOut)
	}
}
