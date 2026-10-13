package source

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Unit tests for the branches scancmd's registry tests cannot reach through
// a localhost registry: docker.io's aliases, podman's key spellings, and the
// error texts' refusal to carry a value. The caller tests are in
// internal/scancmd/credentials_test.go and come first (CLAUDE.md).

func isolateEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	for _, v := range []string{EnvRegistryUsername, EnvRegistryPassword, EnvRegistryToken, EnvRegistryAuthority} {
		t.Setenv(v, "")
	}
}

func repo(t *testing.T, s string) name.Repository {
	t.Helper()
	r, err := name.NewRepository(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestKeychain_AuthorityDockerIOMatchesIndexDockerIO(t *testing.T) {
	for _, authority := range []string{"docker.io", "index.docker.io"} {
		t.Run(authority, func(t *testing.T) {
			isolateEnv(t)
			t.Setenv(EnvRegistryUsername, "u")
			t.Setenv(EnvRegistryPassword, "p")
			t.Setenv(EnvRegistryAuthority, authority)

			target, err := name.ParseReference("alpine:3.19")
			if err != nil {
				t.Fatal(err)
			}
			kc, err := newKeychain(target)
			if err != nil {
				t.Fatal(err)
			}
			a, err := kc.Resolve(target.Context())
			if err != nil {
				t.Fatal(err)
			}
			if a == authn.Anonymous || kc.source() != CredentialsEnvironment {
				t.Errorf("authority %q did not answer for %s (source %q)", authority,
					target.Context().RegistryStr(), kc.source())
			}
		})
	}
}

// Without an authority the credential is bound to the target's registry: a
// resource on another host (a cross-repository mount, a redirect) is not
// offered it.
func TestKeychain_UnscopedEnvironmentAnswersOnlyForTheTarget(t *testing.T) {
	isolateEnv(t)
	t.Setenv(EnvRegistryUsername, "u")
	t.Setenv(EnvRegistryPassword, "p")
	target, err := name.ParseReference("registry.example.com/team/app:1")
	if err != nil {
		t.Fatal(err)
	}
	kc, err := newKeychain(target)
	if err != nil {
		t.Fatal(err)
	}
	a, err := kc.Resolve(repo(t, "other.example.com/team/app"))
	if err != nil {
		t.Fatal(err)
	}
	if a != authn.Anonymous {
		t.Error("the environment credential was offered to a registry the scan did not target")
	}
	if a, _ := kc.Resolve(target.Context()); a == authn.Anonymous {
		t.Error("the environment credential was not offered to the target's own registry")
	}
}

func TestReadEnvCredential(t *testing.T) {
	cases := []struct {
		name    string
		set     map[string]string
		wantErr string // "" = no error
		wantSet bool
	}{
		{"nothing", nil, "", false},
		{"empty values count as unset", map[string]string{EnvRegistryUsername: "", EnvRegistryPassword: ""}, "", false},
		{"basic", map[string]string{EnvRegistryUsername: "u", EnvRegistryPassword: "p"}, "", true},
		{"token", map[string]string{EnvRegistryToken: "t"}, "", true},
		{"token with authority", map[string]string{EnvRegistryToken: "t", EnvRegistryAuthority: "ghcr.io"}, "", true},
		{"bad authority", map[string]string{EnvRegistryToken: "t", EnvRegistryAuthority: "a b"}, EnvRegistryAuthority + " is not a registry host", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			e, err := readEnvCredential()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if e.set() != tc.wantSet {
					t.Errorf("set() = %v, want %v", e.set(), tc.wantSet)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func encAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func TestMatchAuthKey(t *testing.T) {
	cases := []struct {
		name     string
		keys     map[string]string // key -> user
		resource string
		wantUser string // "" = no match
	}{
		{"bare host", map[string]string{"ghcr.io": "a"}, "ghcr.io/x/y", "a"},
		{"https url with api path", map[string]string{"https://index.docker.io/v1/": "a"}, "index.docker.io/library/alpine", "a"},
		{"docker.io alias", map[string]string{"docker.io": "a"}, "index.docker.io/library/alpine", "a"},
		{"other host", map[string]string{"ghcr.io": "a"}, "quay.io/x/y", ""},
		{"host with port is its own host", map[string]string{"ghcr.io": "a"}, "ghcr.io:5000/x/y", ""},
		{"repository-scoped wins over host", map[string]string{"ghcr.io": "a", "ghcr.io/team": "b"}, "ghcr.io/team/app", "b"},
		{"longer scope wins", map[string]string{"ghcr.io/team": "b", "ghcr.io/team/app": "c"}, "ghcr.io/team/app", "c"},
		{"scope is a path prefix, not a string prefix", map[string]string{"ghcr.io/team": "b"}, "ghcr.io/teammate/app", ""},
		{"scope with a trailing slash", map[string]string{"ghcr.io/team/": "b"}, "ghcr.io/team/app", "b"},
		{"empty auth is skipped", map[string]string{"ghcr.io": ""}, "ghcr.io/x/y", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var f podmanAuthFile
			f.Auths = map[string]struct {
				Auth string `json:"auth"`
			}{}
			for k, u := range tc.keys {
				v := f.Auths[k]
				if u != "" {
					v.Auth = encAuth(u, "p")
				}
				f.Auths[k] = v
			}
			auth, _, ok := matchAuthKey(f, repo(t, tc.resource))
			if tc.wantUser == "" {
				if ok {
					t.Errorf("matched %q, want no match", auth)
				}
				return
			}
			if !ok || auth != encAuth(tc.wantUser, "p") {
				t.Errorf("matched %v, want %s's entry", ok, tc.wantUser)
			}
		})
	}
}

func TestPodmanCredential_Files(t *testing.T) {
	const secret = "s3cr3t-Vq8"
	cases := []struct {
		name    string
		body    *string // nil = no file
		wantErr bool
		wantNil bool
	}{
		{"missing file is no login", nil, false, true},
		{"valid", ptr(fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`, encAuth("u", secret))), false, false},
		{"no entry for the host", ptr(fmt.Sprintf(`{"auths":{"quay.io":{"auth":%q}}}`, encAuth("u", secret))), false, true},
		{"garbage is an error", ptr(`{"auths": {"ghcr.io": ` + secret), true, false},
		{"wrong shape is an error", ptr(`{"auths": ["` + secret + `"]}`), true, false},
		{"auth not base64", ptr(`{"auths":{"ghcr.io":{"auth":"` + secret + `!!"}}}`), true, false},
		{"auth without a colon", ptr(fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`,
			base64.StdEncoding.EncodeToString([]byte(secret)))), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			p := filepath.Join(t.TempDir(), "auth.json")
			if tc.body != nil {
				if err := os.WriteFile(p, []byte(*tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("REGISTRY_AUTH_FILE", p)
			a, err := podmanCredential(repo(t, "ghcr.io/x/y"))
			if tc.wantErr {
				if err == nil {
					t.Fatal("err = nil, want an error")
				}
				if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), secret[:4]) {
					t.Errorf("the error carries part of the file's secret: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (a == nil) != tc.wantNil {
				t.Errorf("authenticator = %v, want nil=%v", a, tc.wantNil)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// An unset XDG_RUNTIME_DIR must not turn into a relative containers/auth.json
// read from the working directory — which is what DefaultKeychain's fallback
// does (filepath.Join("", "containers/auth.json")).
func TestPodmanAuthPath_NoXDGRuntimeDirIsNoPath(t *testing.T) {
	isolateEnv(t)
	if p := podmanAuthPath(); p != "" {
		t.Errorf("podmanAuthPath() = %q, want none", p)
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if p := podmanAuthPath(); p != filepath.Join("/run/user/1000", "containers", "auth.json") {
		t.Errorf("podmanAuthPath() = %q", p)
	}
	t.Setenv("REGISTRY_AUTH_FILE", "/etc/auth.json")
	if p := podmanAuthPath(); p != "/etc/auth.json" {
		t.Errorf("podmanAuthPath() = %q, want REGISTRY_AUTH_FILE to win", p)
	}
}

// A docker config that cannot be parsed is an error, not an anonymous pull.
func TestKeychain_UnparsableDockerConfigIsAnError(t *testing.T) {
	isolateEnv(t)
	dc := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dc)
	if err := os.WriteFile(filepath.Join(dc, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, _ := name.ParseReference("ghcr.io/x/y:1")
	kc, err := newKeychain(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kc.Resolve(target.Context()); err == nil || !strings.Contains(err.Error(), "read docker config") {
		t.Errorf("err = %v, want a docker config error", err)
	}
}

func TestAsAuthError(t *testing.T) {
	target, _ := name.ParseReference("ghcr.io/x/y:1")
	kc := &keychain{target: target.Context().RegistryStr()}

	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		err := asAuthError(&transport.Error{StatusCode: code}, "ghcr.io/x/y:1", kc)
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("%d: not an AuthError: %v", code, err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("answered %d %s", code, http.StatusText(code))) {
			t.Errorf("%d: %v", code, err)
		}
		// Unwrap keeps the transport error reachable for callers that branch
		// on it.
		var te *transport.Error
		if !errors.As(err, &te) {
			t.Errorf("%d: the transport error is no longer reachable", code)
		}
	}
	for _, other := range []error{&transport.Error{StatusCode: http.StatusNotFound}, errors.New("dial tcp")} {
		if got := asAuthError(other, "r", kc); got != other {
			t.Errorf("asAuthError(%v) = %v, want it unchanged", other, got)
		}
	}
}
