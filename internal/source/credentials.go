package source

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// The variables are grype's GRYPE_REGISTRY_AUTH_* with assay's prefix (D18,
// D118), so a job migrating between the two renames rather than relearns.
const (
	EnvRegistryUsername  = "ASSAY_REGISTRY_AUTH_USERNAME"
	EnvRegistryPassword  = "ASSAY_REGISTRY_AUTH_PASSWORD"
	EnvRegistryToken     = "ASSAY_REGISTRY_AUTH_TOKEN"
	EnvRegistryAuthority = "ASSAY_REGISTRY_AUTH_AUTHORITY"
)

// CredentialSource names which link of D118's chain answered for a registry.
// It is a name, never a value: the whole point of reporting it is that the
// line saying "the docker config" can be printed and logged where the
// credential itself must never go.
type CredentialSource string

const (
	// CredentialsNone is an anonymous pull — nothing in the chain answered.
	CredentialsNone         CredentialSource = ""
	CredentialsEnvironment  CredentialSource = "the environment"
	CredentialsDockerConfig CredentialSource = "the docker config"
	CredentialsPodmanFile   CredentialSource = "the podman auth file"
)

// Credentials says what a registry pull was offered: the registry, and which
// source supplied the credential. Source is CredentialsNone for an anonymous
// pull, for a pull whose registry never asked, and for every target that is
// not a registry reference at all.
type Credentials struct {
	Registry string
	Source   CredentialSource
}

// envCredential is D118's first source, read once per Open. The values are
// held only to build an authn.Authenticator; nothing formats this struct.
type envCredential struct {
	username, password, token string
	// authority is the registry the credential is scoped to, already through
	// name.NewRegistry so docker.io and index.docker.io compare equal. Empty
	// means the target's own registry.
	authority string
}

func (e envCredential) set() bool { return e.username != "" || e.token != "" }

// readEnvCredential reads the ASSAY_REGISTRY_AUTH_* variables. A half-set
// credential is an error, never a quiet fall back to the next source or to
// anonymous: degraded, it fails later as a 401 that points at the registry
// rather than at the variable the job got wrong.
//
// An empty variable counts as unset. CI templates routinely export a name with
// an empty value when a secret is not configured, and "set to nothing" is the
// same intent as absent.
func readEnvCredential() (envCredential, error) {
	e := envCredential{
		username: os.Getenv(EnvRegistryUsername),
		password: os.Getenv(EnvRegistryPassword),
		token:    os.Getenv(EnvRegistryToken),
	}
	authority := os.Getenv(EnvRegistryAuthority)

	// Errors name variables only. A username is a value too (D118), so even
	// it is never echoed back.
	switch {
	case e.token != "" && (e.username != "" || e.password != ""):
		return envCredential{}, fmt.Errorf("%s is set together with %s/%s; set the token "+
			"alone or the username and password alone, not both", EnvRegistryToken,
			EnvRegistryUsername, EnvRegistryPassword)
	case e.username != "" && e.password == "":
		return envCredential{}, fmt.Errorf("%s is set without %s; set both, or neither "+
			"to use a docker or podman login", EnvRegistryUsername, EnvRegistryPassword)
	case e.password != "" && e.username == "":
		return envCredential{}, fmt.Errorf("%s is set without %s; set both, or neither "+
			"to use a docker or podman login", EnvRegistryPassword, EnvRegistryUsername)
	case authority != "" && !e.set():
		return envCredential{}, fmt.Errorf("%s is set without a credential; set %s and %s, "+
			"or %s, or unset it", EnvRegistryAuthority, EnvRegistryUsername,
			EnvRegistryPassword, EnvRegistryToken)
	}
	if authority != "" {
		reg, err := name.NewRegistry(authority)
		if err != nil {
			return envCredential{}, fmt.Errorf("%s is not a registry host: %w", EnvRegistryAuthority, err)
		}
		e.authority = reg.RegistryStr()
	}
	return e, nil
}

// keychain is D118's chain: the environment, then the docker login, then the
// podman login, first non-anonymous answer wins. It records which one answered
// so the scan can say so — and so a 401 can say what was offered.
type keychain struct {
	env envCredential
	// target is the scan target's own registry. An unscoped environment
	// credential is bound to it rather than to every host the process might be
	// asked about, so a job's credential is offered only where the job pointed.
	target string

	mu   sync.Mutex
	used CredentialSource
}

func newKeychain(target name.Reference) (*keychain, error) {
	env, err := readEnvCredential()
	if err != nil {
		return nil, err
	}
	return &keychain{env: env, target: target.Context().RegistryStr()}, nil
}

// Resolve implements authn.Keychain.
func (k *keychain) Resolve(r authn.Resource) (authn.Authenticator, error) {
	a, src, err := k.resolve(r)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	if k.used == CredentialsNone {
		k.used = src
	}
	k.mu.Unlock()
	return a, nil
}

func (k *keychain) source() CredentialSource {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.used
}

func (k *keychain) resolve(r authn.Resource) (authn.Authenticator, CredentialSource, error) {
	reg := r.RegistryStr()

	// The environment goes first because it is what a job states for itself.
	// Measured 2026-10-13: with it second, a stale docker login for the same
	// host shadowed the right password and the pull was 401.
	if k.env.set() && reg == k.envScope() {
		if k.env.token != "" {
			return &authn.Bearer{Token: k.env.token}, CredentialsEnvironment, nil
		}
		return &authn.Basic{Username: k.env.username, Password: k.env.password}, CredentialsEnvironment, nil
	}

	// DefaultKeychain is consulted only when a docker config exists. Without
	// one it falls back to podman's file itself, and an answer from there
	// would be reported as the docker config's; with one it never reads
	// podman's file at all — the case the third source below exists for.
	if dockerConfigExists() {
		a, err := authn.DefaultKeychain.Resolve(r)
		if err != nil {
			return nil, CredentialsNone, dockerConfigError(err)
		}
		if a != authn.Anonymous {
			return a, CredentialsDockerConfig, nil
		}
	}

	a, err := podmanCredential(r)
	if err != nil {
		return nil, CredentialsNone, err
	}
	if a != nil {
		return a, CredentialsPodmanFile, nil
	}
	return authn.Anonymous, CredentialsNone, nil
}

// dockerConfigError reduces DefaultKeychain's error to text that cannot carry
// a credential. The library hands back docker/cli's config error unchanged,
// and that wraps encoding/json's decode error with %w: a syntax error quotes
// the offending character, which in a hand-edited config can be a byte of a
// password or of the encoded auth field — the same reason podmanCredential
// prints only the offset.
//
// A type mismatch is rewritten too: its Value is the literal for a number
// ("number 12345"), so an unquoted numeric password would be echoed.
//
// Every other failure keeps its text, because that text is the diagnosis: a
// credential helper missing from PATH, an unreadable file, an auth field that
// is not base64 (whose error gives a byte offset, not the data).
func dockerConfigError(err error) error {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("read docker config: not valid JSON at byte %d", se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Errorf("read docker config: not docker's config format at byte %d", te.Offset)
	}
	return fmt.Errorf("read docker config: %w", err)
}

// envScope is the registry the environment credential answers for.
func (k *keychain) envScope() string {
	if k.env.authority != "" {
		return k.env.authority
	}
	return k.target
}

// dockerConfigExists mirrors DefaultKeychain's own test for whether it will
// read a docker config, in its order: ~/.docker/config.json, then
// $DOCKER_CONFIG/config.json. When the first exists the library still loads
// from $DOCKER_CONFIG, so a per-job DOCKER_CONFIG pointed at an empty
// directory isolates the job from the home login (D118's third measurement).
func dockerConfigExists() bool {
	if home, err := os.UserHomeDir(); err == nil && isFile(filepath.Join(home, ".docker", "config.json")) {
		return true
	}
	if d := os.Getenv("DOCKER_CONFIG"); d != "" && isFile(filepath.Join(d, "config.json")) {
		return true
	}
	return false
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// podmanAuthPath is where podman's login writes: $REGISTRY_AUTH_FILE, else
// $XDG_RUNTIME_DIR/containers/auth.json. An unset XDG_RUNTIME_DIR yields no
// path rather than a relative "containers/auth.json", which would read
// whatever file of that name sits in the scan's working directory.
func podmanAuthPath() string {
	if p := os.Getenv("REGISTRY_AUTH_FILE"); p != "" {
		return p
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "containers", "auth.json")
	}
	return ""
}

// podmanAuthFile is the slice of podman's auth.json assay reads — docker's
// config format, which is why it is parsed here with encoding/json rather than
// through docker/cli: importing that would make it a direct dependency.
type podmanAuthFile struct {
	Auths map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

// podmanCredential returns the podman login for r's registry, or nil when
// there is none. A missing file is no login; a file that exists and cannot be
// read or parsed is an error, because skipping it would turn a broken login
// into an anonymous pull that fails with a 401 naming the registry instead.
func podmanCredential(r authn.Resource) (authn.Authenticator, error) {
	p := podmanAuthPath()
	if p == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read podman auth file: %w", err)
	}
	var f podmanAuthFile
	if err := json.Unmarshal(raw, &f); err != nil {
		// Not %v of the decode error: a syntax error quotes the offending
		// character, and in this file that character can be part of a secret.
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("parse podman auth file %s: not valid JSON at byte %d", p, se.Offset)
		}
		return nil, fmt.Errorf("parse podman auth file %s: not docker's config format", p)
	}

	auth, key, ok := matchAuthKey(f, r)
	if !ok {
		return nil, nil
	}
	dec, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return nil, fmt.Errorf("parse podman auth file %s: the auth entry for %s is not base64", p, key)
	}
	user, pass, ok := strings.Cut(string(dec), ":")
	if !ok || user == "" || pass == "" {
		return nil, fmt.Errorf("parse podman auth file %s: the auth entry for %s is not user:password", p, key)
	}
	return &authn.Basic{Username: user, Password: pass}, nil
}

// matchAuthKey finds r's entry in the auths map. Podman writes bare hosts and
// may write repository-scoped keys (host/namespace); older docker-format files
// carry https:// URLs such as https://index.docker.io/v1/. Every key's host is
// normalised through name.NewRegistry so docker.io and index.docker.io are one
// host. A repository-scoped key wins over the bare host, the longest first —
// podman's own precedence.
func matchAuthKey(f podmanAuthFile, r authn.Resource) (auth, key string, ok bool) {
	reg := r.RegistryStr()
	repo := strings.TrimPrefix(r.String(), reg)
	bestLen := -1
	for k, v := range f.Auths {
		if v.Auth == "" {
			continue
		}
		host, path := k, ""
		schemed := false
		for _, s := range []string{"https://", "http://"} {
			if strings.HasPrefix(host, s) {
				host, schemed = strings.TrimPrefix(host, s), true
			}
		}
		host, path, _ = strings.Cut(host, "/")
		// A URL's path is an API version (/v1/), not a repository.
		if schemed {
			path = ""
		}
		nr, err := name.NewRegistry(host)
		if err != nil || nr.RegistryStr() != reg {
			continue
		}
		if path != "" {
			want := "/" + strings.TrimSuffix(path, "/")
			if repo != want && !strings.HasPrefix(repo, want+"/") {
				continue
			}
		}
		if len(path) > bestLen {
			auth, key, ok, bestLen = v.Auth, k, true, len(path)
		}
	}
	return auth, key, ok
}

// AuthError is a registry's 401 or 403, worded for whoever has to fix it
// (D118): which registry, whether credentials were offered and from where,
// and the two ways to supply them. It names sources, never values.
type AuthError struct {
	Ref      string
	Registry string
	Status   int
	Source   CredentialSource
	// EnvScopedTo is set when an environment credential exists but is scoped
	// by ASSAY_REGISTRY_AUTH_AUTHORITY to another registry — the case where
	// "no credentials were offered" is true and baffling at once.
	EnvScopedTo string
	Err         error
}

func (e *AuthError) Error() string {
	status := fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status))
	var what string
	if e.Source == CredentialsNone {
		what = fmt.Sprintf("registry %s answered %s and no credentials were offered "+
			"(the environment, the docker config and the podman auth file had none for it)",
			e.Registry, status)
		if e.EnvScopedTo != "" {
			what += fmt.Sprintf("; the environment credential is scoped by %s to %s",
				EnvRegistryAuthority, e.EnvScopedTo)
		}
	} else {
		what = fmt.Sprintf("registry %s answered %s to the credentials offered from %s",
			e.Registry, status, e.Source)
	}
	return fmt.Sprintf("pull %s: %s; run `docker login %s`, or set %s and %s (or %s): %v",
		e.Ref, what, e.Registry, EnvRegistryUsername, EnvRegistryPassword, EnvRegistryToken, e.Err)
}

func (e *AuthError) Unwrap() error { return e.Err }

// asAuthError rewrites a registry's 401/403 into an AuthError and leaves every
// other error alone. It is applied at every point a registry request can be
// refused, not only the manifest fetch: the config blob is fetched while Open
// lists the layers, and each layer blob is fetched later still, when the
// cataloger opens the layer — after Open has returned. A credential rotated
// mid-scan or a registry that refuses blob pulls by policy answers there, so
// Open wraps each registry layer's opener too.
func asAuthError(err error, ref string, kc *keychain) error {
	var te *transport.Error
	if !errors.As(err, &te) {
		return err
	}
	if te.StatusCode != http.StatusUnauthorized && te.StatusCode != http.StatusForbidden {
		return err
	}
	ae := &AuthError{Ref: ref, Registry: kc.target, Status: te.StatusCode, Source: kc.source(), Err: err}
	if ae.Source == CredentialsNone && kc.env.set() && kc.envScope() != kc.target {
		ae.EnvScopedTo = kc.envScope()
	}
	return ae
}
