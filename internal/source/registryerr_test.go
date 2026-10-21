package source

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A registry that cannot be reached is an error, not a crash. For an
// http-scheme registry -- localhost, loopback, an RFC 1918 address -- the
// library pings https and http in parallel, and when both fail it returns
// transport.multierrs, a slice: comparing that error to itself with != panics
// ("comparing uncomparable type transport.multierrs"), which is what
// open()'s auth-error check did (2026-10-20 external review). An internal
// registry being down is an ordinary day, so these hold the ordinary days.
func TestOpen_UnreachableRegistryIsAnErrorNotAPanic(t *testing.T) {
	isolateEnv(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	l.Close()

	badGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer badGateway.Close()

	for name, host := range map[string]string{
		"connection refused":   closed,
		"502 on every request": strings.TrimPrefix(badGateway.URL, "http://"),
	} {
		t.Run(name, func(t *testing.T) {
			ref := host + "/team/app:1"
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("Open(%s) panicked: %v", ref, p)
					}
				}()
				_, err = Open(context.Background(), ref, "")
			}()
			if err == nil {
				t.Fatalf("Open(%s) succeeded against a registry that is not there", ref)
			}
			if want := "pull " + ref + ": "; !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to start the way every other pull failure does (%q)", err, want)
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				t.Errorf("err = %v, want a plain pull error -- nothing refused credentials here", err)
			}
		})
	}
}

// The other half of the same check: a refusal is still an AuthError with
// D118's guidance once the comparison is gone.
func TestOpen_RefusedRegistryIsStillAnAuthError(t *testing.T) {
	isolateEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":"DENIED","message":"denied"}]}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	_, err := Open(context.Background(), host+"/team/app:1", "")
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want an *AuthError for a 403", err)
	}
	if ae.Status != http.StatusForbidden || ae.Registry != host {
		t.Errorf("AuthError = {Status %d, Registry %q}, want {403, %q}", ae.Status, ae.Registry, host)
	}
}
