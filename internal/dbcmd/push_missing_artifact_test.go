package dbcmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// QA 2026-11-20. Only a 404 that names the manifest or the repository as
// unknown means nothing is published; anything else is a check that could not
// be made, and publishing over it would skip the narrowing guard.
func TestMissingArtifact(t *testing.T) {
	e := func(status int, codes ...transport.ErrorCode) error {
		x := &transport.Error{StatusCode: status}
		for _, c := range codes {
			x.Errors = append(x.Errors, transport.Diagnostic{Code: c})
		}
		return fmt.Errorf("get: %w", x)
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"manifest unknown":     {e(404, transport.ManifestUnknownErrorCode), true},
		"repository unknown":   {e(404, transport.NameUnknownErrorCode), true},
		"404 without a code":   {e(404), false},
		"404, denied":          {e(404, transport.DeniedErrorCode), false},
		"404, mixed":           {e(404, transport.ManifestUnknownErrorCode, transport.DeniedErrorCode), false},
		"403 denied":           {e(403, transport.DeniedErrorCode), false},
		"403 manifest unknown": {e(403, transport.ManifestUnknownErrorCode), false},
		"500":                  {e(500, transport.ManifestUnknownErrorCode), false},
		"not a registry error": {errors.New("x"), false},
	} {
		if got := missingArtifact(tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
