package source

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestLayoutConfigStopsAtFirstUndeclaredByte(t *testing.T) {
	const blob = "an understated config"
	source := strings.NewReader(blob)
	img := layoutImage{
		Image: fakeImage{declaredConfig: 1},
		openBlob: func(v1.Hash) (io.ReadCloser, error) {
			return io.NopCloser(source), nil
		},
	}
	if _, err := img.RawConfigFile(); err == nil {
		t.Fatal("RawConfigFile accepted the larger blob")
	}
	if read := len(blob) - source.Len(); read != 2 {
		t.Fatalf("read %d bytes from a blob declared as one byte, want 2", read)
	}
}

func TestOpen_LayoutConfigMustFitItsDescriptor(t *testing.T) {
	base := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	for _, tc := range []struct {
		name        string
		actual      int64
		declared    int64
		nested      bool
		hasPlatform bool
		wantErr     string
	}{
		{name: "understated oversized config", actual: MaxConfigBytes + 1, declared: 1, wantErr: "exceeds its declared size"},
		{name: "exactly the limit", actual: MaxConfigBytes, declared: MaxConfigBytes},
		{name: "shorter than declared", actual: int64(len(base)), declared: 1024, wantErr: "manifest declares 1024"},
		{name: "nested with platform", actual: 128, declared: 1, nested: true, hasPlatform: true, wantErr: "exceeds its declared size"},
		{name: "nested without platform", actual: 128, declared: 1, nested: true, wantErr: "offers no readable image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lp, err := layout.Write(dir, empty.Index)
			if err != nil {
				t.Fatal(err)
			}
			raw := bytes.Repeat([]byte{' '}, int(tc.actual))
			copy(raw, base)
			config := v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: writeBlob(t, lp, raw), Size: tc.declared}
			manifest, err := json.Marshal(v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: config})
			if err != nil {
				t.Fatal(err)
			}
			desc := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: writeBlob(t, lp, manifest), Size: int64(len(manifest))}
			if tc.hasPlatform {
				desc.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
			}
			if tc.nested {
				index, err := json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{desc}})
				if err != nil {
					t.Fatal(err)
				}
				desc = v1.Descriptor{MediaType: types.OCIImageIndex, Digest: writeBlob(t, lp, index), Size: int64(len(index))}
			}
			if err := lp.AppendDescriptor(desc); err != nil {
				t.Fatal(err)
			}
			_, err = Open(context.Background(), "oci-dir:"+dir, "linux/amd64")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Open error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
