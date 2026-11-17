package source

import (
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// The upstream layout reader reads the entire config blob, regardless of its
// descriptor size. Open the same blob through the library's regular-file
// checks, and stop after the first byte that disproves its declared size.
type layoutImage struct {
	v1.Image
	openBlob func(v1.Hash) (io.ReadCloser, error)
}

func (img layoutImage) RawConfigFile() ([]byte, error) {
	m, err := img.Manifest()
	if err != nil {
		return nil, err
	}
	if err := checkConfigDescriptor(m); err != nil {
		return nil, err
	}
	rc, err := img.openBlob(m.Config.Digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, m.Config.Size+1))
	if err != nil {
		return nil, err
	}
	switch n := int64(len(raw)); {
	case n > m.Config.Size:
		return nil, fmt.Errorf("image config %s exceeds its declared size of %d bytes", m.Config.Digest, m.Config.Size)
	case n < m.Config.Size:
		return nil, fmt.Errorf("image config %s contains %d bytes, manifest declares %d", m.Config.Digest, n, m.Config.Size)
	}
	return raw, nil
}

func (img layoutImage) ConfigFile() (*v1.ConfigFile, error) {
	return verifiedConfig(img)
}
