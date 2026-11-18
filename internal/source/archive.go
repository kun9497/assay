package source

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Match the registry library's manifest limit. Configs use MaxConfigBytes.
const maxArchiveManifestBytes int64 = 100 << 20

func openDockerArchive(ctx context.Context, filename string) (v1.Image, error) {
	opener, err := dockerArchiveOpener(ctx, func() (io.ReadCloser, error) {
		return os.Open(filename)
	})
	if err != nil {
		return nil, err
	}
	return tarball.Image(opener, nil)
}

// The library reads config entries whole and reopens the archive for each
// lookup. Capture both metadata files under limits, then prefix every open
// with those exact bytes. A changed archive cannot replace them after the
// check. Layer contents still stream from the archive and undergo diff-ID
// verification through the existing image reader.
func dockerArchiveOpener(ctx context.Context, open tarball.Opener) (tarball.Opener, error) {
	manifest, err := readArchiveMetadata(ctx, open, "manifest.json", maxArchiveManifestBytes)
	if err != nil {
		return nil, err
	}
	var descriptors tarball.Manifest
	if err := json.NewDecoder(bytes.NewReader(manifest)).Decode(&descriptors); err != nil {
		return nil, fmt.Errorf("read archive manifest: %w", err)
	}
	if len(descriptors) != 1 {
		return nil, fmt.Errorf("docker archive must contain exactly one image, found %d", len(descriptors))
	}
	configPath := descriptors[0].Config
	config, err := readArchiveMetadata(ctx, open, configPath, MaxConfigBytes)
	if err != nil {
		return nil, err
	}
	cf, err := v1.ParseConfigFile(bytes.NewReader(config))
	if err != nil {
		return nil, fmt.Errorf("read archive config: %w", err)
	}
	// An inconsistent count can panic in the library's uncompressed-layer
	// lookup before fromV1 gets a chance to check it.
	if len(cf.RootFS.DiffIDs) != len(descriptors[0].Layers) {
		return nil, fmt.Errorf("image config lists %d diff ids for %d layers, so its layers cannot be verified (D123)",
			len(cf.RootFS.DiffIDs), len(descriptors[0].Layers))
	}
	manifestHeader, err := archiveMetadataHeader("manifest.json", manifest)
	if err != nil {
		return nil, err
	}
	configHeader, err := archiveMetadataHeader(path.Clean(configPath), config)
	if err != nil {
		return nil, err
	}
	return func() (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := open()
		if err != nil {
			return nil, err
		}
		// No end-of-archive blocks between the captured entries and the
		// original archive. Share their backing bytes across layer opens.
		reader := io.MultiReader(
			bytes.NewReader(manifestHeader), bytes.NewReader(manifest), archivePadding(len(manifest)),
			bytes.NewReader(configHeader), bytes.NewReader(config), archivePadding(len(config)),
			file,
		)
		return &archiveContextReader{ctx: ctx, Reader: reader, Closer: file}, nil
	}, nil
}

func archiveMetadataHeader(name string, data []byte) ([]byte, error) {
	var header bytes.Buffer
	writer := tar.NewWriter(&header)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
		return nil, err
	}
	return header.Bytes(), nil
}

func archivePadding(size int) io.Reader {
	return bytes.NewReader(make([]byte, (512-size%512)%512))
}

// Match the library's first clean-path match and relative link resolution.
// Iteration bounds link depth and closes each file before following a link.
func readArchiveMetadata(ctx context.Context, open tarball.Opener, name string, limit int64) ([]byte, error) {
	visited := make(map[string]bool)
	for hops := 0; hops <= maxSymlinks; hops++ {
		clean := path.Clean(name)
		if visited[clean] {
			return nil, fmt.Errorf("archive metadata link cycle at %s", name)
		}
		visited[clean] = true
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := open()
		if err != nil {
			return nil, err
		}
		body, link, err := findArchiveMetadata(&archiveContextReader{ctx: ctx, Reader: file, Closer: file}, name, limit)
		file.Close()
		if err != nil {
			return nil, err
		}
		if link == "" {
			return body, nil
		}
		name = link
	}
	return nil, fmt.Errorf("archive metadata exceeds %d link hops at %s", maxSymlinks, name)
}

func findArchiveMetadata(reader io.Reader, name string, limit int64) ([]byte, string, error) {
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return nil, "", fmt.Errorf("file %s not found in tar", name)
		}
		if err != nil {
			return nil, "", err
		}
		if path.Clean(header.Name) != path.Clean(name) {
			continue
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return nil, path.Join(filepath.Dir(name), path.Clean(header.Linkname)), nil
		}
		if header.Size > limit {
			return nil, "", fmt.Errorf("archive metadata %s declares %d bytes, past the %s limit (D112)", name, header.Size, formatBytes(limit))
		}
		data, err := io.ReadAll(io.LimitReader(archive, limit+1))
		if err != nil {
			return nil, "", err
		}
		if int64(len(data)) > limit {
			return nil, "", fmt.Errorf("archive metadata %s exceeds the %s limit (D112)", name, formatBytes(limit))
		}
		return data, "", nil
	}
}

// Do not expose the file's Seek or WriterTo: tar's skip path must also check
// cancellation, including while looking past a large preceding layer.
type archiveContextReader struct {
	ctx context.Context
	io.Reader
	io.Closer
}

func (reader *archiveContextReader) Read(buf []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(buf)
}
