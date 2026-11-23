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
		prefix := [][]byte{manifestHeader, manifest, archivePadding(len(manifest)),
			configHeader, config, archivePadding(len(config))}
		reader := &archivePrefixReader{file: file, prefix: prefix}
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

func archivePadding(size int) []byte {
	return make([]byte, (512-size%512)%512)
}

// Match the library's clean-path match and relative link resolution.
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

// findArchiveMetadata reads the one member called name. Two are refused, not
// resolved: go-containerregistry takes the first, moby and containerd unpack
// the archive and so take the last, and no archive a tool writes has both --
// one tarball scanned as one image and loaded as another (QA 2026-11-20).
// Layers need no such rule: their content is held to the config's diff ids.
func findArchiveMetadata(reader io.Reader, name string, limit int64) ([]byte, string, error) {
	archive := tar.NewReader(reader)
	found := false
	var data []byte
	link := ""
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			if !found {
				return nil, "", fmt.Errorf("file %s not found in tar", name)
			}
			return data, link, nil
		}
		if err != nil {
			return nil, "", err
		}
		if path.Clean(header.Name) != path.Clean(name) {
			continue
		}
		if found {
			return nil, "", fmt.Errorf("docker archive holds more than one member named %s; readers disagree on which is the image", path.Clean(name))
		}
		found = true
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			link = path.Join(filepath.Dir(name), path.Clean(header.Linkname))
			continue
		}
		if header.Size > limit {
			return nil, "", fmt.Errorf("archive metadata %s declares %d bytes, past the %s limit (D112)", name, header.Size, formatBytes(limit))
		}
		data, err = io.ReadAll(io.LimitReader(archive, limit+1))
		if err != nil {
			return nil, "", err
		}
		if int64(len(data)) > limit {
			return nil, "", fmt.Errorf("archive metadata %s exceeds the %s limit (D112)", name, formatBytes(limit))
		}
	}
}

// Both reading and seeking check cancellation. tar.Reader seeks over the
// payload of unwanted entries, then reads the final byte to detect truncation.
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

func (reader *archiveContextReader) Seek(offset int64, whence int) (int64, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	seeker, ok := reader.Reader.(io.Seeker)
	if !ok {
		return 0, errors.New("archive reader does not support seeking")
	}
	return seeker.Seek(offset, whence)
}

// Present the captured metadata followed by the original archive as one
// seekable file. Without this, each layer lookup would reread all preceding
// layers. The small prefix slices share the already-bounded metadata bytes.
type archivePrefixReader struct {
	file   io.ReadCloser
	prefix [][]byte
	pos    int64
}

func (r *archivePrefixReader) Read(buf []byte) (int, error) {
	offset := r.pos
	for _, part := range r.prefix {
		if offset < int64(len(part)) {
			n := copy(buf, part[offset:])
			r.pos += int64(n)
			return n, nil
		}
		offset -= int64(len(part))
	}
	n, err := r.file.Read(buf)
	r.pos += int64(n)
	return n, err
}

func (r *archivePrefixReader) Seek(offset int64, whence int) (int64, error) {
	seeker, ok := r.file.(io.Seeker)
	if !ok {
		return 0, errors.New("archive file does not support seeking")
	}
	var prefixSize int64
	for _, part := range r.prefix {
		prefixSize += int64(len(part))
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.pos
	case io.SeekEnd:
		end, err := seeker.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, err
		}
		// Restore the backing position if the requested offset is invalid.
		if _, err := seeker.Seek(max(0, r.pos-prefixSize), io.SeekStart); err != nil {
			return 0, err
		}
		offset += prefixSize + end
	default:
		return 0, errors.New("invalid archive seek origin")
	}
	if offset < 0 {
		return 0, errors.New("negative archive seek position")
	}
	if _, err := seeker.Seek(max(0, offset-prefixSize), io.SeekStart); err != nil {
		return 0, err
	}
	r.pos = offset
	return r.pos, nil
}
