package source

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// D160: FilesProbed is the image probes' one pass over several roots, with
// the header in the match and a sniff on the first four bytes.

func isELFTest(_ string, head []byte) bool {
	return len(head) == 4 && string(head) == "\x7fELF"
}

func probeMatch(name string, h *tar.Header) bool {
	switch h.Typeflag {
	case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
	default:
		return false
	}
	return h.Mode&0o111 != 0 && h.Size >= 16
}

// modeLayer is layerOf with a mode per entry.
func modeLayer(t *testing.T, diffID string, files map[string]string, modes map[string]int64) Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range sortedNames(files) {
		mode := int64(0o644)
		if m, ok := modes[n]; ok {
			mode = m
		}
		body := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	return Layer{DiffID: diffID, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }}
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func elfBody(tail string) string { return "\x7fELF" + tail }

// One pass for every root: the layer is opened once however many roots are
// probed, and files from each root come back together.
func TestFilesProbed_SeveralRootsInOnePass(t *testing.T) {
	opens := 0
	inner := modeLayer(t, "sha256:one", map[string]string{
		"usr/bin/tool":                        elfBody(strings.Repeat("x", 64)),
		"usr/local/bin/other":                 elfBody(strings.Repeat("y", 64)),
		"usr/lib/node_modules/a/package.json": `{"name":"a"}`,
		"etc/passwd":                          "root:x:0:0",
	}, map[string]int64{"usr/bin/tool": 0o755, "usr/local/bin/other": 0o755})
	counted := Layer{DiffID: inner.DiffID, Open: func() (io.ReadCloser, error) { opens++; return inner.Open() }}
	img := imageOf(counted)

	got, _, err := img.FilesProbed(context.Background(), []string{"usr/bin", "usr/local/bin", "usr/lib/node_modules"},
		func(name string, h *tar.Header) bool {
			if strings.HasSuffix(name, "/package.json") {
				return true
			}
			return probeMatch(name, h)
		},
		func(name string, head []byte) bool {
			return strings.HasSuffix(name, "/package.json") || isELFTest(name, head)
		})
	if err != nil {
		t.Fatal(err)
	}
	if opens != 1 {
		t.Errorf("layer opened %d times, want 1: the roots share one pass", opens)
	}
	if g := namesOf(got); len(g) != 3 || g[0] != "usr/bin/tool" || g[1] != "usr/lib/node_modules/a/package.json" || g[2] != "usr/local/bin/other" {
		t.Errorf("FilesProbed = %v, want the two executables and the package.json", g)
	}
	if got["usr/bin/tool"].DiffID != "sha256:one" {
		t.Errorf("DiffID = %q, want the layer", got["usr/bin/tool"].DiffID)
	}
}

// The sniff declines a non-ELF executable: it is not returned, its bytes are
// not charged to the per-scan budget, and it still shadows a lower layer's
// file at the same name (A10).
func TestFilesProbed_SniffDeclinesWithoutReading(t *testing.T) {
	script := "#!/bin/sh\n" + strings.Repeat("echo hi\n", 200)
	img := imageOf(
		modeLayer(t, "sha256:base", map[string]string{"usr/bin/tool": elfBody(strings.Repeat("o", 64))}, map[string]int64{"usr/bin/tool": 0o755}),
		modeLayer(t, "sha256:top", map[string]string{"usr/bin/tool": script, "usr/bin/keep": elfBody(strings.Repeat("k", 64))},
			map[string]int64{"usr/bin/tool": 0o755, "usr/bin/keep": 0o755}),
	)
	got, _, err := img.FilesProbed(context.Background(), []string{"usr/bin"}, probeMatch, isELFTest)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["usr/bin/tool"]; ok {
		t.Error("usr/bin/tool was returned: the newer layer's shell script shadows the ELF below, and a script is not wanted")
	}
	if f, ok := got["usr/bin/keep"]; !ok || f.DiffID != "sha256:top" {
		t.Errorf("usr/bin/keep = %+v (present %v), want the top layer's ELF", f, ok)
	}
	if want := int64(len(elfBody(strings.Repeat("k", 64)))); img.read != want {
		t.Errorf("bytes charged = %d, want %d: only the accepted ELF counts, the declined script's %d bytes do not", img.read, want, len(script))
	}
}

// A regular file without the execute bit, or below the caller's size floor,
// never reaches the sniff; a symlink is neither followed nor returned.
func TestFilesProbed_MatchSeesTheHeader(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "usr/bin/plain", body: elfBody(strings.Repeat("p", 64))}, // mode 0644
		entry{name: "usr/bin/link", link: "tool"},
	))
	sniffed := 0
	got, links, err := img.FilesProbed(context.Background(), []string{"usr/bin"}, probeMatch, func(name string, head []byte) bool { sniffed++; return true })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || sniffed != 0 {
		t.Errorf("FilesProbed = %v with %d sniffs, want nothing and no sniff: a 0644 file never matched", namesOf(got), sniffed)
	}
	if links != 0 {
		t.Errorf("links = %d, want 0: a link the match rejects is not counted as a file the probe failed to read", links)
	}
}

func TestFilesProbed_RefusesTheRootAndNilHooks(t *testing.T) {
	img := imageOf(layerOf(t, "sha256:one", map[string]string{"usr/bin/x": "x"}))
	if _, _, err := img.FilesProbed(context.Background(), []string{""}, probeMatch, isELFTest); err == nil {
		t.Error("an empty root was accepted")
	}
	if _, _, err := img.FilesProbed(context.Background(), nil, probeMatch, isELFTest); err == nil {
		t.Error("no roots were accepted")
	}
	if _, _, err := img.FilesProbed(context.Background(), []string{"usr/bin"}, nil, isELFTest); err == nil {
		t.Error("a nil match was accepted")
	}
	if _, _, err := img.FilesProbed(context.Background(), []string{"usr/bin"}, probeMatch, nil); err == nil {
		t.Error("a nil sniff was accepted")
	}
}

// A10 holds for every root in the pass, not only the first: a lower layer's
// file at usr/local/bin/x is shadowed when an upper layer makes x a directory,
// exactly as it would be in a single-root collect of usr/local/bin.
func TestFilesProbed_AncestorShadowingHoldsForEveryRoot(t *testing.T) {
	img := imageOf(
		modeLayer(t, "sha256:base", map[string]string{"usr/local/bin/x": elfBody(strings.Repeat("b", 64))}, map[string]int64{"usr/local/bin/x": 0o755}),
		modeLayer(t, "sha256:top", map[string]string{"usr/local/bin/x/inner": "now a directory"}, nil),
	)
	got, _, err := img.FilesProbed(context.Background(), []string{"usr/bin", "usr/local/bin"}, probeMatch, isELFTest)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["usr/local/bin/x"]; ok {
		t.Error("usr/local/bin/x was returned: the upper layer made it a directory, so the lower file is not what the image ships (A10) -- the second root's ancestors were not shadowed")
	}
}
