package scancmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/source"
)

// Main QA of 672fe7a (2026-11-13): etc/debian_version is consulted on a
// Debian image only -- not read, not charged to the read budget, not
// link-followed anywhere else. Held with the per-file limit lowered to
// 4 KiB: a 4,097-byte file of that name on an Alpine image had failed the
// scan before its packages were read; on a Debian image the same file is
// read, and so still fails (the control that shows the path is consulted
// there), while an ordinary one spells the point release.
func TestCatalogFromImage_DebianVersionIsConsultedOnDebianOnly(t *testing.T) {
	lowerLimit(t, &source.MaxFileBytes, 4096)
	big := strings.Repeat("Q", 4097)
	for _, tc := range []struct {
		name           string
		files          map[string]string
		wantErr        bool
		wantPackages   int
		wantPointRel   string
		wantPURLDistro string
	}{
		{"alpine, no debian_version", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: p4ApkPatched}, false, 1, "", "alpine-3.19.9"},
		{"alpine, an over-limit unrelated file", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: p4ApkPatched, "etc/unrelated-release": big}, false, 1, "", "alpine-3.19.9"},
		{"alpine, an over-limit debian_version is not read", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: p4ApkPatched, debianVersionPath: big}, false, 1, "", "alpine-3.19.9"},
		{"alpine, an ordinary debian_version is not read", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: p4ApkPatched, debianVersionPath: "12.11\n"}, false, 1, "", "alpine-3.19.9"},
		{"debian, an over-limit debian_version is read and refused", map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc, debianVersionPath: big}, true, 0, "", ""},
		{"debian, an ordinary debian_version spells the point release", map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc, debianVersionPath: "12.11\n"}, false, 3, "12.11", "debian-12.11"},
		{"debian, no debian_version spells the major", map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc}, false, 3, "", "debian-12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := &source.Image{Layers: []source.Layer{imageLayer(t, "sha256:fixture", tc.files)}}
			target, _, _, err := catalogFromImage(context.Background(), "test-image", img)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if !strings.Contains(err.Error(), debianVersionPath) {
					t.Fatalf("err = %v, want it to name %s", err, debianVersionPath)
				}
				return
			}
			if len(target.Packages) != tc.wantPackages {
				t.Fatalf("%d packages, want %d", len(target.Packages), tc.wantPackages)
			}
			if target.Distro == nil || target.Distro.PointRelease != tc.wantPointRel {
				t.Fatalf("distro = %+v, want point release %q", target.Distro, tc.wantPointRel)
			}
			if !strings.Contains(target.Packages[0].PURL, "distro="+tc.wantPURLDistro) {
				t.Fatalf("purl = %s, want distro=%s", target.Packages[0].PURL, tc.wantPURLDistro)
			}
		})
	}
}

// The cost side of the same rule, counted in layer opens (every Files pass
// opens every layer once, D123): on an Alpine image a debian_version --
// absent, an ordinary file or a symlink -- opens no layer more than an
// unrelated symlink does. On a Debian image the point release costs one
// more pass, documented here as the number it is.
func TestCatalogFromImage_DebianVersionCostsANonDebianImageNoLayerOpen(t *testing.T) {
	opens := func(t *testing.T, base []p4Entry, extra ...p4Entry) int {
		t.Helper()
		raw := p4Tar(t, append(append([]p4Entry{}, base...), extra...)...)
		count := 0
		l := source.Layer{DiffID: "sha256:test", Open: func() (io.ReadCloser, error) { count++; return io.NopCloser(bytes.NewReader(raw)), nil }}
		if _, _, _, err := catalogFromImage(context.Background(), "test", &source.Image{Layers: []source.Layer{l}}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	alpine := []p4Entry{{name: osReleasePath, body: osReleaseAlpine319}, {name: apkDBPath, body: p4ApkPatched}, {name: "etc/shared_version", body: "12.8\n"}}
	baseline := opens(t, alpine)
	for _, tc := range []struct {
		name  string
		extra []p4Entry
	}{
		{"an unrelated symlink", []p4Entry{{name: "etc/local_version", link: "shared_version"}}},
		{"an ordinary debian_version", []p4Entry{{name: debianVersionPath, body: "12.8\n"}}},
		{"a debian_version symlink", []p4Entry{{name: debianVersionPath, link: "shared_version"}}},
		{"a debian_version symlink chain", []p4Entry{{name: debianVersionPath, link: "local_version"}, {name: "etc/local_version", link: "shared_version"}}},
	} {
		if got := opens(t, alpine, tc.extra...); got != baseline {
			t.Errorf("alpine with %s: %d layer opens, want the baseline %d (the path is not consulted)", tc.name, got, baseline)
		}
	}
	debian := []p4Entry{{name: osReleasePath, body: osReleaseDebian12Bookworm}, {name: dpkgDBPath, body: dpkgOpensslAndGlibc}}
	if without, with := opens(t, debian), opens(t, debian, p4Entry{name: debianVersionPath, body: "12.11\n"}); with != without {
		// Whether or not the file exists the pass is made: the cost is the
		// image's being Debian, not the file's being there.
		t.Errorf("debian: %d opens with debian_version, %d without; want the same count (one pass either way)", with, without)
	}
}
