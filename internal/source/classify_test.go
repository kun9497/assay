package source

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeZip builds a minimal zip archive from name -> content pairs and writes
// it to path, for classify_test.go's own jar-sniffing fixtures. Never a
// committed binary fixture (CLAUDE.md) — built in-test with archive/zip.
func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// The prefixes are the escape hatch from the sniff, so they must win outright
// — including when the sniff would have said something else, which is the only
// situation in which a user reaches for one.
func TestClassify_ExplicitPrefixesOverrideTheContent(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		in       string
		wantKind TargetKind
		wantPath string
	}{
		{"sbom:" + sbom, TargetSBOM, sbom},
		{"dir:" + dir, TargetDirectory, dir},
		// file: on a document the sniff would have called an SBOM. If the
		// prefix did not win, this row would return TargetSBOM.
		{"file:" + sbom, TargetGoBinary, sbom},
		// jar: on that same document. If the prefix did not win, this row
		// would return TargetSBOM too — the sniff never even runs.
		{"jar:" + sbom, TargetJar, sbom},
		// A prefix on a path that does not exist is still that kind. The
		// error the caller then reports is "cannot open", which is true,
		// rather than "not a recognised target", which is not.
		{"dir:/does/not/exist", TargetDirectory, "/does/not/exist"},
		{"file:/does/not/exist", TargetGoBinary, "/does/not/exist"},
		{"sbom:/does/not/exist", TargetSBOM, "/does/not/exist"},
		{"jar:/does/not/exist", TargetJar, "/does/not/exist"},
	} {
		gotKind, gotPath, err := Classify(tt.in)
		if err != nil {
			t.Errorf("Classify(%q): %v", tt.in, err)
			continue
		}
		if gotKind != tt.wantKind {
			t.Errorf("Classify(%q) kind = %v, want %v", tt.in, gotKind, tt.wantKind)
		}
		if gotPath != tt.wantPath {
			t.Errorf("Classify(%q) path = %q, want %q", tt.in, gotPath, tt.wantPath)
		}
	}
}

// Image prefixes keep their prefix, because source.Open re-parses it.
// Stripping one here would send an oci-dir: layout down the registry path.
func TestClassify_ImagePrefixesAreLeftIntact(t *testing.T) {
	for _, in := range []string{"docker-archive:/tmp/x.tar", "oci-dir:/tmp/layout"} {
		kind, path, err := Classify(in)
		if err != nil {
			t.Errorf("Classify(%q): %v", in, err)
			continue
		}
		if kind != TargetImage {
			t.Errorf("Classify(%q) kind = %v, want image", in, kind)
		}
		if path != in {
			t.Errorf("Classify(%q) path = %q, want it unchanged", in, path)
		}
	}
}

// A bare path is decided by content, in a fixed order.
//
// The Go-binary fixture is this test binary itself: os.Executable() is a real
// binary with real build info, so the case cannot pass against a sniff that
// says yes to everything — a hand-written fixture could.
func TestClassify_BarePathsAreSniffed(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.cdx.json")
	if err := os.WriteFile(sbom,
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	spdxDoc := filepath.Join(dir, "s.spdx.json")
	if err := os.WriteFile(spdxDoc,
		[]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	// Recognized by name suffix alone (the common case: a real jar always
	// carries META-INF/, but the suffix check is cheap and tried first).
	byName := filepath.Join(dir, "app.jar")
	writeZip(t, byName, map[string]string{"com/example/Main.class": "not real bytecode"})
	// No .jar/.war suffix at all, recognized only by the META-INF/ entry
	// inside it — the fallback the suffix check exists beside.
	byContent := filepath.Join(dir, "app.bin")
	writeZip(t, byContent, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})

	for _, tt := range []struct {
		name string
		in   string
		want TargetKind
	}{
		{"a Go binary", self, TargetGoBinary},
		{"a CycloneDX document", sbom, TargetSBOM},
		{"an SPDX document", spdxDoc, TargetSBOM},
		{"a directory", dir, TargetDirectory},
		{"a jar recognized by its .jar name", byName, TargetJar},
		{"a jar recognized by its META-INF/ content", byContent, TargetJar},
		// Not a path at all: the pre-existing behaviour, unchanged.
		{"a registry reference", "alpine:3.19", TargetImage},
		{"a registry reference with a port", "registry.example.com:5000/team/app", TargetImage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, gotPath, err := Classify(tt.in)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.in, got, tt.want)
			}
			if gotPath != tt.in {
				t.Errorf("Classify(%q) path = %q, want it unchanged", tt.in, gotPath)
			}
		})
	}
}

// A Go binary must be recognised before the CycloneDX test runs, not after.
// Order is the whole of D22's sniff: a file cannot be both, but a test that
// only ever sees one kind at a time cannot tell whether the order is right.
// This pins it by asserting the binary case specifically — the one that used
// to be classified as an SBOM.
func TestClassify_AGoBinaryIsNotAnSBOM(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Classify(self)
	if err != nil {
		t.Fatal(err)
	}
	if got == TargetSBOM {
		t.Fatal("a Go binary classified as an SBOM - the CycloneDX parser will " +
			"report a malformed document for a file that was never JSON")
	}
	if got != TargetGoBinary {
		t.Errorf("Classify(self) = %v, want go-binary", got)
	}
}

// A file that exists and is none of the three is an error naming all three,
// not a silent fallthrough to whichever branch is last. Falling through to
// SBOM is what happened before D22, and it reported a malformed JSON document
// for a file that was never meant to be one.
func TestClassify_AnUnrecognisedFileIsAnErrorNamingWhatWasTried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystery.bin")
	if err := os.WriteFile(path, []byte("not a go binary, not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kind, _, err := Classify(path)
	if err == nil {
		t.Fatalf("Classify of an unrecognised file succeeded as %v", kind)
	}
	// The message has to name what was tried AND how to override, because
	// those are the user's two next questions.
	for _, want := range []string{"Go binary", "CycloneDX", "SPDX", "jar", "sbom:", "file:", "dir:", "jar:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q - the user cannot tell what to do next", err, want)
		}
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file", err)
	}
}

// A plain zip — the magic bytes without either signal jar scanning actually
// needs — is none of the four kinds and must reach the same loud error, not
// be misclassified as a component inventory just because it happens to share
// jar's container format.
func TestClassify_APlainZipIsNotAJar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.zip")
	writeZip(t, path, map[string]string{"readme.txt": "not a jar"})

	kind, _, err := Classify(path)
	if err == nil {
		t.Fatalf("Classify(plain zip) = %v, want an error - it names neither "+
			".jar/.war nor META-INF/", kind)
	}
}

// An empty file is a real case — a truncated download, an interrupted build —
// and it is none of the three. It must reach the same loud error rather than
// tripping a length check somewhere and being called an SBOM.
func TestClassify_AnEmptyFileIsUnrecognised(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if kind, _, err := Classify(path); err == nil {
		t.Errorf("Classify(empty file) = %v, want an error", kind)
	}
}

// JSON member order is arbitrary, so a valid CycloneDX document can put
// bomFormat past any fixed prefix. An 880-byte 1.6 document leading with a
// metadata block did exactly that and was rejected as "not a CycloneDX
// document" - a regression against the pre-sniff behaviour, where every
// existing file went to the order-independent parser.
func TestClassify_ACycloneDXDocumentWithALateBomFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "late.cdx.json")
	// Padding pushes bomFormat well past the 512-byte fast path.
	pad := strings.Repeat("x", 900)
	body := `{"metadata":{"tools":[{"vendor":"` + pad + `","name":"syft"}]},` +
		`"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := Classify(p)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != TargetSBOM {
		t.Errorf("Classify = %v, want sbom", got)
	}
}

// The SPDX analogue of the late-bomFormat test above: LooksLikeSPDX needs the
// identical order-independent fallback, since SPDX's own top-level key order
// is exactly as arbitrary as CycloneDX's.
func TestClassify_AnSPDXDocumentWithALateSpdxVersion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "late.spdx.json")
	pad := strings.Repeat("x", 900)
	body := `{"SPDXID":"SPDXRef-DOCUMENT","name":"` + pad + `",` +
		`"spdxVersion":"SPDX-2.3","packages":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := Classify(p)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != TargetSBOM {
		t.Errorf("Classify = %v, want sbom", got)
	}
}

// ...but the marker has to be a top-level KEY. A document whose only
// occurrence of the word is a value, or a nested property name - and
// CycloneDX property names come from whatever tool wrote the file - is not an
// SBOM, and calling it one sends a stranger's document to the wrong parser.
func TestClassify_BomFormatMustBeATopLevelKey(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct{ name, body string }{
		{"as a value", `{"note":"bomFormat","x":1}`},
		{"nested one level down", `{"metadata":{"bomFormat":"CycloneDX"}}`},
		{"as a property name inside an array", `{"a":[{"properties":[{"name":"bomFormat"}]}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".json")
			// The padding keeps the fast prefix scan from seeing it, so this
			// exercises the streaming fallback rather than the shortcut.
			body := `{"pad":"` + strings.Repeat("y", 900) + `",` + tt.body[1:]
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _, err := Classify(p); err == nil {
				t.Errorf("Classify(%s) = %v, want an error - the marker is not a top-level key",
					tt.name, got)
			}
		})
	}
}

// A truncated or non-object document must not hang or panic the fallback.
func TestClassify_MalformedJSONIsNotAnSBOM(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct{ name, body string }{
		{"truncated object", `{"pad":"` + strings.Repeat("z", 900) + `","a":`},
		{"a bare array", `[` + strings.Repeat(`"x",`, 300) + `"y"]`},
		{"not json at all", strings.Repeat("q", 900)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".json")
			if err := os.WriteFile(p, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _, err := Classify(p); err == nil {
				t.Errorf("Classify(%s) = %v, want an error", tt.name, got)
			}
		})
	}
}

// The kind is printed in the scan's own output so a wrong guess is visible
// rather than inferred from a confusing downstream error, which makes these
// names contract.
func TestTargetKindString(t *testing.T) {
	for k, want := range map[TargetKind]string{
		TargetImage:     "image",
		TargetSBOM:      "sbom",
		TargetDirectory: "directory",
		TargetGoBinary:  "go-binary",
		TargetJar:       "jar",
	} {
		if got := k.String(); got != want {
			t.Errorf("TargetKind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
	// A kind from outside the set must be visibly wrong rather than blank:
	// an empty kind in "scanned X as a " reads as a rendering bug, not as an
	// unknown classification.
	if got := TargetKind(99).String(); !strings.Contains(got, "99") {
		t.Errorf("TargetKind(99).String() = %q, want something naming the value", got)
	}
}
