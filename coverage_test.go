package oci

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// ----- failing fs.FS for TarballFS error paths -----

type failFS struct {
	readDirErr error
	openErr    error
}

func (f failFS) Open(name string) (fs.File, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (f failFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.readDirErr != nil {
		return nil, f.readDirErr
	}
	return []fs.DirEntry{stubDirEntry{name: "image.tar"}}, nil
}

type stubDirEntry struct{ name string }

func (s stubDirEntry) Name() string               { return s.name }
func (s stubDirEntry) IsDir() bool                { return false }
func (s stubDirEntry) Type() fs.FileMode          { return 0 }
func (s stubDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestTarballFSReadDirError(t *testing.T) {
	if _, err := TarballFS(failFS{readDirErr: errors.New("readdir boom")}); err == nil {
		t.Fatal("expected ReadDir error")
	}
}

func TestTarballFSOpenError(t *testing.T) {
	if _, err := TarballFS(failFS{openErr: errors.New("open boom")}); err == nil {
		t.Fatal("expected Open error")
	}
}

// ----- tarballFromReader: skip non-regular member + ReadAll error -----

func TestTarballFromReaderSkipsNonRegular(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "adir/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "alink", Typeflag: tar.TypeSymlink, Linkname: "x"})
	body := []byte("hi")
	_ = tw.WriteHeader(&tar.Header{Name: "afile", Typeflag: tar.TypeReg, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	src, err := tarballFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	// "afile" indexed by sha256; dir/symlink skipped.
	if _, err := src.Blob(digestOf(body)); err != nil {
		t.Fatalf("afile blob: %v", err)
	}
}

// errReader returns an error partway through, after producing a valid tar
// header so tar.Reader.Next succeeds but the body read fails.
type errReader struct {
	data []byte
	off  int
	fail int
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.off >= e.fail {
		return 0, errors.New("synthetic read failure")
	}
	n := copy(p, e.data[e.off:e.fail])
	e.off += n
	return n, nil
}

func TestTarballFromReaderMemberReadError(t *testing.T) {
	// Build a tar whose first member header is intact but whose body read
	// fails, by truncating the underlying stream mid-body.
	body := bytes.Repeat([]byte("z"), 4096)
	full := buildTar(t, []tentry{{name: "big", typeflag: tar.TypeReg, mode: 0o644, body: body}})
	// 512 header + partial body; fail before body completes.
	r := &errReader{data: full, fail: 512 + 100}
	if _, err := tarballFromReader(r); err == nil {
		t.Fatal("expected member read error")
	}
}

func TestTarballFromReaderHeaderError(t *testing.T) {
	// Garbage that yields a tar header read error (not clean EOF).
	r := &errReader{data: bytes.Repeat([]byte("x"), 600), fail: 600}
	// Reading header from this errReader fails -> archive read error.
	if _, err := tarballFromReader(r); err == nil {
		t.Fatal("expected header read error")
	}
}

// ----- memFS.ReadDir dedup branch -----

func TestMemFSReadDirDedup(t *testing.T) {
	m := &memFS{files: map[string][]byte{
		"d/a": []byte("a"),
		"d/b": []byte("b"), // same top "d" -> exercises the seen dedup
		"top": []byte("t"),
	}}
	entries, err := m.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	if !names["d"] || !names["top"] || len(names) != 2 {
		t.Fatalf("dedup failed: %v", names)
	}
}

// ----- applyLayerBlob error branches -----

func TestApplyLayerBlobErrors(t *testing.T) {
	ov := newOverlay()

	// Blob fetch error.
	if err := applyLayerBlob(ov, bareSource{}, descriptor{Digest: "sha256:" + hex.EncodeToString(make([]byte, 32)), MediaType: MediaTypeLayerTar}); err == nil {
		t.Fatal("expected blob error")
	}

	// Read error on the blob body.
	if err := applyLayerBlob(ov, readErrSource{}, descriptor{Digest: "sha256:" + hex.EncodeToString(make([]byte, 32)), MediaType: MediaTypeLayerTar}); err == nil {
		t.Fatal("expected read error")
	}

	// Digest mismatch on the layer.
	bad := bytesSource{data: []byte("not the right content")}
	if err := applyLayerBlob(ov, bad, descriptor{Digest: digestOf([]byte("different")), MediaType: MediaTypeLayerTar}); err == nil {
		t.Fatal("expected digest mismatch")
	}
}

type readErrSource struct{}

func (readErrSource) Blob(string) (io.ReadCloser, error) {
	return io.NopCloser(&errReader{data: []byte("abc"), fail: 0}), nil
}

type bytesSource struct{ data []byte }

func (b bytesSource) Blob(string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

// ----- Selector OS and Variant mismatch -----

func TestSelectorMismatchBranches(t *testing.T) {
	d := descriptor{Platform: &platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}
	if (Selector{OS: "windows"}).matches(d) {
		t.Fatal("OS mismatch should not match")
	}
	if (Selector{Variant: "v7"}).matches(d) {
		t.Fatal("Variant mismatch should not match")
	}
	if !(Selector{OS: "linux", Architecture: "arm64", Variant: "v8"}).matches(d) {
		t.Fatal("exact match should match")
	}
}

// ----- resolveManifest ReadAll error on top blob -----

func TestResolveManifestReadError(t *testing.T) {
	_, err := resolveManifest(readErrSource{}, descriptor{Digest: digestOf([]byte("x")), MediaType: MediaTypeImageManifest}, Selector{})
	if err == nil {
		t.Fatal("expected read error")
	}
}

// ----- OpenDescriptor layer-apply error -----

func TestOpenDescriptorLayerError(t *testing.T) {
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	_ = os.MkdirAll(blobsDir, 0o755)
	put := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		_ = os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644)
		return d
	}
	// Manifest references a layer blob that does not exist on disk.
	m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
		Config: descriptor{Digest: put([]byte(`{}`))},
		Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: "sha256:" + hex.EncodeToString(make([]byte, 32))}}}
	mb, _ := json.Marshal(m)
	md := put(mb)
	if _, err := OpenDescriptor(OCILayout(dir), descriptor{Digest: md}, Selector{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected layer not-found, got %v", err)
	}
}

// ----- topDescriptor archive index.json read error -----

type idxReadErrFile struct{}

func (idxReadErrFile) Stat() (fs.FileInfo, error) { return memFileInfo{name: "index.json"}, nil }
func (idxReadErrFile) Read([]byte) (int, error)   { return 0, errors.New("index read boom") }
func (idxReadErrFile) Close() error               { return nil }

type idxErrFS struct{ *memFS }

func (f idxErrFS) Open(name string) (fs.File, error) {
	if name == "index.json" {
		return idxReadErrFile{}, nil
	}
	return f.memFS.Open(name)
}

func TestTopDescriptorArchiveIndexReadError(t *testing.T) {
	tb := &tarball{fsys: idxErrFS{memFS: &memFS{files: map[string][]byte{"index.json": nil}}}, blobs: map[string]string{}}
	if _, err := tb.topDescriptor(); err == nil {
		t.Fatal("expected index read error")
	}
}

// ----- OCILayout.Blob non-NotExist (ENOTDIR) error -----

func TestOCILayoutBlobNotDir(t *testing.T) {
	dir := t.TempDir()
	// Make "blobs/sha256" a regular FILE so descending into it yields ENOTDIR.
	_ = os.MkdirAll(filepath.Join(dir, "blobs"), 0o755)
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := OCILayout(dir).Blob("sha256:" + hex.EncodeToString(make([]byte, 32)))
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected non-NotExist (ENOTDIR) error, got %v", err)
	}
}

// ----- Selector with platform set but descriptor has no Platform -----

func TestSelectorNoPlatformOnDescriptor(t *testing.T) {
	d := descriptor{} // Platform == nil
	if (Selector{Architecture: "arm64"}).matches(d) {
		t.Fatal("platformed selector must not match platformless descriptor")
	}
}

// ----- malformed index JSON when media type is already known as index -----

func TestMalformedIndexWithKnownMediaType(t *testing.T) {
	// Top descriptor declares an index media type but the blob is not valid
	// index JSON (it is a bare number) -> json.Unmarshal into index fails.
	src := bytesSource{data: []byte("123")}
	_, err := resolveManifest(src, descriptor{Digest: digestOf([]byte("123")), MediaType: MediaTypeImageIndex}, Selector{})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("parsing index")) {
		t.Fatalf("want index parse error, got %v", err)
	}
}

// ----- docker save manifest.json read error -----

type manReadErrFile struct{}

func (manReadErrFile) Stat() (fs.FileInfo, error) { return memFileInfo{name: "manifest.json"}, nil }
func (manReadErrFile) Read([]byte) (int, error)   { return 0, errors.New("manifest read boom") }
func (manReadErrFile) Close() error               { return nil }

type manErrFS struct{ *memFS }

func (f manErrFS) Open(name string) (fs.File, error) {
	if name == "manifest.json" {
		return manReadErrFile{}, nil
	}
	return f.memFS.Open(name) // index.json absent -> falls through to manifest.json
}

func TestTopDescriptorDockerManifestReadError(t *testing.T) {
	tb := &tarball{fsys: manErrFS{memFS: &memFS{files: map[string][]byte{"manifest.json": nil}}}, blobs: map[string]string{}}
	if _, err := tb.topDescriptor(); err == nil || !bytes.Contains([]byte(err.Error()), []byte("reading manifest.json")) {
		t.Fatalf("want manifest read error, got %v", err)
	}
}

// ----- opaque whiteout keeps a same-layer entry added BEFORE the .opq -----

func TestOpaqueKeepsEarlierSameLayerEntry(t *testing.T) {
	lower := buildTar(t, []tentry{
		{name: "o/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "o/lowerfile", typeflag: tar.TypeReg, mode: 0o644, body: []byte("low")},
	})
	// In the upper layer, "o/early" is written BEFORE the opaque marker, so at
	// opq-application time it is already present-and-opaque and must be kept.
	upper := buildTar(t, []tentry{
		{name: "o/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "o/early", typeflag: tar.TypeReg, mode: 0o644, body: []byte("early")},
		{name: "o/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{
		{blob: lower, mediaType: MediaTypeLayerTar},
		{blob: upper, mediaType: MediaTypeLayerTar},
	})
	f, _ := OpenLayout(dir)
	defer f.Close()
	if b, _ := f.ReadFile("/o/early"); string(b) != "early" {
		t.Fatalf("opaque dropped earlier same-layer entry: %q", b)
	}
	if _, err := f.ReadFile("/o/lowerfile"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("opaque should clear lower entry: %v", err)
	}
}

// ----- tree internals: splitParent root, lookup nil children, applyLayer "." -----

func TestTreeInternals(t *testing.T) {
	if p, b := splitParent("/"); p != "/" || b != "" {
		t.Fatalf("splitParent root = %q,%q", p, b)
	}

	ov := newOverlay()
	// Put a regular file at /f, then look up a path beneath it (/f/x): the
	// regular node has nil children -> lookup returns false via that branch.
	ov.root.children["f"] = &node{name: "f", ftype: FileTypeRegular}
	if _, ok := ov.lookup("/f/x"); ok {
		t.Fatal("lookup beneath a file should fail")
	}

	// applyLayer with a "./" entry that cleans to "." must be skipped.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "keep", Typeflag: tar.TypeReg, Size: 1})
	_, _ = tw.Write([]byte("k"))
	_ = tw.Close()
	ov2 := newOverlay()
	if err := ov2.applyLayer(tar.NewReader(&buf), maxLayerUncompressed); err != nil {
		t.Fatal(err)
	}
	if _, ok := ov2.lookup("/keep"); !ok {
		t.Fatal("keep missing after root-skip layer")
	}
}
