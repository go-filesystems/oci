package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// ----- synthetic image building helpers -----

type tentry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	linkname string
}

func buildTar(t *testing.T, entries []tentry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
		}
		if e.typeflag == tar.TypeDir && hdr.Mode == 0 {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %s: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// layerSpec is a layer's bytes plus its declared media type.
type layerSpec struct {
	blob      []byte
	mediaType string
}

// writeLayout writes a full OCI image layout under dir with the given layers
// and returns the dir.
func writeLayout(t *testing.T, dir string, layers []layerSpec) {
	t.Helper()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBlob := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		if err := os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}

	config := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	configDigest := writeBlob(config)

	m := manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeImageManifest,
		Config:        descriptor{MediaType: MediaTypeImageConfig, Digest: configDigest, Size: int64(len(config))},
	}
	for _, l := range layers {
		ld := writeBlob(l.blob)
		m.Layers = append(m.Layers, descriptor{MediaType: l.mediaType, Digest: ld, Size: int64(len(l.blob))})
	}
	mBytes, _ := json.Marshal(m)
	mDigest := writeBlob(mBytes)

	idx := index{
		SchemaVersion: 2,
		MediaType:     MediaTypeImageIndex,
		Manifests:     []descriptor{{MediaType: MediaTypeImageManifest, Digest: mDigest, Size: int64(len(mBytes))}},
	}
	idxBytes, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idxBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ----- core overlay behaviour -----

func TestSingleLayerBasic(t *testing.T) {
	dir := t.TempDir()
	layer := buildTar(t, []tentry{
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/hostname", typeflag: tar.TypeReg, mode: 0o644, body: []byte("host\n")},
		{name: "bin/sh", typeflag: tar.TypeReg, mode: 0o755, body: []byte("ELF")},
	})
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})

	f, err := OpenLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := f.ReadFile("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "host\n" {
		t.Fatalf("hostname = %q", got)
	}
	// mutating the returned slice must not corrupt the buffered content.
	got[0] = 'X'
	again, _ := f.ReadFile("/etc/hostname")
	if string(again) != "host\n" {
		t.Fatalf("ReadFile not isolated: %q", again)
	}

	st, err := f.Stat("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("size = %d", st.Size())
	}
	if st.Mode()&0o777 != 0o755 {
		t.Fatalf("mode = %o", st.Mode())
	}
	if st.Mode()&0o170000 != 0o100000 {
		t.Fatalf("type bits = %o", st.Mode()&0o170000)
	}
	if st.Inode() == 0 {
		t.Fatal("inode 0")
	}
}

func TestMultiLayerOverrideAndAdd(t *testing.T) {
	lower := buildTar(t, []tentry{
		{name: "app/config", typeflag: tar.TypeReg, mode: 0o644, body: []byte("v1")},
		{name: "app/keep", typeflag: tar.TypeReg, mode: 0o644, body: []byte("keep")},
	})
	upper := buildTar(t, []tentry{
		{name: "app/config", typeflag: tar.TypeReg, mode: 0o644, body: []byte("v2")},
		{name: "app/new", typeflag: tar.TypeReg, mode: 0o644, body: []byte("new")},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{
		{blob: lower, mediaType: MediaTypeLayerTar},
		{blob: gzipBytes(t, upper), mediaType: MediaTypeLayerTarGzip},
	})

	f, err := OpenLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if b, _ := f.ReadFile("/app/config"); string(b) != "v2" {
		t.Fatalf("override: %q", b)
	}
	if b, _ := f.ReadFile("/app/keep"); string(b) != "keep" {
		t.Fatalf("keep: %q", b)
	}
	if b, _ := f.ReadFile("/app/new"); string(b) != "new" {
		t.Fatalf("new: %q", b)
	}
}

func TestWhiteoutRemovesLowerFile(t *testing.T) {
	lower := buildTar(t, []tentry{
		{name: "data/a", typeflag: tar.TypeReg, mode: 0o644, body: []byte("a")},
		{name: "data/b", typeflag: tar.TypeReg, mode: 0o644, body: []byte("b")},
	})
	upper := buildTar(t, []tentry{
		{name: "data/.wh.a", typeflag: tar.TypeReg, mode: 0o644},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{
		{blob: lower, mediaType: MediaTypeLayerTar},
		{blob: upper, mediaType: MediaTypeLayerTar},
	})
	f, _ := OpenLayout(dir)
	defer f.Close()

	if _, err := f.ReadFile("/data/a"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("whiteout did not remove a: %v", err)
	}
	if b, _ := f.ReadFile("/data/b"); string(b) != "b" {
		t.Fatalf("b should remain: %q", b)
	}
}

func TestOpaqueWhiteout(t *testing.T) {
	lower := buildTar(t, []tentry{
		{name: "d/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "d/old1", typeflag: tar.TypeReg, mode: 0o644, body: []byte("o1")},
		{name: "d/old2", typeflag: tar.TypeReg, mode: 0o644, body: []byte("o2")},
	})
	// Upper marks d opaque AND adds a new same-layer entry which must survive.
	upper := buildTar(t, []tentry{
		{name: "d/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "d/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
		{name: "d/fresh", typeflag: tar.TypeReg, mode: 0o644, body: []byte("fresh")},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{
		{blob: lower, mediaType: MediaTypeLayerTar},
		{blob: upper, mediaType: MediaTypeLayerTar},
	})
	f, _ := OpenLayout(dir)
	defer f.Close()

	if _, err := f.ReadFile("/d/old1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("opaque should clear old1: %v", err)
	}
	if _, err := f.ReadFile("/d/old2"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("opaque should clear old2: %v", err)
	}
	if b, _ := f.ReadFile("/d/fresh"); string(b) != "fresh" {
		t.Fatalf("same-layer entry lost: %q", b)
	}
}

func TestSymlinkAndHardlink(t *testing.T) {
	layer := buildTar(t, []tentry{
		{name: "real", typeflag: tar.TypeReg, mode: 0o644, body: []byte("content")},
		{name: "sym", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/real"},
		{name: "hard", typeflag: tar.TypeLink, mode: 0o644, linkname: "real"},
		{name: "hard2", typeflag: tar.TypeLink, mode: 0o644, linkname: "hard"}, // link to link
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, _ := OpenLayout(dir)
	defer f.Close()

	target, err := f.ReadLink("/sym")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/real" {
		t.Fatalf("symlink target = %q", target)
	}
	if b, err := f.ReadFile("/hard"); err != nil || string(b) != "content" {
		t.Fatalf("hardlink read = %q, %v", b, err)
	}
	if b, err := f.ReadFile("/hard2"); err != nil || string(b) != "content" {
		t.Fatalf("chained hardlink read = %q, %v", b, err)
	}
	// Stat on a symlink reports symlink type.
	st, _ := f.Stat("/sym")
	if st.Mode()&0o170000 != 0o120000 {
		t.Fatalf("sym type bits = %o", st.Mode()&0o170000)
	}
	// Stat on a hardlink follows to the target's metadata (regular).
	hst, _ := f.Stat("/hard")
	if hst.Mode()&0o170000 != 0o100000 {
		t.Fatalf("hard type bits = %o", hst.Mode()&0o170000)
	}
	if hst.Size() != 7 {
		t.Fatalf("hard size = %d", hst.Size())
	}
}

func TestSpecialFileTypes(t *testing.T) {
	layer := buildTar(t, []tentry{
		{name: "dev/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "dev/null", typeflag: tar.TypeChar, mode: 0o666},
		{name: "dev/sda", typeflag: tar.TypeBlock, mode: 0o660},
		{name: "dev/fifo", typeflag: tar.TypeFifo, mode: 0o644},
		{name: "weird", typeflag: tar.TypeXGlobalHeader}, // skipped (unknown)
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, _ := OpenLayout(dir)
	defer f.Close()

	cs, _ := f.Stat("/dev/null")
	if cs.Mode()&0o170000 != 0o020000 {
		t.Fatalf("char type = %o", cs.Mode()&0o170000)
	}
	bs, _ := f.Stat("/dev/sda")
	if bs.Mode()&0o170000 != 0o060000 {
		t.Fatalf("block type = %o", bs.Mode()&0o170000)
	}
	fs2, _ := f.Stat("/dev/fifo")
	if fs2.Mode()&0o170000 != 0o010000 {
		t.Fatalf("fifo type = %o", fs2.Mode()&0o170000)
	}
	if _, err := f.Stat("/weird"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown type should be skipped: %v", err)
	}
}

func TestListDirOrderingAndSynthParents(t *testing.T) {
	// Note: no explicit "a/" or "a/b/" dir entries -> parents synthesized.
	layer := buildTar(t, []tentry{
		{name: "a/b/zeta", typeflag: tar.TypeReg, mode: 0o644, body: []byte("z")},
		{name: "a/b/alpha", typeflag: tar.TypeReg, mode: 0o644, body: []byte("a")},
		{name: "a/b/mid", typeflag: tar.TypeReg, mode: 0o644, body: []byte("m")},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, _ := OpenLayout(dir)
	defer f.Close()

	entries, err := f.ListDir("/a/b")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "mid", "zeta"}
	if len(entries) != 3 {
		t.Fatalf("got %d entries", len(entries))
	}
	for i, e := range entries {
		if e.Name() != want[i] {
			t.Fatalf("entry %d = %q want %q", i, e.Name(), want[i])
		}
		if e.FileType() != FileTypeRegular {
			t.Fatalf("entry %q type = %d", e.Name(), e.FileType())
		}
		if e.Inode() == 0 {
			t.Fatalf("entry %q inode 0", e.Name())
		}
	}
	// Synthesized parent dir "a" exists and lists "b".
	root, err := f.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 1 || root[0].Name() != "a" || root[0].FileType() != FileTypeDir {
		t.Fatalf("root listing = %+v", root)
	}
	st, _ := f.Stat("/a")
	if st.Mode()&0o170000 != 0o040000 {
		t.Fatalf("dir type = %o", st.Mode()&0o170000)
	}
}

func TestDirReplacedByFileAndMerge(t *testing.T) {
	// lower: x is a dir with a child. upper: x reappears as a dir (merge path)
	// then a deeper layer turns a file path into a dir.
	lower := buildTar(t, []tentry{
		{name: "x/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "x/child", typeflag: tar.TypeReg, mode: 0o644, body: []byte("c")},
		{name: "y", typeflag: tar.TypeReg, mode: 0o644, body: []byte("file")},
	})
	upper := buildTar(t, []tentry{
		{name: "x/", typeflag: tar.TypeDir, mode: 0o700}, // merge, mode update
		{name: "x/added", typeflag: tar.TypeReg, mode: 0o644, body: []byte("add")},
		{name: "y/", typeflag: tar.TypeDir, mode: 0o755}, // file y replaced by dir
		{name: "y/inside", typeflag: tar.TypeReg, mode: 0o644, body: []byte("in")},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{
		{blob: lower, mediaType: MediaTypeLayerTar},
		{blob: upper, mediaType: MediaTypeLayerTar},
	})
	f, _ := OpenLayout(dir)
	defer f.Close()

	if b, _ := f.ReadFile("/x/child"); string(b) != "c" {
		t.Fatalf("merge lost child: %q", b)
	}
	if b, _ := f.ReadFile("/x/added"); string(b) != "add" {
		t.Fatalf("merge lost added: %q", b)
	}
	st, _ := f.Stat("/x")
	if st.Mode()&0o7777 != 0o700 {
		t.Fatalf("dir mode not updated: %o", st.Mode()&0o7777)
	}
	if b, _ := f.ReadFile("/y/inside"); string(b) != "in" {
		t.Fatalf("file->dir replace failed: %q", b)
	}
}

// ----- decompressor registry -----

func TestCustomDecompressor(t *testing.T) {
	const mt = "application/vnd.test.layer.rot13"
	// "compress" = rot13 each byte's low bit? Use a trivial reversible xor.
	plainLayer := buildTar(t, []tentry{
		{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("secret")},
	})
	xored := make([]byte, len(plainLayer))
	for i, b := range plainLayer {
		xored[i] = b ^ 0x5a
	}
	RegisterDecompressor(mt, func(r io.Reader) (io.Reader, error) {
		raw, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(raw))
		for i, b := range raw {
			out[i] = b ^ 0x5a
		}
		return bytes.NewReader(out), nil
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: xored, mediaType: mt}})
	f, err := OpenLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/f"); string(b) != "secret" {
		t.Fatalf("custom decompressor: %q", b)
	}
}

func TestUnknownMediaType(t *testing.T) {
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, body: []byte("x")}})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: "application/x-unregistered"}})
	_, err := OpenLayout(dir)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("no decompressor")) {
		t.Fatalf("want unknown media type error, got %v", err)
	}
}

func TestLookupDecompressorParamStripping(t *testing.T) {
	d, err := lookupDecompressor(MediaTypeLayerTarGzip + "; charset=utf-8")
	if err != nil || d == nil {
		t.Fatalf("param strip lookup failed: %v", err)
	}
}

func TestCustomDecompressorError(t *testing.T) {
	const mt = "application/vnd.test.fail"
	RegisterDecompressor(mt, func(r io.Reader) (io.Reader, error) {
		return nil, errors.New("boom")
	})
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, body: []byte("x")}})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: mt}})
	_, err := OpenLayout(dir)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("decompressing")) {
		t.Fatalf("want decompress error, got %v", err)
	}
}

// ----- tarball (docker save) -----

func writeDockerSaveTarball(t *testing.T, layers [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, body []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
	}
	config := []byte(`{"architecture":"arm64","os":"linux"}`)
	add("config.json", config)
	var layerNames []string
	for i, l := range layers {
		name := filepath.Join("layer"+string(rune('0'+i)), "layer.tar")
		add(name, l)
		layerNames = append(layerNames, name)
	}
	save := []dockerSaveManifest{{Config: "config.json", RepoTags: []string{"img:latest"}, Layers: layerNames}}
	sb, _ := json.Marshal(save)
	add("manifest.json", sb)
	_ = tw.Close()
	return buf.Bytes()
}

func TestTarballDockerSave(t *testing.T) {
	l0 := buildTar(t, []tentry{
		{name: "etc/x", typeflag: tar.TypeReg, mode: 0o644, body: []byte("first")},
		{name: "etc/y", typeflag: tar.TypeReg, mode: 0o644, body: []byte("y0")},
	})
	l1 := buildTar(t, []tentry{
		{name: "etc/x", typeflag: tar.TypeReg, mode: 0o644, body: []byte("second")},
		{name: "etc/.wh.y", typeflag: tar.TypeReg, mode: 0o644},
	})
	tarBytes := writeDockerSaveTarball(t, [][]byte{l0, l1})
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, tarBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenTarball(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/etc/x"); string(b) != "second" {
		t.Fatalf("docker save override: %q", b)
	}
	if _, err := f.ReadFile("/etc/y"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("docker save whiteout: %v", err)
	}
}

func TestTarballOCIArchive(t *testing.T) {
	// An OCI archive carries index.json + blobs/ inside the tar.
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("oci")}})
	config := []byte(`{"architecture":"arm64","os":"linux"}`)

	var members []tentry
	put := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		members = append(members, tentry{name: "blobs/sha256/" + hx, typeflag: tar.TypeReg, mode: 0o644, body: b})
		return d
	}
	cd := put(config)
	ld := put(layer)
	m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
		Config: descriptor{MediaType: MediaTypeImageConfig, Digest: cd, Size: int64(len(config))},
		Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: ld, Size: int64(len(layer))}}}
	mb, _ := json.Marshal(m)
	md := put(mb)
	idx := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
		Manifests: []descriptor{{MediaType: MediaTypeImageManifest, Digest: md, Size: int64(len(mb))}}}
	ib, _ := json.Marshal(idx)
	members = append(members, tentry{name: "index.json", typeflag: tar.TypeReg, mode: 0o644, body: ib})
	members = append(members, tentry{name: "oci-layout", typeflag: tar.TypeReg, mode: 0o644, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)})

	archive := buildTar(t, members)
	p := filepath.Join(t.TempDir(), "oci.tar")
	if err := os.WriteFile(p, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenTarball(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/f"); string(b) != "oci" {
		t.Fatalf("oci archive read: %q", b)
	}
}

func TestTarballFS(t *testing.T) {
	l0 := buildTar(t, []tentry{{name: "g", typeflag: tar.TypeReg, mode: 0o644, body: []byte("fsbacked")}})
	tarBytes := writeDockerSaveTarball(t, [][]byte{l0})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "image.tar"), tarBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := TarballFS(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/g"); string(b) != "fsbacked" {
		t.Fatalf("TarballFS read: %q", b)
	}
}

// ----- multi-arch selection -----

func writeMultiArchLayout(t *testing.T, dir string) (arm64Digest string) {
	t.Helper()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBlob := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		if err := os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	mkManifest := func(body string) string {
		layer := buildTar(t, []tentry{{name: "arch", typeflag: tar.TypeReg, mode: 0o644, body: []byte(body)}})
		ld := writeBlob(layer)
		config := []byte(`{"architecture":"` + body + `","os":"linux"}`)
		cd := writeBlob(config)
		m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
			Config: descriptor{MediaType: MediaTypeImageConfig, Digest: cd, Size: int64(len(config))},
			Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: ld, Size: int64(len(layer))}}}
		mb, _ := json.Marshal(m)
		return writeBlob(mb)
	}
	amdM := mkManifest("amd64")
	armM := mkManifest("arm64")
	idx := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex, Manifests: []descriptor{
		{MediaType: MediaTypeImageManifest, Digest: amdM, Platform: &platform{OS: "linux", Architecture: "amd64"}},
		{MediaType: MediaTypeImageManifest, Digest: armM, Platform: &platform{OS: "linux", Architecture: "arm64"}},
	}}
	ib, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), ib, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return armM
}

func TestMultiArchSelectByPlatform(t *testing.T) {
	dir := t.TempDir()
	armDigest := writeMultiArchLayout(t, dir)

	// Default Open picks the first matching (amd64).
	f, err := Open(OCILayout(dir))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := f.ReadFile("/arch"); string(b) != "amd64" {
		t.Fatalf("default select = %q", b)
	}
	f.Close()

	// Select arm64 by platform.
	f2, err := OpenSelect(OCILayout(dir), Selector{OS: "linux", Architecture: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := f2.ReadFile("/arch"); string(b) != "arm64" {
		t.Fatalf("arm select = %q", b)
	}
	f2.Close()

	// Select by digest.
	f3, err := OpenSelect(OCILayout(dir), Selector{Digest: armDigest})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := f3.ReadFile("/arch"); string(b) != "arm64" {
		t.Fatalf("digest select = %q", b)
	}
	f3.Close()

	// No match.
	if _, err := OpenSelect(OCILayout(dir), Selector{Architecture: "riscv64"}); err == nil {
		t.Fatal("expected no-match error")
	}
}

// ----- OpenDescriptor + variant probing (no mediaType) -----

func TestOpenDescriptorAndMediaTypeSniff(t *testing.T) {
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBlob := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		if err := os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	layer := buildTar(t, []tentry{{name: "z", typeflag: tar.TypeReg, mode: 0o644, body: []byte("zz")}})
	ld := writeBlob(layer)
	config := []byte(`{"architecture":"arm64","os":"linux"}`)
	cd := writeBlob(config)
	// Manifest WITHOUT a mediaType field to exercise the sniff path.
	m := manifest{SchemaVersion: 2,
		Config: descriptor{MediaType: MediaTypeImageConfig, Digest: cd, Size: int64(len(config))},
		Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: ld, Size: int64(len(layer))}}}
	mb, _ := json.Marshal(m)
	md := writeBlob(mb)

	src := OCILayout(dir)
	// Descriptor with empty MediaType -> sniff -> manifest.
	f, err := OpenDescriptor(src, descriptor{Digest: md}, Selector{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/z"); string(b) != "zz" {
		t.Fatalf("sniff manifest read: %q", b)
	}
}

func TestSniffIndexWithoutMediaType(t *testing.T) {
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	_ = os.MkdirAll(blobsDir, 0o755)
	writeBlob := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		_ = os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644)
		return d
	}
	layer := buildTar(t, []tentry{{name: "q", typeflag: tar.TypeReg, mode: 0o644, body: []byte("qq")}})
	ld := writeBlob(layer)
	config := []byte(`{"os":"linux"}`)
	cd := writeBlob(config)
	m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
		Config: descriptor{MediaType: MediaTypeImageConfig, Digest: cd, Size: int64(len(config))},
		Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: ld, Size: int64(len(layer))}}}
	mb, _ := json.Marshal(m)
	md := writeBlob(mb)
	// Index WITHOUT mediaType -> sniff via "manifests".
	idx := index{SchemaVersion: 2, Manifests: []descriptor{{Digest: md}}}
	ib, _ := json.Marshal(idx)
	id := writeBlob(ib)

	f, err := OpenDescriptor(OCILayout(dir), descriptor{Digest: id}, Selector{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/q"); string(b) != "qq" {
		t.Fatalf("sniff index read: %q", b)
	}
}

// ----- read-only sentinel methods -----

func TestReadOnlyMethods(t *testing.T) {
	dir := t.TempDir()
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}})
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, _ := OpenLayout(dir)
	defer f.Close()

	if err := f.WriteFile("/f", []byte("y"), 0o644); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := f.MkDir("/d", 0o755); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("MkDir: %v", err)
	}
	if err := f.DeleteFile("/f"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("DeleteFile: %v", err)
	}
	if err := f.DeleteDir("/d"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("DeleteDir: %v", err)
	}
	if err := f.Rename("/f", "/g"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Rename: %v", err)
	}
}

func TestDoubleCloseAndUseAfterClose(t *testing.T) {
	dir := t.TempDir()
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}})
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, _ := OpenLayout(dir)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
	if _, err := f.ReadFile("/f"); err == nil {
		t.Fatal("expected error after close")
	}
	if _, err := f.Stat("/f"); err == nil {
		t.Fatal("expected stat error after close")
	}
	if _, err := f.ListDir("/"); err == nil {
		t.Fatal("expected listdir error after close")
	}
	if _, err := f.ReadLink("/f"); err == nil {
		t.Fatal("expected readlink error after close")
	}
}

// ----- error branches -----

func TestErrorBranches(t *testing.T) {
	t.Run("missing blob", func(t *testing.T) {
		dir := t.TempDir()
		// index.json references a manifest blob that doesn't exist.
		_ = os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755)
		idx := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
			Manifests: []descriptor{{MediaType: MediaTypeImageManifest, Digest: "sha256:" + hex.EncodeToString(make([]byte, 32))}}}
		ib, _ := json.Marshal(idx)
		_ = os.WriteFile(filepath.Join(dir, "index.json"), ib, 0o644)
		if _, err := OpenLayout(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("missing blob: %v", err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		dir := t.TempDir()
		blobsDir := filepath.Join(dir, "blobs", "sha256")
		_ = os.MkdirAll(blobsDir, 0o755)
		// Write a manifest under a WRONG hex name so digest verify fails.
		layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, body: []byte("x")}})
		ld := digestOf(layer)
		_, lhx, _ := parseDigest(ld)
		_ = os.WriteFile(filepath.Join(blobsDir, lhx), layer, 0o644)
		m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
			Config: descriptor{Digest: ld}, Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: ld}}}
		mb, _ := json.Marshal(m)
		wrongHex := hex.EncodeToString(make([]byte, 32)) // all-zero name
		_ = os.WriteFile(filepath.Join(blobsDir, wrongHex), mb, 0o644)
		idx := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
			Manifests: []descriptor{{MediaType: MediaTypeImageManifest, Digest: "sha256:" + wrongHex}}}
		ib, _ := json.Marshal(idx)
		_ = os.WriteFile(filepath.Join(dir, "index.json"), ib, 0o644)
		if _, err := OpenLayout(dir); err == nil || !bytes.Contains([]byte(err.Error()), []byte("digest mismatch")) {
			t.Fatalf("digest mismatch: %v", err)
		}
	})

	t.Run("malformed index json", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "index.json"), []byte("{not json"), 0o644)
		if _, err := OpenLayout(dir); err == nil {
			t.Fatal("malformed index: expected error")
		}
	})

	t.Run("empty index", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"schemaVersion":2,"manifests":[]}`), 0o644)
		if _, err := OpenLayout(dir); err == nil {
			t.Fatal("empty index: expected error")
		}
	})

	t.Run("missing index file", func(t *testing.T) {
		if _, err := OpenLayout(t.TempDir()); err == nil {
			t.Fatal("missing index.json: expected error")
		}
	})

	t.Run("malformed manifest json", func(t *testing.T) {
		dir := t.TempDir()
		blobsDir := filepath.Join(dir, "blobs", "sha256")
		_ = os.MkdirAll(blobsDir, 0o755)
		bad := []byte("{broken")
		bd := digestOf(bad)
		_, bhx, _ := parseDigest(bd)
		_ = os.WriteFile(filepath.Join(blobsDir, bhx), bad, 0o644)
		idx := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
			Manifests: []descriptor{{MediaType: MediaTypeImageManifest, Digest: bd}}}
		ib, _ := json.Marshal(idx)
		_ = os.WriteFile(filepath.Join(dir, "index.json"), ib, 0o644)
		if _, err := OpenLayout(dir); err == nil {
			t.Fatal("malformed manifest: expected error")
		}
	})

	t.Run("manifest no layers", func(t *testing.T) {
		dir := t.TempDir()
		writeLayoutRaw(t, dir, manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest})
		if _, err := OpenLayout(dir); err == nil || !bytes.Contains([]byte(err.Error()), []byte("no layers")) {
			t.Fatalf("no layers: %v", err)
		}
	})

	t.Run("truncated tar", func(t *testing.T) {
		dir := t.TempDir()
		layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: bytes.Repeat([]byte("a"), 2048)}})
		truncated := layer[:600] // cut mid-stream
		writeLayout(t, dir, []layerSpec{{blob: truncated, mediaType: MediaTypeLayerTar}})
		if _, err := OpenLayout(dir); err == nil {
			t.Fatal("truncated tar: expected error")
		}
	})

	t.Run("gzip body but plain media type", func(t *testing.T) {
		dir := t.TempDir()
		layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, body: []byte("x")}})
		gz := gzipBytes(t, layer)
		// declared plain -> tar reader sees gzip magic -> error
		writeLayout(t, dir, []layerSpec{{blob: gz, mediaType: MediaTypeLayerTar}})
		if _, err := OpenLayout(dir); err == nil {
			t.Fatal("gzip-as-plain: expected tar error")
		}
	})

	t.Run("plain body but gzip media type", func(t *testing.T) {
		dir := t.TempDir()
		layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, body: []byte("x")}})
		writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTarGzip}})
		if _, err := OpenLayout(dir); err == nil {
			t.Fatal("plain-as-gzip: expected gzip header error")
		}
	})

	t.Run("path not found and not-dir/not-file/not-symlink", func(t *testing.T) {
		dir := t.TempDir()
		layer := buildTar(t, []tentry{
			{name: "d/", typeflag: tar.TypeDir, mode: 0o755},
			{name: "d/file", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")},
		})
		writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
		f, _ := OpenLayout(dir)
		defer f.Close()
		if _, err := f.Stat("/nope"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stat missing: %v", err)
		}
		if _, err := f.ListDir("/d/missing/deep"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("listdir missing: %v", err)
		}
		if _, err := f.ListDir("/d/file"); err == nil {
			t.Fatal("listdir on file: expected error")
		}
		if _, err := f.ReadFile("/d"); err == nil {
			t.Fatal("readfile on dir: expected error")
		}
		if _, err := f.ReadLink("/d/file"); err == nil {
			t.Fatal("readlink on file: expected error")
		}
	})
}

func writeLayoutRaw(t *testing.T, dir string, m manifest) {
	t.Helper()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	_ = os.MkdirAll(blobsDir, 0o755)
	mb, _ := json.Marshal(m)
	md := digestOf(mb)
	_, mhx, _ := parseDigest(md)
	_ = os.WriteFile(filepath.Join(blobsDir, mhx), mb, 0o644)
	idx := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
		Manifests: []descriptor{{MediaType: MediaTypeImageManifest, Digest: md}}}
	ib, _ := json.Marshal(idx)
	_ = os.WriteFile(filepath.Join(dir, "index.json"), ib, 0o644)
}

// ----- digest / path helpers -----

func TestParseDigestErrors(t *testing.T) {
	for _, bad := range []string{"", ":", "sha256:", ":abc", "sha256:zz", "noColon"} {
		if _, _, err := parseDigest(bad); err == nil {
			t.Fatalf("parseDigest(%q) should fail", bad)
		}
	}
	if a, h, err := parseDigest("sha256:" + hex.EncodeToString([]byte{0x01})); err != nil || a != "sha256" || h != "01" {
		t.Fatalf("parseDigest valid: %v %q %q", err, a, h)
	}
}

func TestVerifyDigestNonSHA256(t *testing.T) {
	// non-sha256 algorithm is accepted without verification.
	if err := verifyDigest("sha512:"+hex.EncodeToString(make([]byte, 64)), []byte("anything")); err != nil {
		t.Fatalf("sha512 should pass-through: %v", err)
	}
	if err := verifyDigest("bad", nil); err == nil {
		t.Fatal("bad digest should error")
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"":           "/",
		"/":          "/",
		"a/b":        "/a/b",
		"/a/../b":    "/b",
		"/a/./b/":    "/a/b",
		"//x//y":     "/x/y",
		"/../escape": "/escape",
	}
	for in, want := range cases {
		if got := cleanPath(in); got != want {
			t.Fatalf("cleanPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBlobMalformedDigest(t *testing.T) {
	if _, err := OCILayout(t.TempDir()).Blob("nope"); err == nil {
		t.Fatal("layout blob malformed digest: expected error")
	}
	tb, _ := tarballFromReader(bytes.NewReader(buildTar(t, nil)))
	if _, err := tb.Blob("nope"); err == nil {
		t.Fatal("tarball blob malformed digest: expected error")
	}
	if _, err := tb.Blob("sha256:" + hex.EncodeToString(make([]byte, 32))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("tarball missing blob: %v", err)
	}
}

// ----- tarball construction error branches -----

func TestTarballErrors(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		if _, err := Tarball(filepath.Join(t.TempDir(), "nope.tar")); err == nil {
			t.Fatal("expected open error")
		}
		if _, err := OpenTarball(filepath.Join(t.TempDir(), "nope.tar")); err == nil {
			t.Fatal("expected open error")
		}
	})

	t.Run("bad archive bytes", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.tar")
		_ = os.WriteFile(p, []byte("this is not a tar at all, but long enough to look like one............"), 0o644)
		// archive/tar tolerates leading garbage as EOF in some cases; ensure
		// no panic and an empty source resolves to a "no index/manifest" err.
		src, err := Tarball(p)
		if err != nil {
			return // acceptable: read error
		}
		if _, err := Open(src); err == nil {
			t.Fatal("expected resolve error on empty archive")
		}
	})

	t.Run("archive without manifest or index", func(t *testing.T) {
		archive := buildTar(t, []tentry{{name: "random.txt", typeflag: tar.TypeReg, body: []byte("hi")}})
		p := filepath.Join(t.TempDir(), "noman.tar")
		_ = os.WriteFile(p, archive, 0o644)
		src, _ := Tarball(p)
		if _, err := Open(src); err == nil || !bytes.Contains([]byte(err.Error()), []byte("neither index.json nor manifest.json")) {
			t.Fatalf("want neither-index error, got %v", err)
		}
	})

	t.Run("docker save missing config member", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		save := []dockerSaveManifest{{Config: "missing-config.json", Layers: []string{"l/layer.tar"}}}
		sb, _ := json.Marshal(save)
		_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: int64(len(sb))})
		_, _ = tw.Write(sb)
		_ = tw.Close()
		p := filepath.Join(t.TempDir(), "x.tar")
		_ = os.WriteFile(p, buf.Bytes(), 0o644)
		src, _ := Tarball(p)
		if _, err := Open(src); err == nil || !bytes.Contains([]byte(err.Error()), []byte("config")) {
			t.Fatalf("want config-missing error, got %v", err)
		}
	})

	t.Run("docker save missing layer member", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		cfg := []byte(`{"os":"linux"}`)
		_ = tw.WriteHeader(&tar.Header{Name: "config.json", Typeflag: tar.TypeReg, Size: int64(len(cfg))})
		_, _ = tw.Write(cfg)
		save := []dockerSaveManifest{{Config: "config.json", Layers: []string{"l/missing.tar"}}}
		sb, _ := json.Marshal(save)
		_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: int64(len(sb))})
		_, _ = tw.Write(sb)
		_ = tw.Close()
		p := filepath.Join(t.TempDir(), "x2.tar")
		_ = os.WriteFile(p, buf.Bytes(), 0o644)
		src, _ := Tarball(p)
		if _, err := Open(src); err == nil || !bytes.Contains([]byte(err.Error()), []byte("layer")) {
			t.Fatalf("want layer-missing error, got %v", err)
		}
	})

	t.Run("empty docker manifest list", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		sb := []byte(`[]`)
		_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: int64(len(sb))})
		_, _ = tw.Write(sb)
		_ = tw.Close()
		p := filepath.Join(t.TempDir(), "empty.tar")
		_ = os.WriteFile(p, buf.Bytes(), 0o644)
		src, _ := Tarball(p)
		if _, err := Open(src); err == nil || !bytes.Contains([]byte(err.Error()), []byte("empty")) {
			t.Fatalf("want empty manifest error, got %v", err)
		}
	})

	t.Run("malformed docker manifest json", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		sb := []byte(`{not array`)
		_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: int64(len(sb))})
		_, _ = tw.Write(sb)
		_ = tw.Close()
		p := filepath.Join(t.TempDir(), "malman.tar")
		_ = os.WriteFile(p, buf.Bytes(), 0o644)
		src, _ := Tarball(p)
		if _, err := Open(src); err == nil {
			t.Fatal("expected malformed docker manifest error")
		}
	})

	t.Run("malformed archive index json", func(t *testing.T) {
		archive := buildTar(t, []tentry{{name: "index.json", typeflag: tar.TypeReg, body: []byte("{bad")}})
		p := filepath.Join(t.TempDir(), "badidx.tar")
		_ = os.WriteFile(p, archive, 0o644)
		src, _ := Tarball(p)
		if _, err := Open(src); err == nil {
			t.Fatal("expected malformed archive index error")
		}
	})
}

func TestTarballFSEmpty(t *testing.T) {
	if _, err := TarballFS(os.DirFS(t.TempDir())); err == nil {
		t.Fatal("empty dir fs: expected error")
	}
}

// ----- manifest classification edge cases -----

func TestUnsupportedAndUnclassifiableDescriptor(t *testing.T) {
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	_ = os.MkdirAll(blobsDir, 0o755)
	put := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		_ = os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644)
		return d
	}
	src := OCILayout(dir)

	// Unsupported declared media type.
	blob := []byte(`{"schemaVersion":2}`)
	bd := put(blob)
	if _, err := OpenDescriptor(src, descriptor{Digest: bd, MediaType: "application/x-weird"}, Selector{}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("unsupported descriptor media type")) {
		t.Fatalf("want unsupported, got %v", err)
	}

	// Unclassifiable: empty mediaType, no config, no manifests.
	empty := []byte(`{"schemaVersion":2}`)
	ed := put(empty)
	if _, err := OpenDescriptor(src, descriptor{Digest: ed}, Selector{}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("cannot classify")) {
		t.Fatalf("want cannot-classify, got %v", err)
	}

	// Malformed JSON during sniff probe.
	bad := []byte(`{broken`)
	badd := put(bad)
	if _, err := OpenDescriptor(src, descriptor{Digest: badd}, Selector{}); err == nil {
		t.Fatal("want sniff parse error")
	}
}

func TestNestedIndexResolution(t *testing.T) {
	// index -> index -> manifest, to cover the recursive index branch.
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	_ = os.MkdirAll(blobsDir, 0o755)
	put := func(b []byte) string {
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		_ = os.WriteFile(filepath.Join(blobsDir, hx), b, 0o644)
		return d
	}
	layer := buildTar(t, []tentry{{name: "n", typeflag: tar.TypeReg, mode: 0o644, body: []byte("nested")}})
	ld := put(layer)
	cfg := []byte(`{"os":"linux"}`)
	cd := put(cfg)
	m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
		Config: descriptor{Digest: cd}, Layers: []descriptor{{MediaType: MediaTypeLayerTar, Digest: ld}}}
	mb, _ := json.Marshal(m)
	md := put(mb)
	inner := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
		Manifests: []descriptor{{MediaType: MediaTypeImageManifest, Digest: md}}}
	ib, _ := json.Marshal(inner)
	id := put(ib)
	outer := index{SchemaVersion: 2, MediaType: MediaTypeImageIndex,
		Manifests: []descriptor{{MediaType: MediaTypeImageIndex, Digest: id}}}
	ob, _ := json.Marshal(outer)
	_ = os.WriteFile(filepath.Join(dir, "index.json"), ob, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{}`), 0o644)

	f, err := OpenLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, _ := f.ReadFile("/n"); string(b) != "nested" {
		t.Fatalf("nested index read: %q", b)
	}
}

func TestTopDescriptorUnsupportedSource(t *testing.T) {
	// A bare BlobSource that doesn't implement topDescriptorProvider.
	var src BlobSource = bareSource{}
	if _, err := Open(src); err == nil || !bytes.Contains([]byte(err.Error()), []byte("does not provide a top descriptor")) {
		t.Fatalf("want bare-source error, got %v", err)
	}
}

type bareSource struct{}

func (bareSource) Blob(string) (io.ReadCloser, error) {
	return nil, errors.New("unused")
}

func TestHardlinkMissingTarget(t *testing.T) {
	layer := buildTar(t, []tentry{
		{name: "h", typeflag: tar.TypeLink, mode: 0o644, linkname: "does/not/exist"},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, _ := OpenLayout(dir)
	defer f.Close()
	if _, err := f.ReadFile("/h"); err == nil {
		t.Fatal("dangling hardlink read: expected error")
	}
	if _, err := f.Stat("/h"); err == nil {
		t.Fatal("dangling hardlink stat: expected error")
	}
}

func TestStatInterfaceCompliance(t *testing.T) {
	var _ filesystem.Filesystem = (*FS)(nil)
	st := filesystem.NewStat(0o100644, 5, 7)
	if st.Mode() != 0o100644 || st.Size() != 5 || st.Inode() != 7 {
		t.Fatal("NewStat round-trip failed")
	}
	de := filesystem.NewDirEntry(3, "x", FileTypeRegular)
	if de.Inode() != 3 || de.Name() != "x" || de.FileType() != FileTypeRegular {
		t.Fatal("NewDirEntry round-trip failed")
	}
}

func TestMemFSReadDirAndMisc(t *testing.T) {
	// Exercise memFS.ReadDir + memDirEntry accessors via TarballFS path that
	// reads the archive's root dir. Build a docker save tarball, back it with
	// an fs, then resolve top descriptor.
	l0 := buildTar(t, []tentry{{name: "m", typeflag: tar.TypeReg, mode: 0o644, body: []byte("mm")}})
	tarBytes := writeDockerSaveTarball(t, [][]byte{l0})
	src, err := tarballFromReader(bytes.NewReader(tarBytes))
	if err != nil {
		t.Fatal(err)
	}
	tb := src.(*tarball)
	mem := tb.fsys.(*memFS)
	entries, err := mem.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	for _, e := range entries {
		_ = e.Name()
		_ = e.IsDir()
		_ = e.Type()
		if info, err := e.Info(); err != nil || info.Name() == "" {
			t.Fatalf("entry info: %v", err)
		}
	}
	if _, err := mem.ReadDir("sub"); err == nil {
		t.Fatal("ReadDir non-root should error")
	}
	if _, err := mem.Open("nonexistent"); err == nil {
		t.Fatal("Open missing should error")
	}
	// memFile.Stat + Read to EOF.
	fh, _ := mem.Open("config.json")
	if info, err := fh.Stat(); err != nil || info.Size() == 0 {
		t.Fatalf("memfile stat: %v", err)
	}
	buf := make([]byte, 4)
	for {
		_, err := fh.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = fh.Close()
	// memFileInfo accessors.
	info, _ := mem.Open("config.json")
	fi, _ := info.Stat()
	_ = fi.Mode()
	_ = fi.ModTime()
	_ = fi.IsDir()
	_ = fi.Sys()
	di := memFileInfo{name: "d", dir: true}
	if di.Mode()&fs.ModeDir == 0 {
		t.Fatal("dir mode missing")
	}
}
