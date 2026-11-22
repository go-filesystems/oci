package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"testing"
)

type spoolBlobs map[string][]byte

func (a spoolBlobs) Blob(d string) (io.ReadCloser, error) {
	b, ok := a[d]
	if !ok {
		return nil, fmt.Errorf("%s: %w", d, fs.ErrNotExist)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// zerosImage builds a one-layer gzip image whose layer holds one file of
// payload zero bytes, plus a small file, and returns its source and manifest
// descriptor.
func zerosImage(t testing.TB, payload int64) (spoolBlobs, descriptor, int) {
	t.Helper()
	var blob bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&blob, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "zeros", Mode: 0o644, Size: payload, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for left := payload; left > 0; left -= int64(len(chunk)) {
		if _, err := tw.Write(chunk[:min(int64(len(chunk)), left)]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "small", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("hello"))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	layer := blob.Bytes()
	cfg := []byte("{}")
	m := manifest{SchemaVersion: 2, MediaType: MediaTypeImageManifest,
		Config: descriptor{MediaType: MediaTypeImageConfig, Digest: sha256Digest(cfg), Size: 2},
		Layers: []descriptor{{MediaType: MediaTypeLayerTarGzip, Digest: sha256Digest(layer), Size: int64(len(layer))}}}
	mb, _ := json.Marshal(m)
	src := spoolBlobs{sha256Digest(layer): layer, sha256Digest(mb): mb, sha256Digest(cfg): cfg}
	return src, descriptor{MediaType: MediaTypeImageManifest, Digest: sha256Digest(mb), Size: int64(len(mb))}, len(layer)
}

// TestDefaultLimitsSpoolGzipLayerToDisk is the regression test of the audit
// finding "default limits buffer a gzip layer in RAM": with the DEFAULT
// limits, a layer whose one file is 256 MiB of zeros is spooled to disk, so the
// heap retained after Open stays far below the file size. (Scaled to 256 MiB so
// that it fits GOMEMLIMIT=1GiB; run it so: GOMEMLIMIT=1GiB go test -run
// TestDefaultLimitsSpoolGzipLayerToDisk.)
func TestDefaultLimitsSpoolGzipLayerToDisk(t *testing.T) {
	const payload = 256 << 20
	src, top, layerLen := zerosImage(t, payload)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fsys, err := OpenDescriptor(src, top, Selector{})
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("layer blob %d bytes; heap retained after Open %d MiB for a %d MiB file", layerLen, retained>>20, payload>>20)
	if retained > 64<<20 {
		t.Fatalf("a %d-byte image holds %d MiB of heap under the default limits", layerLen, retained>>20)
	}

	st, err := fsys.Stat("/zeros")
	if err != nil || st.Size() != payload {
		t.Fatalf("Stat(/zeros) = %v, %v; want size %d", st, err, payload)
	}
	got, err := fsys.ReadFile("/zeros")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != payload || got[0] != 0 || got[payload-1] != 0 {
		t.Fatalf("ReadFile(/zeros) returned %d bytes", len(got))
	}
	got = nil
	small, err := fsys.ReadFile("/small")
	if err != nil || string(small) != "hello" {
		t.Fatalf("ReadFile(/small) = %q, %v", small, err)
	}
}

func TestSpoolRoundTripAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name string
		lim  Limits
	}{
		{"threshold", Limits{SpoolThreshold: 1}},
		{"always", Limits{SpoolThreshold: -1}},
		{"memory", Limits{MaxMemory: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.lim.SpoolDir = dir
			src, top, _ := zerosImage(t, 3<<20)
			m, err := resolveManifestLimits(src, top, Selector{}, tc.lim.resolve(), 0)
			if err != nil {
				t.Fatal(err)
			}
			fsys, err := buildFS(src, m, tc.lim.resolve())
			if err != nil {
				t.Fatal(err)
			}
			if !fsys.ov.lookupMust(t, "/zeros").spooled {
				t.Fatal("/zeros was not spooled")
			}
			if tc.name != "memory" && !fsys.ov.lookupMust(t, "/small").spooled {
				t.Fatal("/small was not spooled")
			}
			got, err := fsys.ReadFile("/zeros")
			if err != nil || len(got) != 3<<20 || !bytes.Equal(got[:16], make([]byte, 16)) {
				t.Fatalf("ReadFile(/zeros): %d bytes, %v", len(got), err)
			}
			if err := fsys.Close(); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Fatalf("spool files left in %s: %d", dir, len(ents))
			}
		})
	}
}

func (o *overlay) lookupMust(t *testing.T, p string) *node {
	t.Helper()
	n, ok := o.lookup(p)
	if !ok {
		t.Fatalf("%s missing", p)
	}
	return n
}

func TestSpoolDirMustExist(t *testing.T) {
	src, top, _ := zerosImage(t, 3<<20)
	m, err := resolveManifestLimits(src, top, Selector{}, Limits{}.resolve(), 0)
	if err != nil {
		t.Fatal(err)
	}
	lim := Limits{SpoolDir: t.TempDir() + "/absent", SpoolThreshold: 1}.resolve()
	if _, err := buildFS(src, m, lim); err == nil {
		t.Fatal("buildFS succeeded with a missing spool directory")
	}
}

func TestSpooledLayerDigestMismatch(t *testing.T) {
	src, top, _ := zerosImage(t, 3<<20)
	m, err := resolveManifestLimits(src, top, Selector{}, Limits{}.resolve(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Declare the layer larger than the threshold so it is staged on disk, then
	// corrupt it.
	d := m.Layers[0].Digest
	src[d] = append([]byte(nil), src[d]...)
	src[d][len(src[d])/2] ^= 0xff
	lim := Limits{SpoolDir: t.TempDir(), SpoolThreshold: 1}.resolve()
	if _, err := buildFS(src, m, lim); err == nil {
		t.Fatal("corrupt spooled layer accepted")
	}
}

func TestTarballSpoolsLargeMembers(t *testing.T) {
	big := bytes.Repeat([]byte{7}, 64<<10)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string][]byte{"big/layer.tar": big, "small": []byte("x")} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
	}
	tw.Close()
	dir := t.TempDir()
	src, err := tarballFromReaderLimits(bytes.NewReader(buf.Bytes()), Limits{SpoolThreshold: 1024, SpoolDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	tb := src.(*tarball)
	mem := tb.fsys.(*memFS)
	if _, ok := mem.ext["big/layer.tar"]; !ok {
		t.Fatal("big member not spooled")
	}
	rc, err := src.Blob(sha256Digest(big))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, big) {
		t.Fatalf("spooled member read back %d bytes", len(got))
	}
	f, err := mem.Open("big/layer.tar")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := f.Stat(); st.Size() != int64(len(big)) {
		t.Fatalf("Stat size %d", st.Size())
	}
	if ents, err := mem.ReadDir("."); err != nil || len(ents) != 2 {
		t.Fatalf("ReadDir = %d entries, %v", len(ents), err)
	}
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Blob(sha256Digest(big)); err == nil {
		t.Fatal("Blob after Close succeeded")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("spool files left: %d", len(ents))
	}
}
