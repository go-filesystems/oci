package oci

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
)

// A docker-save manifest naming members that were spooled to disk (they are
// in mem.ext, not mem.files) must still resolve, with the size and digest the
// spool recorded.
func TestSynthManifestOfSpooledMembers(t *testing.T) {
	cfg := bytes.Repeat([]byte{'c'}, 4<<10)
	layer := bytes.Repeat([]byte{'l'}, 8<<10)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string][]byte{"cfg.json": cfg, "big/layer.tar": layer} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
	}
	tw.Close()
	lim := Limits{SpoolThreshold: 1024, SpoolDir: t.TempDir()}
	src, err := tarballFromReaderLimits(bytes.NewReader(buf.Bytes()), lim)
	if err != nil {
		t.Fatal(err)
	}
	tb := src.(*tarball)
	defer tb.Close()
	mem := tb.fsys.(*memFS)
	if _, ok := mem.ext["cfg.json"]; !ok {
		t.Fatal("config was not spooled")
	}
	desc, err := tb.synthManifest(dockerSaveManifest{Config: "cfg.json", Layers: []string{"big/layer.tar"}}, lim.resolve())
	if err != nil {
		t.Fatalf("synthManifest with spooled members: %v", err)
	}
	rc, err := src.Blob(desc.Digest)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	for _, want := range []string{sha256Digest(cfg), sha256Digest(layer)} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("synthesized manifest lacks %s: %s", want, got)
		}
	}
}
