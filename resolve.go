package oci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// byteReader returns an io.Reader over b. Centralised so the rest of the
// package never imports bytes directly for this trivial use.
func byteReader(b []byte) io.Reader { return bytes.NewReader(b) }

// topDescriptorProvider is the optional interface a BlobSource implements to
// describe how to find the image's top-level descriptor (index or manifest).
// Both built-in sources implement it; a caller-supplied BlobSource that does
// not implement it can still be used via OpenDescriptor.
type topDescriptorProvider interface {
	topDescriptor() (descriptor, error)
}

// topDescriptor resolves the top-level descriptor for src. Sources that don't
// advertise one are rejected with a clear error directing the caller to
// OpenDescriptor.
func topDescriptor(src BlobSource) (descriptor, error) {
	p, ok := src.(topDescriptorProvider)
	if !ok {
		return descriptor{}, fmt.Errorf("oci: BlobSource %T does not provide a top descriptor; use OpenDescriptor", src)
	}
	return p.topDescriptor()
}

// OpenDescriptor opens an image given an explicit top-level descriptor,
// allowing use of a bare BlobSource that does not embed index discovery.
func OpenDescriptor(src BlobSource, top descriptor, sel Selector) (*FS, error) {
	m, err := resolveManifest(src, top, sel)
	if err != nil {
		return nil, err
	}
	ov := newOverlay()
	for _, layer := range m.Layers {
		if err := applyLayerBlob(ov, src, layer); err != nil {
			return nil, err
		}
		ov.clearOpaqueFlags()
	}
	return &FS{ov: ov}, nil
}

// ----- OCI layout top descriptor -----

func (o *ociLayout) topDescriptor() (descriptor, error) {
	data, err := os.ReadFile(filepath.Join(o.dir, "index.json"))
	if err != nil {
		return descriptor{}, fmt.Errorf("oci: reading index.json: %w", err)
	}
	if _, err := readIndexJSON(data); err != nil {
		return descriptor{}, err
	}
	// Register the index itself as a synthetic blob so resolveManifest can
	// load it and apply the selector across all of its manifests.
	dgst := sha256Digest(data)
	if o.synth == nil {
		o.synth = map[string][]byte{}
	}
	o.synth[dgst] = data
	return descriptor{MediaType: MediaTypeImageIndex, Digest: dgst, Size: int64(len(data))}, nil
}

// ----- Tarball top descriptor -----

func (t *tarball) topDescriptor() (descriptor, error) {
	// Prefer an OCI archive index.json.
	if rc, err := t.fsys.Open("index.json"); err == nil {
		data, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			return descriptor{}, fmt.Errorf("oci: reading archive index.json: %w", rerr)
		}
		if _, perr := readIndexJSON(data); perr != nil {
			return descriptor{}, perr
		}
		dgst := sha256Digest(data)
		mem := t.fsys.(*memFS)
		_, hexpart, _ := parseDigest(dgst)
		mem.files["blobs/sha256/"+hexpart] = data
		t.blobs["sha256/"+hexpart] = "blobs/sha256/" + hexpart
		return descriptor{MediaType: MediaTypeImageIndex, Digest: dgst, Size: int64(len(data))}, nil
	}

	// Fall back to a docker save manifest.json.
	rc, err := t.fsys.Open("manifest.json")
	if err != nil {
		return descriptor{}, fmt.Errorf("oci: archive has neither index.json nor manifest.json")
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return descriptor{}, fmt.Errorf("oci: reading manifest.json: %w", err)
	}
	var saves []dockerSaveManifest
	if err := json.Unmarshal(data, &saves); err != nil {
		return descriptor{}, fmt.Errorf("oci: parsing manifest.json: %w", err)
	}
	if len(saves) == 0 {
		return descriptor{}, fmt.Errorf("oci: manifest.json is empty")
	}
	return t.synthManifest(saves[0])
}

// synthManifest builds an OCI manifest blob from a docker-save manifest.json
// entry (which references config + layer files by archive path), inserts it
// into the tarball's content store, and returns a descriptor pointing at it.
func (t *tarball) synthManifest(s dockerSaveManifest) (descriptor, error) {
	mem := t.fsys.(*memFS) // tarballFromReader always backs t with *memFS

	member := func(kind, p string) ([]byte, string, error) {
		data, ok := mem.files[normalizeArchivePath(p)]
		if !ok {
			return nil, "", fmt.Errorf("oci: %s %q: member not found in archive", kind, p)
		}
		return data, sha256Digest(data), nil
	}

	cfg, configDigest, err := member("config", s.Config)
	if err != nil {
		return descriptor{}, err
	}
	m := manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifest,
		Config: descriptor{
			MediaType: MediaTypeDockerImageConfig,
			Digest:    configDigest,
			Size:      int64(len(cfg)),
		},
	}
	for _, l := range s.Layers {
		data, dgst, err := member("layer", l)
		if err != nil {
			return descriptor{}, err
		}
		// docker save layers are uncompressed tar.
		m.Layers = append(m.Layers, descriptor{
			MediaType: MediaTypeDockerLayerTar,
			Digest:    dgst,
			Size:      int64(len(data)),
		})
	}
	// json.Marshal of a manifest (only strings/ints/slices/maps) cannot fail.
	blob, _ := json.Marshal(m)
	dgst := sha256Digest(blob)
	// Store synthesized manifest so resolveManifest can fetch it.
	_, hexpart, _ := parseDigest(dgst)
	mem.files["blobs/sha256/"+hexpart] = blob
	t.blobs["sha256/"+hexpart] = "blobs/sha256/" + hexpart
	return descriptor{MediaType: MediaTypeDockerManifest, Digest: dgst, Size: int64(len(blob))}, nil
}
