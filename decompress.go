// Package oci presents an OCI/Docker image as a read-only
// github.com/go-filesystems/interface Filesystem by overlaying the image's
// tar layers with overlayfs semantics. It is pure Go (CGO_ENABLED=0) and
// pulls no third-party dependencies for its core: gzip and plain layers are
// handled by the standard library, and any other compression (e.g. zstd) is
// supported through an injectable Decompressor registry.
package oci

import (
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Decompressor wraps a raw layer blob reader and returns a reader that yields
// the decompressed tar stream. Implementations must not assume ownership of r;
// closing the underlying blob is the caller's responsibility.
type Decompressor func(r io.Reader) (io.Reader, error)

var (
	decompMu      sync.RWMutex
	decompressors = map[string]Decompressor{}
)

// Built-in OCI / Docker layer media types.
const (
	// Uncompressed tar layers.
	MediaTypeLayerTar       = "application/vnd.oci.image.layer.v1.tar"
	MediaTypeDockerLayerTar = "application/vnd.docker.image.rootfs.diff.tar"

	// gzip-compressed tar layers.
	MediaTypeLayerTarGzip       = "application/vnd.oci.image.layer.v1.tar+gzip"
	MediaTypeDockerLayerTarGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"

	// zstd-compressed tar layers (no built-in decompressor; register one).
	MediaTypeLayerTarZstd = "application/vnd.oci.image.layer.v1.tar+zstd"

	// Manifest / index media types we resolve.
	MediaTypeImageManifest      = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeImageIndex         = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeImageConfig        = "application/vnd.oci.image.config.v1+json"
	MediaTypeDockerImageConfig  = "application/vnd.docker.container.image.v1+json"
)

func init() {
	plain := func(r io.Reader) (io.Reader, error) { return r, nil }
	RegisterDecompressor(MediaTypeLayerTar, plain)
	RegisterDecompressor(MediaTypeDockerLayerTar, plain)

	gz := func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }
	RegisterDecompressor(MediaTypeLayerTarGzip, gz)
	RegisterDecompressor(MediaTypeDockerLayerTarGzip, gz)
}

// RegisterDecompressor registers d for the given layer media type, replacing
// any previous registration. Pass a media type such as
// MediaTypeLayerTarZstd to enable zstd without a core dependency.
func RegisterDecompressor(mediaType string, d Decompressor) {
	decompMu.Lock()
	defer decompMu.Unlock()
	decompressors[mediaType] = d
}

// lookupDecompressor returns the Decompressor for mediaType. The media type is
// matched exactly; a trailing parameter list (e.g. "...+gzip; foo=bar") is
// stripped before lookup to tolerate annotated manifests.
func lookupDecompressor(mediaType string) (Decompressor, error) {
	mt := strings.TrimSpace(mediaType)
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	decompMu.RLock()
	d, ok := decompressors[mt]
	decompMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("oci: no decompressor registered for layer media type %q", mediaType)
	}
	return d, nil
}
