package oci

import (
	"fmt"
	"io"

	"github.com/go-volumes/safeio"
)

// Hardening ceilings for parsing UNTRUSTED OCI images. A malicious or corrupt
// image must never OOM the host, recurse without bound, or buffer an
// arbitrarily large decompression bomb. These defaults are deliberately
// generous for legitimate disk-image-as-filesystem use (gigabyte-scale
// uncompressed layers are fine) while still being finite.
//
// The values are package variables rather than constants so that a caller with
// a different threat budget can lower (or raise) them before opening an image;
// they are read, never written, by the parsing paths.
var (
	// maxBlobSize bounds a single raw (still-compressed) layer/manifest blob.
	// The OCI descriptor's Size field is digest-verified for content blobs, so
	// this only needs to defend the read itself against a blob that streams
	// more bytes than the source promised. 4 GiB.
	maxBlobSize int64 = 4 << 30

	// maxLayerUncompressed bounds the cumulative *uncompressed* bytes of a
	// single layer tar stream. This is the decompression-bomb guard: a tiny
	// gzip descriptor that expands to terabytes is cut off here. 8 GiB.
	maxLayerUncompressed int64 = 8 << 30

	// maxFileSize bounds a single regular file's buffered contents within a
	// layer. 4 GiB.
	maxFileSize int64 = 4 << 30

	// maxArchiveMember bounds a single member of a docker-save / OCI archive
	// tar (config, manifest, layer.tar). 4 GiB.
	maxArchiveMember int64 = 4 << 30

	// maxArchiveTotal bounds the cumulative size of all indexed archive
	// members. 16 GiB.
	maxArchiveTotal int64 = 16 << 30

	// maxHardlinkDepth bounds how many hardlink-to-hardlink hops are followed
	// before declaring a cycle. Legitimate images never chain hardlinks; any
	// chain at all is suspicious, so a small bound is safe.
	maxHardlinkDepth = 40
)

// readAllCapped reads from r into a buffer, failing closed with
// safeio.ErrTooLarge once more than limit bytes are available. It reads up to
// limit+1 bytes and rejects when the source overruns, so a blob that streams
// more than its digest-verified descriptor promised cannot OOM the host. what
// names the blob for the error message.
func readAllCapped(r io.Reader, limit int64, what string) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("oci: %s: %w", what, safeio.ErrTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("oci: reading %s: %w", what, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("oci: %s: blob exceeds %d bytes: %w", what, limit, safeio.ErrTooLarge)
	}
	return data, nil
}
