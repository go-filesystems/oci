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
// The values are package variables so the test suite can lower them with small
// inputs; callers choose their own budget per image through Limits and
// OpenSelectLimits / TarballLimits.
var (
	// maxBlobSize bounds a single raw (still-compressed) layer blob. The OCI
	// descriptor's Size field is digest-verified for content blobs, so this
	// only needs to defend the read itself against a blob that streams more
	// bytes than the source promised. 4 GiB.
	maxBlobSize int64 = 4 << 30

	// maxLayerUncompressed bounds the cumulative *uncompressed* bytes of the
	// regular files of a single layer. This is the decompression-bomb guard: a
	// tiny gzip descriptor that expands to terabytes is cut off here. 8 GiB.
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

	// maxManifestSize bounds a manifest, an image index, index.json and a
	// docker-save manifest.json. The OCI distribution spec asks clients and
	// registries to support manifests "of at least 4 megabytes" (section on
	// the manifest size limit); 16 MiB leaves headroom while keeping the JSON
	// decoder to a few hundred MiB at worst. Before this limit these were read
	// up to maxBlobSize (4 GiB) and index.json with an unbounded os.ReadFile.
	maxManifestSize int64 = 16 << 20

	// maxLayerStream bounds the decompressed tar stream of one layer (headers,
	// padding and bodies, and the data of entries we skip). Without it a gzip
	// layer could make us inflate terabytes just to skip an unknown entry. 16 GiB.
	maxLayerStream int64 = 16 << 30

	// maxImageUncompressed bounds the cumulative regular-file bytes buffered
	// across ALL layers of one image (maxLayerUncompressed only bounds one). 16 GiB.
	maxImageUncompressed int64 = 16 << 30

	// maxSparseHoles bounds how many bytes a layer may claim beyond the bytes it
	// actually carries. A PAX/GNU sparse file reads back as zeros for its holes
	// without storing them: 199 bytes of gzip declared a 1 GiB file and
	// allocated 1 GiB. Docker never emits sparse members, so this is small. 64 MiB.
	maxSparseHoles int64 = 64 << 20

	// maxMetadata bounds the names and link targets kept in the tree (the
	// bytes of every entry name and link target, cumulative over the image).
	// A 2 KiB gzip layer holding one 1 MiB PAX path used to cost 191 MB. 512 MiB.
	maxMetadata int64 = 512 << 20

	// maxEntries bounds the nodes created in the merged tree (files, dirs and
	// the directories implied by a path), cumulative over the image. A node
	// costs about 1.1 KB while the layer is decoded (measured), so 2 Mi nodes
	// is a couple of GiB at worst; real images are two orders of magnitude below.
	maxEntries int64 = 2 << 20

	// maxPathLen bounds an entry name and a link target in bytes: PATH_MAX on
	// Linux (limits.h, 4096). Longer is not a path any kernel can hold; the
	// bound also caps the directory depth of the tree.
	maxPathLen = 4096

	// maxLayers bounds the number of layers of one image. Docker's overlay2
	// driver stops at 128; 1024 is far above any real image.
	maxLayers = 1024

	// maxIndexDepth bounds index-of-index nesting while resolving a manifest.
	maxIndexDepth = 16

	// maxHardlinkDepth bounds how many hardlink-to-hardlink hops are followed
	// before declaring a cycle. Legitimate images never chain hardlinks; any
	// chain at all is suspicious, so a small bound is safe.
	maxHardlinkDepth = 40
)

// Limits is the resource budget for opening one untrusted image. A zero field
// takes the package default (see DefaultLimits); a negative one refuses
// everything of that kind. Pass it to OpenSelectLimits or TarballLimits.
type Limits struct {
	// MaxBlob bounds one raw (compressed) layer blob, in bytes.
	MaxBlob int64
	// MaxManifest bounds a manifest, index, index.json or manifest.json.
	MaxManifest int64
	// MaxLayerUncompressed bounds the regular-file bytes of one layer.
	MaxLayerUncompressed int64
	// MaxImageUncompressed bounds the regular-file bytes of the whole image.
	MaxImageUncompressed int64
	// MaxFile bounds one regular file.
	MaxFile int64
	// MaxLayerStream bounds the decompressed tar stream of one layer.
	MaxLayerStream int64
	// MaxSparseHoles bounds the bytes a layer may claim beyond what it carries.
	MaxSparseHoles int64
	// MaxMetadata bounds the names and link targets of the whole image.
	MaxMetadata int64
	// MaxEntries bounds the nodes of the merged tree.
	MaxEntries int64
	// MaxPathLen bounds one entry name or link target, in bytes.
	MaxPathLen int
	// MaxLayers bounds the number of layers.
	MaxLayers int
	// MaxIndexDepth bounds index-of-index nesting.
	MaxIndexDepth int
	// MaxArchiveMember bounds one member of a docker-save / OCI archive.
	MaxArchiveMember int64
	// MaxArchiveTotal bounds all the members of an archive together.
	MaxArchiveTotal int64
}

// DefaultLimits returns the default budget: generous for real images,
// finite for hostile ones.
func DefaultLimits() Limits {
	return Limits{
		MaxBlob:              maxBlobSize,
		MaxManifest:          maxManifestSize,
		MaxLayerUncompressed: maxLayerUncompressed,
		MaxImageUncompressed: maxImageUncompressed,
		MaxFile:              maxFileSize,
		MaxLayerStream:       maxLayerStream,
		MaxSparseHoles:       maxSparseHoles,
		MaxMetadata:          maxMetadata,
		MaxEntries:           maxEntries,
		MaxPathLen:           maxPathLen,
		MaxLayers:            maxLayers,
		MaxIndexDepth:        maxIndexDepth,
		MaxArchiveMember:     maxArchiveMember,
		MaxArchiveTotal:      maxArchiveTotal,
	}
}

// resolve fills every zero field with its default.
func (l Limits) resolve() Limits {
	d := DefaultLimits()
	if l.MaxBlob == 0 {
		l.MaxBlob = d.MaxBlob
	}
	if l.MaxManifest == 0 {
		l.MaxManifest = d.MaxManifest
	}
	if l.MaxLayerUncompressed == 0 {
		l.MaxLayerUncompressed = d.MaxLayerUncompressed
	}
	if l.MaxImageUncompressed == 0 {
		l.MaxImageUncompressed = d.MaxImageUncompressed
	}
	if l.MaxFile == 0 {
		l.MaxFile = d.MaxFile
	}
	if l.MaxLayerStream == 0 {
		l.MaxLayerStream = d.MaxLayerStream
	}
	if l.MaxSparseHoles == 0 {
		l.MaxSparseHoles = d.MaxSparseHoles
	}
	if l.MaxMetadata == 0 {
		l.MaxMetadata = d.MaxMetadata
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxPathLen == 0 {
		l.MaxPathLen = d.MaxPathLen
	}
	if l.MaxLayers == 0 {
		l.MaxLayers = d.MaxLayers
	}
	if l.MaxIndexDepth == 0 {
		l.MaxIndexDepth = d.MaxIndexDepth
	}
	if l.MaxArchiveMember == 0 {
		l.MaxArchiveMember = d.MaxArchiveMember
	}
	if l.MaxArchiveTotal == 0 {
		l.MaxArchiveTotal = d.MaxArchiveTotal
	}
	return l
}

// tooLarge builds the sentinel error every limit returns.
func tooLarge(format string, args ...any) error {
	return fmt.Errorf("oci: %s: %w", fmt.Sprintf(format, args...), safeio.ErrTooLarge)
}

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

// countingReader counts the bytes read through it and fails closed with
// safeio.ErrTooLarge once more than max have passed. It sits UNDER the tar
// reader, so n is the physical position in the (decompressed) stream: the
// sparse-hole check compares it with the logical bytes the tar reader hands
// back.
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	// Read at most one byte past the bound: that byte proves an overrun and is
	// withheld, so a caller that fills its buffer with io.ReadFull (the tar
	// reader does) still sees the error instead of swallowing it.
	room := c.max - c.n + 1
	if room <= 0 {
		return 0, tooLarge("decompressed stream exceeds %d bytes", c.max)
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	k, err := c.r.Read(p)
	c.n += int64(k)
	if c.n > c.max {
		return k - 1, tooLarge("decompressed stream exceeds %d bytes", c.max)
	}
	return k, err
}

// holeGuard wraps a regular file's body and fails closed when the logical bytes
// read so far (everything already folded plus this file) exceed the physical
// stream position by more than max: the excess is holes a sparse member claims
// without carrying.
type holeGuard struct {
	r    io.Reader
	phys *countingReader
	base int64 // logical file bytes folded before this file
	read int64 // logical bytes read from this file
	max  int64
}

func (h *holeGuard) Read(p []byte) (int, error) {
	k, err := h.r.Read(p)
	h.read += int64(k)
	if h.base+h.read-h.phys.n > h.max {
		return k, tooLarge("sparse member claims more than %d bytes beyond the stream", h.max)
	}
	return k, err
}
