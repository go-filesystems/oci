<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems.png" alt="go-filesystems/oci" width="720"></p>

# oci

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/oci.svg)](https://pkg.go.dev/github.com/go-filesystems/oci)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/oci/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/oci/actions/workflows/ci.yml)

Pure-Go, read-only **OCI / Docker image filesystem** for the
[go-filesystems](https://github.com/go-filesystems) family. It overlays an
image's tar layers — honouring whiteouts, opaque directories, hardlinks and
symlinks — and serves the merged rootfs through
[`go-filesystems/interface`](https://github.com/go-filesystems/interface). No
container runtime, no cgo.

## Why

A container image *is* a filesystem: an ordered stack of tar layers that overlay
into a rootfs. This driver reads that rootfs natively — to `mkfs` it into an
ext4 image, serve it read-only over virtio-fs, or inspect it — without pulling
in containerd, a runtime, or any C toolchain.

## Install

```sh
go get github.com/go-filesystems/oci
```

## Usage

```go
import "github.com/go-filesystems/oci"

// From an OCI image layout directory…
fsys, err := oci.OpenLayout("path/to/oci-layout")
// …or a `docker save` / OCI archive tarball:
//   fsys, err := oci.OpenTarball("image.tar")
if err != nil {
    return err
}
defer fsys.Close()

data, err := fsys.ReadFile("/etc/os-release")
entries, err := fsys.ListDir("/usr/bin")
st, err := fsys.Stat("/bin/sh")
target, err := fsys.ReadLink("/bin/sh") // if it is a symlink
```

`fsys` satisfies `filesystem.Filesystem`. For a multi-arch index, select a
manifest with `OpenSelect`/`OpenDescriptor`; to read from a custom blob store,
implement `BlobSource` and call `Open`.

The image is **read only**: `WriteFile`, `MkDir`, `DeleteFile`, `DeleteDir` and
`Rename` return `ErrReadOnly`.

## Layer compression

`gzip` and uncompressed layers are built in (stdlib only). Other codecs are
opt-in with no extra dependency — register them yourself:

```go
oci.RegisterDecompressor(oci.MediaTypeLayerTarZstd, func(r io.Reader) (io.Reader, error) {
    return zstd.NewReader(r) // your pure-Go zstd of choice
})
```

## Untrusted input

An image is untrusted input: a few hundred bytes of gzip can declare a layer that
expands to gigabytes, and a tar header costs far more memory than its 512 bytes.
Every input-driven allocation is bounded **before** it happens, and exceeding a
bound returns an error wrapping `safeio.ErrTooLarge`. Defaults (`DefaultLimits()`):

| Bound | Default | Why |
| --- | --- | --- |
| manifest, index, `index.json`, `manifest.json` | 16 MiB | the distribution spec asks for at least 4 MB |
| raw layer blob | 4 GiB | |
| regular-file bytes: per file / per layer / whole image | 4 GiB / 8 GiB / 16 GiB | decompression bomb |
| decompressed tar stream of one layer | 16 GiB | headers and skipped entries count |
| bytes a layer claims beyond what it carries (sparse holes) | 64 MiB | 199 bytes of gzip declared 1 GiB |
| tree nodes (files, directories, implied directories) | 2 Mi | a node costs about 1.1 KB |
| names and link targets, whole image | 512 MiB | a 2 KiB layer held a 1 MiB path |
| one path or link target | 4096 bytes | Linux `PATH_MAX` |
| layers / index nesting | 1024 / 16 | |

Open an image with tighter ceilings:

```go
src, err := oci.TarballLimits("image.tar", oci.Limits{MaxArchiveTotal: 1 << 30})
img, err := oci.OpenSelectLimits(src, oci.Selector{}, oci.Limits{
    MaxImageUncompressed: 1 << 30,
    MaxEntries:           200_000,
})
```

A zero `Limits` field takes its default. Digests name a directory in an OCI
layout (`blobs/<alg>/<hex>`), so an algorithm outside the image-spec grammar
(`../..`) is rejected rather than followed. `FuzzApplyLayer` and `FuzzOpenTarball`
exercise the layer folder and the archive reader.

## License

BSD-3-Clause © the go-filesystems/oci authors.
