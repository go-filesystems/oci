package oci

import (
	"encoding/json"
	"fmt"
	"io"
)

// descriptor mirrors an OCI content descriptor (subset we use).
type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// index mirrors an OCI image index / docker manifest list.
type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
}

// manifest mirrors an OCI image manifest / docker schema2 manifest.
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

// Selector picks one manifest from a multi-manifest index.
type Selector struct {
	// Digest, if non-empty, selects the manifest descriptor whose digest
	// matches exactly.
	Digest string
	// OS / Architecture / Variant, if set, select by platform. Empty fields
	// are treated as wildcards.
	OS           string
	Architecture string
	Variant      string
}

func (s Selector) matches(d descriptor) bool {
	if s.Digest != "" {
		return d.Digest == s.Digest
	}
	if s.OS == "" && s.Architecture == "" && s.Variant == "" {
		return true
	}
	p := d.Platform
	if p == nil {
		return false
	}
	if s.OS != "" && s.OS != p.OS {
		return false
	}
	if s.Architecture != "" && s.Architecture != p.Architecture {
		return false
	}
	if s.Variant != "" && s.Variant != p.Variant {
		return false
	}
	return true
}

func isIndexMediaType(mt string) bool {
	return mt == MediaTypeImageIndex || mt == MediaTypeDockerManifestList
}

func isManifestMediaType(mt string) bool {
	return mt == MediaTypeImageManifest || mt == MediaTypeDockerManifest
}

// resolveManifest walks an index/manifest blob tree starting at the top-level
// descriptor and returns the concrete image manifest selected by sel.
func resolveManifest(src BlobSource, top descriptor, sel Selector) (*manifest, error) {
	rc, err := src.Blob(top.Digest)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("oci: reading %s: %w", top.Digest, err)
	}
	if err := verifyDigest(top.Digest, data); err != nil {
		return nil, err
	}

	// Sniff: a manifest has a non-empty "config" object; an index has
	// "manifests". Prefer the declared mediaType when present.
	mt := top.MediaType
	if mt == "" {
		var probe struct {
			MediaType string          `json:"mediaType"`
			Config    json.RawMessage `json:"config"`
			Manifests json.RawMessage `json:"manifests"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			return nil, fmt.Errorf("oci: parsing %s: %w", top.Digest, err)
		}
		switch {
		case probe.MediaType != "":
			mt = probe.MediaType
		case len(probe.Manifests) > 0:
			mt = MediaTypeImageIndex
		case len(probe.Config) > 0:
			mt = MediaTypeImageManifest
		default:
			return nil, fmt.Errorf("oci: cannot classify descriptor %s", top.Digest)
		}
	}

	switch {
	case isIndexMediaType(mt):
		var idx index
		if err := json.Unmarshal(data, &idx); err != nil {
			return nil, fmt.Errorf("oci: parsing index %s: %w", top.Digest, err)
		}
		for _, d := range idx.Manifests {
			if isIndexMediaType(d.MediaType) || isManifestMediaType(d.MediaType) || d.MediaType == "" {
				if sel.matches(d) {
					return resolveManifest(src, d, sel)
				}
			}
		}
		return nil, fmt.Errorf("oci: no manifest in index %s matches selector %+v", top.Digest, sel)
	case isManifestMediaType(mt):
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("oci: parsing manifest %s: %w", top.Digest, err)
		}
		if len(m.Layers) == 0 {
			return nil, fmt.Errorf("oci: manifest %s has no layers", top.Digest)
		}
		return &m, nil
	default:
		return nil, fmt.Errorf("oci: unsupported descriptor media type %q for %s", mt, top.Digest)
	}
}

// readIndexJSON parses the top-level index.json bytes (OCI layout) or an
// in-archive index.json.
func readIndexJSON(data []byte) (*index, error) {
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("oci: parsing index.json: %w", err)
	}
	if len(idx.Manifests) == 0 {
		return nil, fmt.Errorf("oci: index.json has no manifests")
	}
	return &idx, nil
}

// dockerSaveManifest mirrors the top-level manifest.json produced by
// `docker save`.
type dockerSaveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}
