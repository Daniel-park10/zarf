// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package mediatype provides media type constants and predicate helpers for OCI and Docker images.
package mediatype

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// DockerMediaTypeManifest is the legacy Docker manifest format, replaced by OCI manifest.
	DockerMediaTypeManifest = "application/vnd.docker.distribution.manifest.v2+json"
	// DockerMediaTypeManifestList is the legacy Docker manifest list, replaced by OCI index.
	DockerMediaTypeManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// IsManifest reports whether the media type represents an OCI manifest or legacy Docker manifest.
func IsManifest(mediaType string) bool {
	switch mediaType {
	case ocispec.MediaTypeImageManifest, DockerMediaTypeManifest:
		return true
	}
	return false
}

// IsIndex reports whether the media type represents an OCI image index or legacy Docker manifest list.
func IsIndex(mediaType string) bool {
	switch mediaType {
	case ocispec.MediaTypeImageIndex, DockerMediaTypeManifestList:
		return true
	}
	return false
}
