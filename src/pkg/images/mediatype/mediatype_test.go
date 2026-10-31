// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package mediatype

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestIsManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mediaType string
		expected  bool
	}{
		{
			name:      "OCI image manifest",
			mediaType: ocispec.MediaTypeImageManifest,
			expected:  true,
		},
		{
			name:      "legacy Docker manifest",
			mediaType: DockerMediaTypeManifest,
			expected:  true,
		},
		{
			name:      "OCI image index",
			mediaType: ocispec.MediaTypeImageIndex,
			expected:  false,
		},
		{
			name:      "legacy Docker manifest list",
			mediaType: DockerMediaTypeManifestList,
			expected:  false,
		},
		{
			name:      "OCI image config",
			mediaType: ocispec.MediaTypeImageConfig,
			expected:  false,
		},
		{
			name:      "OCI layer gzip",
			mediaType: ocispec.MediaTypeImageLayerGzip,
			expected:  false,
		},
		{
			name:      "empty media type",
			mediaType: "",
			expected:  false,
		},
		{
			name:      "whitespace media type",
			mediaType: "   ",
			expected:  false,
		},
		{
			name:      "arbitrary media type",
			mediaType: "application/json",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, IsManifest(tt.mediaType))
		})
	}
}

func TestIsIndex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mediaType string
		expected  bool
	}{
		{
			name:      "OCI image index",
			mediaType: ocispec.MediaTypeImageIndex,
			expected:  true,
		},
		{
			name:      "legacy Docker manifest list",
			mediaType: DockerMediaTypeManifestList,
			expected:  true,
		},
		{
			name:      "OCI image manifest",
			mediaType: ocispec.MediaTypeImageManifest,
			expected:  false,
		},
		{
			name:      "legacy Docker manifest",
			mediaType: DockerMediaTypeManifest,
			expected:  false,
		},
		{
			name:      "OCI image config",
			mediaType: ocispec.MediaTypeImageConfig,
			expected:  false,
		},
		{
			name:      "OCI layer gzip",
			mediaType: ocispec.MediaTypeImageLayerGzip,
			expected:  false,
		},
		{
			name:      "empty media type",
			mediaType: "",
			expected:  false,
		},
		{
			name:      "whitespace media type",
			mediaType: "   ",
			expected:  false,
		},
		{
			name:      "arbitrary media type",
			mediaType: "text/plain",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, IsIndex(tt.mediaType))
		})
	}
}
