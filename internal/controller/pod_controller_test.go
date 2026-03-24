package controller

import (
	"strings"
	"testing"
)

func TestExtractDigest(t *testing.T) {
	tests := []struct {
		name     string
		imageID  string
		expected string
	}{
		{
			name:     "docker-pullable format",
			imageID:  "docker-pullable://registry.example.com/nginx@sha256:abc123def456789",
			expected: "sha256:abc123def456789",
		},
		{
			name:     "just sha256",
			imageID:  "sha256:abc123def456789",
			expected: "sha256:abc123def456789",
		},
		{
			name:     "no digest",
			imageID:  "registry.example.com/nginx:latest",
			expected: "",
		},
		{
			name:     "empty string",
			imageID:  "",
			expected: "",
		},
		{
			name:     "docker.io format",
			imageID:  "docker.io/library/nginx@sha256:abcdef1234567890abcdef1234567890",
			expected: "sha256:abcdef1234567890abcdef1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDigest(tt.imageID)
			if got != tt.expected {
				t.Errorf("extractDigest(%q) = %q, want %q", tt.imageID, got, tt.expected)
			}
		})
	}
}

func TestImageScanName(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		digest   string
		expected string
	}{
		{
			name:     "standard image with digest",
			image:    "nginx:1.25",
			digest:   "sha256:abcdef123456789",
			expected: "scan-nginx-1-25-abcdef123456",
		},
		{
			name:     "image with registry",
			image:    "registry.io/myapp:v1.0",
			digest:   "sha256:fedcba987654321",
			expected: "scan-registry-io-myapp-v1-0-fedcba987654",
		},
		{
			name:     "no digest",
			image:    "myapp:latest",
			digest:   "",
			expected: "scan-myapp-latest-unknown",
		},
		{
			name:     "short digest",
			image:    "app:v1",
			digest:   "sha256:abc",
			expected: "scan-app-v1-unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := imageScanName(tt.image, tt.digest)
			if got != tt.expected {
				t.Errorf("imageScanName(%q, %q) = %q, want %q", tt.image, tt.digest, got, tt.expected)
			}
		})
	}
}

func TestImageScanName_LongImageTruncated(t *testing.T) {
	// Create an image name longer than 230 chars
	longImage := strings.Repeat("a", 250)
	name := imageScanName(longImage, "sha256:abcdef123456789")
	// scan- (5) + 230 + - (1) + 12 = 248, well under 253
	if len(name) > 253 {
		t.Errorf("expected name <= 253 chars, got %d", len(name))
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple image",
			input:    "nginx:1.25",
			expected: "nginx_1.25",
		},
		{
			name:     "image with registry",
			input:    "registry.io/myapp:v1",
			expected: "registry.io_myapp_v1",
		},
		{
			name:     "long string truncated",
			input:    "this-is-a-very-long-image-name-that-exceeds-the-sixty-three-character-limit-for-labels",
			expected: "this-is-a-very-long-image-name-that-exceeds-the-sixty-three-cha",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeLabel(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeLabel(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsNamespaceExcluded(t *testing.T) {
	r := &PodReconciler{
		ExcludeNamespaces: []string{"kube-system", "gke-*", "kube-*"},
	}

	tests := []struct {
		namespace string
		excluded  bool
	}{
		{"kube-system", true},
		{"gke-managed-system", true},
		{"kube-node-lease", true},
		{"default", false},
		{"production", false},
		{"monitoring", false},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := r.isNamespaceExcluded(tt.namespace)
			if got != tt.excluded {
				t.Errorf("isNamespaceExcluded(%q) = %v, want %v", tt.namespace, got, tt.excluded)
			}
		})
	}
}

func TestIsImageExcluded(t *testing.T) {
	r := &PodReconciler{
		ExcludeImages: []string{"*nvidia-driver-installer*", "*gke-metrics-agent*"},
	}

	tests := []struct {
		image    string
		excluded bool
	}{
		{"gke-nvidia-driver-installer:latest", true},
		{"gke-metrics-agent:v1", true},
		{"nginx:1.25", false},
		{"myapp:latest", false},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got := r.isImageExcluded(tt.image)
			if got != tt.excluded {
				t.Errorf("isImageExcluded(%q) = %v, want %v", tt.image, got, tt.excluded)
			}
		})
	}
}

func TestIsNamespaceExcluded_Empty(t *testing.T) {
	r := &PodReconciler{
		ExcludeNamespaces: nil,
	}
	if r.isNamespaceExcluded("anything") {
		t.Error("expected no exclusion with empty list")
	}
}

func TestIsImageExcluded_Empty(t *testing.T) {
	r := &PodReconciler{
		ExcludeImages: nil,
	}
	if r.isImageExcluded("anything:latest") {
		t.Error("expected no exclusion with empty list")
	}
}
