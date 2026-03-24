/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageScanSpec defines the desired state of ImageScan.
type ImageScanSpec struct {
	// image is the full image reference (e.g. nginx:1.25.3)
	// +required
	Image string `json:"image"`

	// digest is the image digest (e.g. sha256:abc123...)
	// +optional
	Digest string `json:"digest,omitempty"`

	// sourceNamespace is the namespace of the pod that triggered this scan
	// +required
	SourceNamespace string `json:"sourceNamespace"`

	// sourcePod is the name of the pod that triggered this scan
	// +required
	SourcePod string `json:"sourcePod"`
}

// ImageScanStatus defines the observed state of ImageScan.
type ImageScanStatus struct {
	// phase indicates the current scan phase: Pending, Scanning, Completed, Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// lastScanTime is the timestamp of the last scan
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// summary contains vulnerability counts by severity
	// +optional
	Summary *VulnSummary `json:"summary,omitempty"`

	// vulnerabilities contains the list of discovered vulnerabilities
	// +optional
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// VulnSummary contains vulnerability counts grouped by severity.
type VulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Vulnerability represents a single vulnerability found in an image.
type Vulnerability struct {
	// id is the CVE identifier (e.g. CVE-2024-12345)
	ID string `json:"id"`
	// severity is the vulnerability severity (Critical, High, Medium, Low, Unknown)
	Severity string `json:"severity"`
	// pkg is the affected package name
	Package string `json:"package"`
	// version is the installed package version
	Version string `json:"version"`
	// fixedIn is the version that fixes this vulnerability
	// +optional
	FixedIn string `json:"fixedIn,omitempty"`
}

// Scan phase constants.
const (
	PhasePending   = "Pending"
	PhaseScanning  = "Scanning"
	PhaseCompleted = "Completed"
	PhaseFailed    = "Failed"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.high`
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.status.summary.medium`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageScan is the Schema for the imagescans API.
type ImageScan struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ImageScanSpec `json:"spec"`

	// +optional
	Status ImageScanStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ImageScanList contains a list of ImageScan
type ImageScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImageScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageScan{}, &ImageScanList{})
}
