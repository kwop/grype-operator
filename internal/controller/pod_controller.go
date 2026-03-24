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

package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kwop/grype-operator/api/v1alpha1"
	"github.com/kwop/grype-operator/internal/cache"
	appmetrics "github.com/kwop/grype-operator/internal/metrics"
)

// PodReconciler watches Pod events and creates ImageScan CRDs for new images.
type PodReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Cache             *cache.ImageCache
	ExcludeNamespaces []string
	ExcludeImages     []string
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile handles Pod create/update events.
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Filter excluded namespaces
	if r.isNamespaceExcluded(req.Namespace) {
		return ctrl.Result{}, nil
	}

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only process running pods with resolved image digests
	if pod.Status.Phase != corev1.PodRunning {
		return ctrl.Result{}, nil
	}

	// Extract images from container statuses (they contain the resolved digest)
	for _, cs := range pod.Status.ContainerStatuses {
		imageRef := cs.Image
		imageID := cs.ImageID

		if r.isImageExcluded(imageRef) {
			continue
		}

		// Extract digest from imageID (format: docker-pullable://repo@sha256:...)
		digest := extractDigest(imageID)

		// Skip if recently scanned
		if !r.Cache.ShouldScan(digest) {
			continue
		}

		// Create a deterministic name for the ImageScan based on digest
		scanName := imageScanName(imageRef, digest)

		// Check if ImageScan already exists
		var existing securityv1alpha1.ImageScan
		err := r.Get(ctx, types.NamespacedName{Name: scanName, Namespace: req.Namespace}, &existing)
		if err == nil {
			// Already exists, skip
			continue
		}
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		// Create new ImageScan
		scan := &securityv1alpha1.ImageScan{
			ObjectMeta: metav1.ObjectMeta{
				Name:      scanName,
				Namespace: req.Namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "grype-operator",
					"grype-operator/image":         sanitizeLabel(imageRef),
				},
			},
			Spec: securityv1alpha1.ImageScanSpec{
				Image:           imageRef,
				Digest:          digest,
				SourceNamespace: req.Namespace,
				SourcePod:       pod.Name,
			},
		}

		if err := r.Create(ctx, scan); err != nil {
			if errors.IsAlreadyExists(err) {
				continue
			}
			log.Error(err, "failed to create ImageScan", "image", imageRef)
			return ctrl.Result{}, err
		}

		// Set initial status to Pending
		scan.Status.Phase = securityv1alpha1.PhasePending
		if err := r.Status().Update(ctx, scan); err != nil {
			log.Error(err, "failed to set initial status", "image", imageRef)
			return ctrl.Result{}, err
		}

		appmetrics.ImagesScanned.Inc()
		log.Info("created ImageScan", "image", imageRef, "digest", digest, "pod", pod.Name)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod-watcher").
		Complete(r)
}

func (r *PodReconciler) isNamespaceExcluded(ns string) bool {
	for _, pattern := range r.ExcludeNamespaces {
		if matched, _ := filepath.Match(pattern, ns); matched {
			return true
		}
	}
	return false
}

func (r *PodReconciler) isImageExcluded(image string) bool {
	for _, pattern := range r.ExcludeImages {
		if matched, _ := filepath.Match(pattern, image); matched {
			return true
		}
	}
	return false
}

// extractDigest extracts sha256 digest from imageID.
// imageID format: docker-pullable://registry/repo@sha256:abcdef...
func extractDigest(imageID string) string {
	if idx := strings.Index(imageID, "sha256:"); idx >= 0 {
		return imageID[idx:]
	}
	return ""
}

// imageScanName generates a deterministic CRD name from image and digest.
func imageScanName(image, digest string) string {
	// Use last 12 chars of digest for uniqueness
	suffix := "unknown"
	if len(digest) > 19 {
		suffix = digest[7:19] // skip "sha256:" prefix, take 12 chars
	}
	// Sanitize image name for k8s naming
	name := strings.ReplaceAll(image, "/", "-")
	name = strings.ReplaceAll(name, ":", "-")
	name = strings.ReplaceAll(name, ".", "-")
	// Truncate to fit k8s name limit (253 chars)
	if len(name) > 230 {
		name = name[:230]
	}
	return fmt.Sprintf("scan-%s-%s", name, suffix)
}

// sanitizeLabel makes a string safe for use as a Kubernetes label value.
func sanitizeLabel(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
