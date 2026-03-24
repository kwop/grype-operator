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
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kwop/grype-operator/api/v1alpha1"
	"github.com/kwop/grype-operator/internal/cache"
	appmetrics "github.com/kwop/grype-operator/internal/metrics"
	"github.com/kwop/grype-operator/internal/scanner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ImageScanReconciler reconciles ImageScan objects by running Grype scans.
type ImageScanReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Scanner *scanner.Scanner
	Cache   *cache.ImageCache
}

// +kubebuilder:rbac:groups=security.paramedic.tech,resources=imagescans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.paramedic.tech,resources=imagescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.paramedic.tech,resources=imagescans/finalizers,verbs=update

// Reconcile processes ImageScan resources: picks up Pending scans, runs Grype, updates status.
func (r *ImageScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var scan securityv1alpha1.ImageScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only process Pending scans
	if scan.Status.Phase != securityv1alpha1.PhasePending {
		return ctrl.Result{}, nil
	}

	// Check cache — skip if recently scanned
	if !r.Cache.ShouldScan(scan.Spec.Digest) {
		log.V(1).Info("skipping scan, image recently scanned", "digest", scan.Spec.Digest)
		scan.Status.Phase = securityv1alpha1.PhaseCompleted
		now := metav1.Now()
		scan.Status.LastScanTime = &now
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Mark as Scanning
	scan.Status.Phase = securityv1alpha1.PhaseScanning
	if err := r.Status().Update(ctx, &scan); err != nil {
		return ctrl.Result{}, err
	}

	// Run the Grype scan
	log.Info("scanning image", "image", scan.Spec.Image)
	start := time.Now()

	imageRef := scan.Spec.Image
	if scan.Spec.Digest != "" {
		imageRef = scan.Spec.Digest
	}

	vulns, summary, err := r.Scanner.Scan(ctx, imageRef)
	duration := time.Since(start).Seconds()

	appmetrics.ScanDuration.WithLabelValues(scan.Spec.Image).Observe(duration)

	if err != nil {
		log.Error(err, "scan failed", "image", scan.Spec.Image)
		scan.Status.Phase = securityv1alpha1.PhaseFailed
		now := metav1.Now()
		scan.Status.LastScanTime = &now
		if updateErr := r.Status().Update(ctx, &scan); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		appmetrics.ScansTotal.WithLabelValues("failed").Inc()
		// Retry after 5 minutes
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	// Update status with results
	now := metav1.Now()
	scan.Status.Phase = securityv1alpha1.PhaseCompleted
	scan.Status.LastScanTime = &now
	scan.Status.Summary = &securityv1alpha1.VulnSummary{
		Critical: summary.Critical,
		High:     summary.High,
		Medium:   summary.Medium,
		Low:      summary.Low,
		Unknown:  summary.Unknown,
	}

	scan.Status.Vulnerabilities = make([]securityv1alpha1.Vulnerability, len(vulns))
	for i, v := range vulns {
		scan.Status.Vulnerabilities[i] = securityv1alpha1.Vulnerability{
			ID:       v.ID,
			Severity: v.Severity,
			Package:  v.Package,
			Version:  v.Version,
			FixedIn:  v.FixedIn,
		}
	}

	if err := r.Status().Update(ctx, &scan); err != nil {
		return ctrl.Result{}, err
	}

	// Update cache and metrics
	r.Cache.MarkScanned(scan.Spec.Digest)
	appmetrics.ScansTotal.WithLabelValues("completed").Inc()
	appmetrics.CacheSize.Set(float64(r.Cache.Size()))

	ns := scan.Spec.SourceNamespace
	img := scan.Spec.Image
	appmetrics.VulnerabilitiesTotal.WithLabelValues(img, ns, "Critical").Set(float64(summary.Critical))
	appmetrics.VulnerabilitiesTotal.WithLabelValues(img, ns, "High").Set(float64(summary.High))
	appmetrics.VulnerabilitiesTotal.WithLabelValues(img, ns, "Medium").Set(float64(summary.Medium))
	appmetrics.VulnerabilitiesTotal.WithLabelValues(img, ns, "Low").Set(float64(summary.Low))

	log.Info("scan completed",
		"image", scan.Spec.Image,
		"critical", summary.Critical,
		"high", summary.High,
		"medium", summary.Medium,
		"low", summary.Low,
		"duration", duration,
	)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ImageScan{}).
		Named("imagescan").
		Complete(r)
}
