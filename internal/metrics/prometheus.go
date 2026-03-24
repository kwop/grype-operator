package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	VulnerabilitiesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "grype_operator_vulnerabilities_total",
			Help: "Total number of vulnerabilities by image, namespace, and severity",
		},
		[]string{"image", "namespace", "severity"},
	)

	ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grype_operator_scan_duration_seconds",
			Help:    "Duration of image scans in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~512s
		},
		[]string{"image"},
	)

	ScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grype_operator_scans_total",
			Help: "Total number of scans by status",
		},
		[]string{"status"},
	)

	ImagesScanned = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "grype_operator_images_scanned",
			Help: "Number of unique images currently tracked",
		},
	)

	DBLastUpdate = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "grype_operator_db_last_update_timestamp",
			Help: "Timestamp of last Grype DB update",
		},
	)

	CacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "grype_operator_cache_size",
			Help: "Number of entries in the image scan cache",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		VulnerabilitiesTotal,
		ScanDuration,
		ScansTotal,
		ImagesScanned,
		DBLastUpdate,
		CacheSize,
	)
}
