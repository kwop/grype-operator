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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/kwop/grype-operator/api/v1alpha1"
	"github.com/kwop/grype-operator/internal/cache"
)

var _ = Describe("ImageScan Controller", func() {
	Context("When reconciling a Pending ImageScan", func() {
		const scanName = "test-scan-pending"
		const namespace = "default"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      scanName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("creating a Pending ImageScan resource")
			scan := &securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:      scanName,
					Namespace: namespace,
				},
				Spec: securityv1alpha1.ImageScanSpec{
					Image:           "alpine:3.21",
					Digest:          "sha256:fakedigest123456",
					SourceNamespace: namespace,
					SourcePod:       "test-pod",
				},
			}
			err := k8sClient.Get(ctx, typeNamespacedName, &securityv1alpha1.ImageScan{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, scan)).To(Succeed())
			}

			// Set status to Pending
			Eventually(func() error {
				var s securityv1alpha1.ImageScan
				if err := k8sClient.Get(ctx, typeNamespacedName, &s); err != nil {
					return err
				}
				s.Status.Phase = securityv1alpha1.PhasePending
				return k8sClient.Status().Update(ctx, &s)
			}, 5*time.Second).Should(Succeed())
		})

		AfterEach(func() {
			resource := &securityv1alpha1.ImageScan{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should skip non-Pending scans", func() {
			By("Setting phase to Completed first")
			Eventually(func() error {
				var s securityv1alpha1.ImageScan
				if err := k8sClient.Get(ctx, typeNamespacedName, &s); err != nil {
					return err
				}
				s.Status.Phase = securityv1alpha1.PhaseCompleted
				return k8sClient.Status().Update(ctx, &s)
			}, 5*time.Second).Should(Succeed())

			imageCache := cache.New(1 * time.Hour)

			reconciler := &ImageScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				Cache:  imageCache,
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})

		It("should skip scan when cache has recent entry", func() {
			imageCache := cache.New(1 * time.Hour)
			imageCache.MarkScanned("sha256:fakedigest123456")

			reconciler := &ImageScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				Cache:  imageCache,
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			// Verify phase was set to Completed (skipped via cache)
			var scan securityv1alpha1.ImageScan
			Expect(k8sClient.Get(ctx, typeNamespacedName, &scan)).To(Succeed())
			Expect(scan.Status.Phase).To(Equal(securityv1alpha1.PhaseCompleted))
		})

		It("should handle not-found ImageScan gracefully", func() {
			imageCache := cache.New(1 * time.Hour)

			reconciler := &ImageScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				Cache:  imageCache,
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "nonexistent",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})
})

var _ = Describe("Pod Controller", func() {
	Context("When a running Pod is created", func() {
		const podName = "test-pod-with-image"
		const namespace = "default"

		ctx := context.Background()

		AfterEach(func() {
			// Cleanup pod
			pod := &corev1.Pod{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, pod)
			if err == nil {
				_ = k8sClient.Delete(ctx, pod)
			}

			// Cleanup any ImageScans created
			scanList := &securityv1alpha1.ImageScanList{}
			_ = k8sClient.List(ctx, scanList)
			for i := range scanList.Items {
				_ = k8sClient.Delete(ctx, &scanList.Items[i])
			}
		})

		It("should create an ImageScan CRD for a running pod", func() {
			By("creating a pod")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "app",
							Image: "nginx:1.25.3",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())

			By("simulating kubelet setting pod status to Running")
			Eventually(func() error {
				var p corev1.Pod
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &p); err != nil {
					return err
				}
				p.Status.Phase = corev1.PodRunning
				p.Status.ContainerStatuses = []corev1.ContainerStatus{
					{
						Name:    "app",
						Image:   "nginx:1.25.3",
						ImageID: "docker-pullable://nginx@sha256:aabbccdd11223344",
						Ready:   true,
					},
				}
				return k8sClient.Status().Update(ctx, &p)
			}, 5*time.Second).Should(Succeed())

			By("verifying pod status was persisted")
			var verifyPod corev1.Pod
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &verifyPod)).To(Succeed())
			Expect(verifyPod.Status.Phase).To(Equal(corev1.PodRunning))
			Expect(verifyPod.Status.ContainerStatuses).To(HaveLen(1))

			imageCache := cache.New(1 * time.Hour)

			reconciler := &PodReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Cache:             imageCache,
				ExcludeNamespaces: []string{"kube-system"},
				ExcludeImages:     []string{},
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: podName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify an ImageScan CRD was created
			scanList := &securityv1alpha1.ImageScanList{}
			Expect(k8sClient.List(ctx, scanList)).To(Succeed())

			found := false
			for _, s := range scanList.Items {
				if s.Spec.Image == "nginx:1.25.3" {
					found = true
					Expect(s.Spec.Digest).To(Equal("sha256:aabbccdd11223344"))
					Expect(s.Spec.SourcePod).To(Equal(podName))
					Expect(s.Spec.SourceNamespace).To(Equal(namespace))
				}
			}
			Expect(found).To(BeTrue(), "expected ImageScan for nginx:1.25.3 to be created")
		})

		It("should skip pods in excluded namespaces", func() {
			imageCache := cache.New(1 * time.Hour)

			reconciler := &PodReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Cache:             imageCache,
				ExcludeNamespaces: []string{"default"},
				ExcludeImages:     []string{},
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: podName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			// No ImageScan should be created
			scanList := &securityv1alpha1.ImageScanList{}
			Expect(k8sClient.List(ctx, scanList)).To(Succeed())
			Expect(scanList.Items).To(BeEmpty())
		})

		It("should not create duplicate ImageScans for cached digests", func() {
			By("creating a pod")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "redis:7"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			Eventually(func() error {
				var p corev1.Pod
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, &p); err != nil {
					return err
				}
				p.Status.Phase = corev1.PodRunning
				p.Status.ContainerStatuses = []corev1.ContainerStatus{
					{
						Name:    "app",
						Image:   "redis:7",
						ImageID: "docker-pullable://redis@sha256:cacheddigest1234",
						Ready:   true,
					},
				}
				return k8sClient.Status().Update(ctx, &p)
			}, 5*time.Second).Should(Succeed())

			imageCache := cache.New(1 * time.Hour)
			imageCache.MarkScanned("sha256:cacheddigest1234")

			reconciler := &PodReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Cache:             imageCache,
				ExcludeNamespaces: []string{},
				ExcludeImages:     []string{},
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: podName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			// No ImageScan should be created since digest is cached
			scanList := &securityv1alpha1.ImageScanList{}
			Expect(k8sClient.List(ctx, scanList)).To(Succeed())
			Expect(scanList.Items).To(BeEmpty())
		})
	})
})
