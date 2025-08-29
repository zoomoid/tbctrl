package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("CSR Controller", func() {
	// Define utility constants for object names and testing timeouts/durations and intervals.
	const (
		CSRName = "test-csr"

		timeout  = time.Second * 10
		duration = time.Second * 10
		interval = time.Millisecond * 250

		group          = "system:nodes"
		nodeName       = "test-node"
		usernamePrefix = "system:node:"
	)
	var (
		expirationSeconds = int32(60 * 60) // 1 hour
	)
	Context("When creating a CSR", func() {
		It("Should only reconcile the CSR if it is a kubelet-serving certificate signing request ", func() {
			By("Create public and private ed2551 keys")
			privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			Expect(err).ShouldNot(HaveOccurred())

			By("Create CSR payload")
			req, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				SignatureAlgorithm: x509.ECDSAWithSHA256,
				DNSNames:           []string{nodeName},
				Subject: pkix.Name{
					CommonName: nodeName,
				},
			}, privateKey)

			Expect(err).ShouldNot(HaveOccurred())

			By("Create a new CSR")
			ctx := context.Background()
			csr := &certificatesv1.CertificateSigningRequest{
				ObjectMeta: v1.ObjectMeta{
					Name: CSRName,
				},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName:        "kubernetes.io/kubelet-serving",
					ExpirationSeconds: &expirationSeconds,
					Username:          usernamePrefix + nodeName,
					Groups:            []string{group},
					Request:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req}),
					Usages:            []certificatesv1.KeyUsage{certificatesv1.UsageServerAuth, certificatesv1.UsageDigitalSignature, certificatesv1.UsageKeyAgreement},
				},
			}
			Expect(k8sClient.Create(ctx, csr)).Should(Succeed())

			csrLookupKey := types.NamespacedName{Name: CSRName}
			createdCSR := &certificatesv1.CertificateSigningRequest{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, csrLookupKey, createdCSR)
				return err == nil
			}, timeout, interval).Should(BeTrue())

		})
	})
})
