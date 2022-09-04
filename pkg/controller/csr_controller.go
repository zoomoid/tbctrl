package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	x509TypeCerticateRequest = "CERTIFICATE REQUEST"
)

type CertificateSigningRequestReconciler struct {
	ClientSet *clientset.Clientset
	client.Client
	Scheme *runtime.Scheme
	*rest.Config
}

//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;watch;list
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,resourceNames="kubernetes.io/kubelet-serving",verbs=approve

func (r *CertificateSigningRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var csr certificatesv1.CertificateSigningRequest
	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		l.Error(err, "Unable to get CSR with name: %s", req.Name)

		return ctrl.Result{}, err
	}

	if csr.Spec.SignerName != certificatesv1.KubeletServingSignerName {
		l.V(4).Info("Ignoring non-kubelet-serving CSR")

		return ctrl.Result{}, nil
	}

	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		l.V(3).Info("The CSR is already approved|denied, ignoring", "approved", approved, "denied", denied)
		return ctrl.Result{}, nil
	}

	if len(csr.Status.Certificate) > 0 {
		l.V(3).Info("The CSR is already signed. No need to do anything else.")
		return ctrl.Result{}, nil
	}

	cr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		l.Error(err, fmt.Sprintf("unable to parse csr %q", csr.Name))

		return ctrl.Result{}, err
	}

	if !strings.HasPrefix(csr.Spec.Username, "system:node:") {
		l.V(3).Info("The CSR is not scoped for a kubelet, ignoring")
		return ctrl.Result{}, err
	}

	r.Validate(ctx, &csr, cr)

	_, err = r.ClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, req.Name, &csr, metav1.UpdateOptions{})

	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		l.Error(err, "Could not update CSR")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1.CertificateSigningRequest{}).
		Complete(r)
}

func (r *CertificateSigningRequestReconciler) Validate(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, cr *x509.CertificateRequest) {
	l := log.FromContext(ctx)
	if len(cr.DNSNames)+len(cr.IPAddresses) == 0 {
		reason := "CSR SAN contains neither an IP address nor a DNS name"
		l.V(0).Info("Denying kubelet-serving CSR, reason" + reason)

		appendCondition(csr, false, reason)
		return
	}

	if cr.Subject.CommonName != csr.Spec.Username {
		reason := "CSR username does not match the parsed x509 certificate request CN"
		l.V(0).Info("Denying kubelet-serving CSR, reason" + reason)

		appendCondition(csr, false, reason)
		return
	}

	appendCondition(csr, true, "CSR is scoped correctly")
}

func appendCondition(csr *certificatesv1.CertificateSigningRequest, approve bool, reason string) {
	if approve {
		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:               certificatesv1.CertificateApproved,
			Status:             corev1.ConditionTrue,
			Reason:             "kubelet-serving CSR approved",
			Message:            reason,
			LastUpdateTime:     metav1.Now(),
			LastTransitionTime: metav1.Time{},
		})
	} else {
		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:               certificatesv1.CertificateDenied,
			Status:             corev1.ConditionTrue,
			Reason:             "kubelet-serving CSR denied",
			Message:            reason,
			LastUpdateTime:     metav1.Now(),
			LastTransitionTime: metav1.Time{},
		})
	}
}

func getCertApprovalCondition(status *certificatesv1.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certificatesv1.CertificateApproved {
			approved = true
		}
		if c.Type == certificatesv1.CertificateDenied {
			denied = true
		}
	}
	return
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)

	if block == nil || block.Type != x509TypeCerticateRequest {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)

	if err != nil {
		return nil, err
	}

	return csr, nil
}
