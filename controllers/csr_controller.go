package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	x509TypeCerticateRequest = "CERTIFICATE REQUEST"
)

type CertificateSigningRequestReconciler struct {
	ClientSet *clientset.Clientset
	client.Client
	Scheme *runtime.Scheme
	*rest.Config
	Logger logr.Logger
}

var _ reconcile.ObjectReconciler[*certificatesv1.CertificateSigningRequest] = &CertificateSigningRequestReconciler{}

//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;watch;list
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,resourceNames="kubernetes.io/kubelet-serving",verbs=approve

func (r *CertificateSigningRequestReconciler) Reconcile(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (ctrl.Result, error) {
	if csr.Spec.SignerName != certificatesv1.KubeletServingSignerName {
		r.Logger.V(4).Info("Ignoring non-kubelet-serving CSR")

		return ctrl.Result{}, nil
	}

	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		r.Logger.V(3).Info("The CSR is already approved/denied, ignoring", "approved", approved, "denied", denied)
		return ctrl.Result{}, nil
	}

	if len(csr.Status.Certificate) > 0 {
		r.Logger.V(3).Info("The CSR is already signed")
		return ctrl.Result{}, nil
	}

	cr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		r.Logger.Error(err, "Unable to parse CSR", "name", csr.Name)

		return ctrl.Result{}, err
	}

	if !strings.HasPrefix(csr.Spec.Username, "system:node:") {
		r.Logger.V(3).Info("The CSR is not scoped for a kubelet, ignoring")
		return ctrl.Result{}, err
	}

	r.Validate(ctx, csr, cr)

	_, err = r.ClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})

	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		r.Logger.Error(err, "CSR is conflicting or not found, requeueing", "name", csr.Name)
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		r.Logger.Error(err, "Could not update CSR", "namespace", csr.Namespace, "name", csr.Name)
		return ctrl.Result{}, err
	}

	r.Logger.V(0).Info("Approved kubelet-serving CSR and finished reconciliation", "name", csr.Name)

	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1.CertificateSigningRequest{}).
		Complete(reconcile.AsReconciler(mgr.GetClient(), &CertificateSigningRequestReconciler{}))
}

func (r *CertificateSigningRequestReconciler) Validate(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, cr *x509.CertificateRequest) {
	// Check for https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#client-and-serving-certificates
	if err := validateNames(csr, cr); err != nil {
		reason := err.Error()
		r.Logger.V(0).Info("Denying kubelet-serving CSR", "reason", reason)
		appendCondition(csr, false, reason)
	}

	if err := validateKeyUsage(csr); err != nil {
		reason := err.Error()
		r.Logger.V(0).Info("Denying kubelet-serving CSR", "reason", reason)
		appendCondition(csr, false, reason)
	}

	if err := validateSubjectAltName(cr); err != nil {
		reason := err.Error()
		r.Logger.V(0).Info("Denying kubelet-serving CSR", "reason", reason)
		appendCondition(csr, false, reason)
	}

	appendCondition(csr, true, "CSR is scoped correctly")
}

func validateNames(csr *certificatesv1.CertificateSigningRequest, cr *x509.CertificateRequest) error {
	if cr.Subject.CommonName != csr.Spec.Username {
		return errors.New("CSR username does not match the parsed x509 certificate request CN")
	}

	if len(csr.Spec.Groups) != 1 || csr.Spec.Groups[0] != "system:nodes" {
		return errors.New(".spec.groups may only contain 'system:nodes'")
	}

	usernamePrefix := "system:node:"
	if !strings.HasPrefix(csr.Spec.Username, usernamePrefix) {
		return errors.New(".spec.username must start with 'system:node:'")
	}

	nodeName, _ := strings.CutPrefix(csr.Spec.Username, usernamePrefix)
	// we already checked that the string has the prefix
	if errs := validation.IsDNS1123Subdomain(nodeName); len(errs) != 0 {
		return errors.New("CSR's node name must be a DNS subdomain name")
	}

	return nil
}

func validateKeyUsage(csr *certificatesv1.CertificateSigningRequest) error {
	l := len(csr.Spec.Usages)
	hasServerAuth := slices.Contains(csr.Spec.Usages, certificatesv1.UsageServerAuth)
	hasKeyEncipherment := slices.Contains(csr.Spec.Usages, certificatesv1.UsageKeyEncipherment)
	hasDigitalSignature := slices.Contains(csr.Spec.Usages, certificatesv1.UsageDigitalSignature)

	if hasServerAuth && ((l == 2 && (hasDigitalSignature || hasKeyEncipherment)) || (l == 3 && hasKeyEncipherment && hasDigitalSignature)) {
		return nil
	}

	return errors.New("key usage may only be 'server auth', and optionally 'key encipherment' and 'digital signature'")
}

func validateSubjectAltName(cr *x509.CertificateRequest) error {
	ip := cr.IPAddresses
	dns := cr.DNSNames

	if len(dns)+len(ip) == 0 {
		return errors.New("CSR SAN contains neither an IP address nor a DNS name")
	}

	if len(cr.URIs) > 0 {
		return errors.New("CSR SAN may not contain URIs")
	}

	if len(cr.EmailAddresses) > 0 {
		return errors.New("CSR SAN may not contain email adresses")
	}

	return nil
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
