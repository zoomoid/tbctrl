# zoomoid/tbctrl

A minimal Kubernetes controller to handle kubelet-serving certificate signing requests at the control plane
automatically during cluster bootstrapping.

For details, see <https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#client-and-serving-certificates> and <https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/#kubelet-serving-certs>.

All this controller does is check some fields in the CSR to be plausible and to interfere as little
with regular CSRs as possible, only reconciles CSRs from "system:node:NODE_NAME".

For a controller that does more checks and in general is more secure, see <https://github.com/postfinance/kubelet-csr-approver>.

## Deploy with Helm

Deploy the controller to a cluster with

```bash
$ helm repo add tbctrl https://zoomoid.github.io/tbctrl
```