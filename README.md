# zoomoid/tbctrl

A minimal Kubernetes controller to handle kubelet-serving certificate signing requests at the control plane
automatically during cluster bootstrapping.

For details, see

- <https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#client-and-serving-certificates> and
- <https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/#kubelet-serving-certs>.

All this controller does is check some fields in the CSR to be plausible and to interfere as little
with regular CSRs as possible, only reconciles CSRs from "system:node:NODE_NAME".

For a controller that does more checks and in general is more secure, see <https://github.com/postfinance/kubelet-csr-approver>. The repository also includes a threat model for security considerations, something
this project neglects for reasons of simplicity.

**If security is a major concern of yours, DO NOT USE this controller, as it can be leveraged to sign spoofed CSRs quite easily.**

## Deploy with Helm

Deploy the controller to a cluster with Helm by running

```bash
# Add the repo to your local helm repositories
$ helm repo add tbctrl https://zoomoid.github.io/tbctrl
# Install the controller into the cluster
$ helm install tls-bootstrapping-controller tbctrl/tbctrl -n kube-system
```

## Deploy from manifests

You can also use static manifests, but be aware of the configuration: by default metrics are enabled,
and the version is "latest".

```bash
# Deploy controller to kube-system namespace
$ kubectl apply -n kube-system -f https://raw.githubusercontent.com/zoomoid/tbctrl/main/manifests/tbctrl.yaml
```

You can also use the kustomization available in `./manifests/kustomization` as a base to customize the deployment without having to dig too deep into the YAML files.
