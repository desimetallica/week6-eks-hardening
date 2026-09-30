# Week 6 — EKS Security Hardening Lab

> Part of the **Cloud Security Training Series** — building on weeks 1–5 (OS hardening, AWS visibility, IaC basics, workload security, privilege escalation).

This lab deploys a **hardened Amazon EKS cluster** using Terraform, applying the security controls documented in the [AWS EKS Best Practices Guide](https://github.com/aws/aws-eks-best-practices). The goal is to understand how to design a production-grade secure Kubernetes cluster on AWS from scratch.

---

## Architecture

```
AWS Region (eu-south-1)
└── VPC (10.0.0.0/16)
    ├── Public Subnets  (AZ-a, AZ-b) → NAT Gateway / future Load Balancers
    └── Private Subnets (AZ-a, AZ-b) → EKS Worker Nodes (2 × t3.medium)
                                         ↑
                                     No public IPs
                                     No SSH keys
                                     SSM only
```

### VPC Endpoints (private AWS API connectivity)

| Endpoint | Type | Purpose |
|---|---|---|
| `ecr.api` | Interface | Authenticate with ECR |
| `ecr.dkr` | Interface | Pull container images |
| `sts` | Interface | IRSA token exchange |
| `ec2` | Interface | Node bootstrap / SSM |
| `ssm` | Interface | SSM Session Manager |
| `s3` | Gateway | Image layer downloads (free) |

---

## Security Controls

Controls are mapped to the [AWS EKS Best Practices](https://github.com/aws/aws-eks-best-practices) pillars.

### IAM

| Control | Implementation |
|---|---|
| Least-privilege cluster role | `AmazonEKSClusterPolicy` + `AmazonEKSVPCResourceController` only |
| Least-privilege node role | Worker node policy + CNI + ECR read-only + SSM + CloudWatch |
| No broad node credentials for pods | OIDC provider created → use IRSA per workload |
| No SSH keypair on nodes | `remote_access` block intentionally omitted; SSM only |

### Secrets & Encryption

| Control | Implementation |
|---|---|
| Kubernetes Secrets encrypted at rest | KMS envelope encryption on etcd (`encryption_config`) |
| Worker node EBS volumes encrypted | Customer-managed KMS key with annual rotation |
| Key rotation | Both KMS keys have `enable_key_rotation = true` |

### Compute / Node Hardening

| Control | Implementation |
|---|---|
| IMDSv2 enforced | `http_tokens = required` in launch template |
| Container SSRF to IMDS blocked | `http_put_response_hop_limit = 1` |
| Nodes in private subnets | `subnet_ids` points to private subnets only |
| No public IPs on nodes | `map_public_ip_on_launch = false` |
| Detailed monitoring | `monitoring { enabled = true }` in launch template |

### Logging & Observability

| Control | Implementation |
|---|---|
| All control plane log types | `api`, `audit`, `authenticator`, `controllerManager`, `scheduler` → CloudWatch |
| VPC Flow Logs | ALL traffic (ACCEPT + REJECT) → CloudWatch |
| Log retention | 30 days (configurable via `log_retention_days`) |

### Network

| Control | Implementation |
|---|---|
| Private API endpoint | `endpoint_private_access = true` |
| Restricted public API endpoint | `public_access_cidrs` = `allowed_cidr_blocks` variable |
| VPC endpoints | Avoids public internet for AWS API calls from nodes |
| Security groups | Minimal ingress: node↔node, control-plane↔node only |

---

## Repository Structure

```
week6-eks-hardening/
└── terraform/
    ├── versions.tf                  # Terraform ≥ 1.6, AWS ~5.40, TLS ~4.0
    ├── providers.tf                 # AWS provider with default tags
    ├── variables.tf                 # All input variables
    ├── main.tf                      # Module orchestration (root)
    ├── outputs.tf                   # Key outputs: endpoint, OIDC, kubeconfig
    ├── terraform.tfvars.example     # Safe template — copy and fill in
    └── modules/
        ├── vpc/
        │   ├── main.tf              # VPC, subnets, NAT GW, flow logs, endpoints
        │   ├── variables.tf
        │   └── outputs.tf
        ├── iam/
        │   ├── main.tf              # Cluster role, node role, instance profile
        │   ├── variables.tf
        │   └── outputs.tf
        └── eks/
            ├── main.tf              # KMS keys, security groups, EKS cluster,
            │                        # OIDC provider, launch template, node group
            ├── variables.tf
            └── outputs.tf
```

---

## Prerequisites

- AWS CLI configured (`aws configure` or environment variables)
- Terraform ≥ 1.6 installed
- An AWS account with permissions to create EKS, VPC, IAM, KMS resources
- `kubectl` installed (for post-deploy interaction)

---

## Deploy

### 1 — Configure your variables

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and **at minimum** set:

```hcl
# Restrict the EKS public API endpoint to your IP address
allowed_cidr_blocks = ["<YOUR_PUBLIC_IP>/32"]
```

### 2 — Initialize and plan

```bash
terraform init
terraform plan -out=eks.tfplan
```

Review the plan carefully before applying.

### 3 — Apply

```bash
terraform apply eks.tfplan
```

> Full deployment takes approximately 15–20 minutes (EKS cluster creation dominates).

### 4 — Connect to the cluster

```bash
# Command is also printed as a Terraform output
aws eks update-kubeconfig --region eu-south-1 --name eks-hardening-lab

# Verify nodes are ready
kubectl get nodes
```

### 5 — Verify hardening

```bash
# Confirm IMDSv2 is enforced on a node (use SSM — no SSH)
aws ssm start-session --target <instance-id>
# Inside the node:
curl -s http://169.254.169.254/latest/meta-data/  # should fail (IMDSv2 required)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id  # should succeed

# Confirm Secrets encryption is enabled
aws eks describe-cluster --name eks-hardening-lab \
  --query "cluster.encryptionConfig"

# Review audit logs in CloudWatch
aws logs tail /aws/eks/eks-hardening-lab/cluster --filter-pattern "objectRef"
```

### 6 — Tear down

```bash
terraform destroy
```

---

## Multi-namespace workload 

This chapter uses custom namespaces to explore three controls: network policies, and namespace/RBAC isolation. 

### 1 — Network Policies

Namespaces do not isolate pod traffic by themselves. By default, pods can reach pods
in other namespaces. A NetworkPolicy only changes that behavior when the cluster's
network plugin enforces it. On EKS, check that the Amazon VPC CNI add-on supports
network policies and that network policy enforcement is enabled before relying on
any of these rules. Check `kubectl config current-context` and the AWS account/region
before running the commands; use a disposable lab cluster or namespaces for this exercise.

Check the available namespaces and policies (the names and ages will differ):

```bash
kubectl get namespaces
kubectl -n network-lab-a get networkpolicies
kubectl -n network-lab-a describe networkpolicy default-deny-all
```

The last two commands return `NotFound` until the lab policies exist. `describe`
shows the selected pods, allowed ingress/egress peers and ports, and policy types.

Create two isolated namespaces and a web endpoint in each. The short-lived probe
pods below use the same BusyBox image as the web pods.

```bash
kubectl create namespace network-lab-a
kubectl create namespace network-lab-b
kubectl -n network-lab-a run web --image=busybox:1.36 --labels=app=web -- /bin/httpd -f -p 8080
kubectl -n network-lab-b run web --image=busybox:1.36 --labels=app=web -- /bin/httpd -f -p 8080
kubectl -n network-lab-a expose pod web --name=web --port=8080
kubectl -n network-lab-b expose pod web --name=web --port=8080
kubectl -n network-lab-a wait --for=condition=Ready pod/web --timeout=120s
kubectl -n network-lab-b wait --for=condition=Ready pod/web --timeout=120s
```

Before applying policies, confirm that a probe in A can reach B. BusyBox `httpd`
may return 404 for `/`, which still proves that the connection succeeded; a timeout
is the result to look for after isolation.

```bash
kubectl -n network-lab-a run probe --image=busybox:1.36 --labels=app=probe --restart=Never --command -- sleep 3600
kubectl -n network-lab-b run probe --image=busybox:1.36 --labels=app=probe --restart=Never --command -- sleep 3600
kubectl -n network-lab-a wait --for=condition=Ready pod/probe --timeout=120s
kubectl -n network-lab-b wait --for=condition=Ready pod/probe --timeout=120s
kubectl -n network-lab-a exec probe -- wget -S -O /dev/null -T 3 http://web.network-lab-b.svc.cluster.local:8080/ 2>&1
kubectl -n network-lab-b exec probe -- wget -S -O /dev/null -T 3 http://web.network-lab-a.svc.cluster.local:8080/ 2>&1
```

Apply the following policies in **each** lab namespace. The default policy selects
all pods and denies both ingress and egress. Policies are additive: the DNS policy
restores name resolution, and the intra-namespace policy restores local pod traffic
without opening cross-namespace access. Save the manifest as
`network-lab-policies.yaml`, then apply it twice with the namespace flag.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-intra-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}
  egress:
    - to:
        - podSelector: {}
```

```bash
kubectl -n network-lab-a apply -f network-lab-policies.yaml
kubectl -n network-lab-b apply -f network-lab-policies.yaml
kubectl -n network-lab-a get networkpolicies
kubectl -n network-lab-a describe networkpolicy default-deny-all
kubectl -n network-lab-a exec probe -- nslookup web.network-lab-b.svc.cluster.local
kubectl -n network-lab-a exec probe -- wget -S -O /dev/null -T 3 http://web.network-lab-a.svc.cluster.local:8080/ 2>&1
kubectl -n network-lab-a exec probe -- wget -S -O /dev/null -T 3 http://web.network-lab-b.svc.cluster.local:8080/ 2>&1
kubectl -n network-lab-b exec probe -- wget -S -O /dev/null -T 3 http://web.network-lab-b.svc.cluster.local:8080/ 2>&1
kubectl -n network-lab-b exec probe -- wget -S -O /dev/null -T 3 http://web.network-lab-a.svc.cluster.local:8080/ 2>&1
```

DNS should resolve, same-namespace requests should connect (a 404 is fine), and
cross-namespace requests should time out in both directions. If they respond, check CNI enforcement and policy
selectors; simply creating a NetworkPolicy does not guarantee isolation. Check
the actual CoreDNS pod labels with `kubectl -n kube-system get pods --show-labels`
if DNS fails. On clusters where DNS uses NodeLocal DNSCache, the DNS policy must
also allow the cache's IP and port.

For a real workload, add only the required paths: egress from the calling pods
**and** ingress to the destination pods, scoped to their namespace/pod labels and
ports. For example, permit an application to reach only its required database
endpoint and port, not all internet destinations. Standard NetworkPolicy supports
CIDRs (`ipBlock`), not DNS names: Atlas hostnames and IPs can change, so use a
controlled egress gateway/proxy or another policy engine that supports FQDN rules
when stable CIDRs are unavailable. Permit ingress from an ingress-controller pod
only when traffic actually originates from that pod; an AWS ALB can send traffic
directly to targets, so validate the real source path, health checks, and security
groups before defining ALB access. Avoid a broad `0.0.0.0/0` egress exception.

The Terraform in this repository does **not** currently manage the `vpc-cni`
add-on or enable its network policy feature. Inspect the live add-on before testing:

```bash
aws eks describe-addon --cluster-name eks-hardening-lab --addon-name vpc-cni \
  --region eu-south-1 --query 'addon.{status:status,version:addonVersion,configuration:configurationValues}'
```

If it is already managed elsewhere, update that configuration instead of creating
a second Terraform owner. Otherwise, after checking version compatibility and
the add-on's existing configuration, an add-on managed by this root module could
enable enforcement with:

```hcl
resource "aws_eks_addon" "vpc_cni" {
  cluster_name = module.eks.cluster_name
  addon_name   = "vpc-cni"

  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
  })
}
```

For a temporary **EKS-managed add-on not owned by Terraform**, after checking its
version and existing settings, the CLI can set the same configuration. If
`describe-addon` returns `ResourceNotFoundException`, this update command does not
apply: first determine whether the CNI is self-managed or needs an EKS add-on
installed. Do not use this command to
override an add-on owned by Terraform or to discard other configuration values:

```bash
aws eks update-addon --cluster-name eks-hardening-lab --addon-name vpc-cni \
  --region eu-south-1 --configuration-values '{"enableNetworkPolicy":"true"}'
```

Verify the add-on is healthy and the network policy agent is running on the
nodes before repeating the connectivity test. Clean up the disposable lab after testing:

```bash
kubectl delete namespace network-lab-a network-lab-b
```

**Conclusion:** for workloads, the practical benefit ot use NetPol is limiting a compromised pod to its documented dependencies and ports, rather than letting it freely contact every pod in the cluster. That helps contain lateral movement and some network-based command-and-control; of course it is not a substitute for runtime protection, patching, authentication, or application-level authorization.




---


## References

- [AWS EKS Best Practices Guide](https://github.com/aws/aws-eks-best-practices)
- [EKS Security — IAM](https://aws.github.io/aws-eks-best-practices/security/docs/iam/)
- [EKS Security — Pod Security](https://aws.github.io/aws-eks-best-practices/security/docs/pods/)
- [EKS Security — Network](https://aws.github.io/aws-eks-best-practices/security/docs/network/)
- [EKS Security — Runtime](https://aws.github.io/aws-eks-best-practices/security/docs/runtime/)
- [Terraform AWS EKS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster)
