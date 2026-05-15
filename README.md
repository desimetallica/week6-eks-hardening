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


## References

- [AWS EKS Best Practices Guide](https://github.com/aws/aws-eks-best-practices)
- [EKS Security — IAM](https://aws.github.io/aws-eks-best-practices/security/docs/iam/)
- [EKS Security — Pod Security](https://aws.github.io/aws-eks-best-practices/security/docs/pods/)
- [EKS Security — Network](https://aws.github.io/aws-eks-best-practices/security/docs/network/)
- [EKS Security — Runtime](https://aws.github.io/aws-eks-best-practices/security/docs/runtime/)
- [Terraform AWS EKS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster)
