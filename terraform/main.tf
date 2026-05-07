# ══════════════════════════════════════════════════════════════
# Root module — Week 6: EKS Security Hardening Lab
#
# Architecture:
#   VPC (2 AZs)
#     ├── Public subnets  → NAT Gateway, future load balancers
#     └── Private subnets → EKS worker nodes (2 × t3.medium)
#
# EKS Security Hardening (aws-eks-best-practices):
#   [IAM]        Least-privilege cluster + node roles
#   [IAM]        OIDC/IRSA — pods get scoped AWS roles, not node credentials
#   [Secrets]    KMS envelope encryption for Kubernetes Secrets
#   [Nodes]      EBS volumes encrypted with customer-managed KMS key
#   [Nodes]      IMDSv2 enforced, hop-limit=1 (blocks container SSRF)
#   [Nodes]      No SSH — SSM Session Manager for interactive access
#   [Nodes]      Private subnets only — no public IPs on worker nodes
#   [Logging]    All 5 control plane log types to CloudWatch
#   [Network]    VPC Flow Logs — full traffic visibility
#   [Network]    VPC endpoints (ECR, STS, EC2, SSM, S3) — no public internet
#                for AWS API calls from within the cluster
#   [Network]    Public API endpoint CIDR-restricted
# ══════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────
# VPC — network foundation
# ──────────────────────────────────────────────────────────────
module "vpc" {
  source = "./modules/vpc"

  cluster_name         = var.cluster_name
  vpc_cidr             = var.vpc_cidr
  private_subnet_cidrs = var.private_subnet_cidrs
  public_subnet_cidrs  = var.public_subnet_cidrs
  aws_region           = var.aws_region
  log_retention_days   = var.log_retention_days
}

# ──────────────────────────────────────────────────────────────
# IAM — least-privilege roles
# ──────────────────────────────────────────────────────────────
module "iam" {
  source = "./modules/iam"

  cluster_name = var.cluster_name
}

# ──────────────────────────────────────────────────────────────
# EKS — hardened cluster + worker nodes
# ──────────────────────────────────────────────────────────────
module "eks" {
  source = "./modules/eks"

  cluster_name       = var.cluster_name
  kubernetes_version = var.kubernetes_version
  cluster_role_arn   = module.iam.cluster_role_arn
  node_role_arn      = module.iam.node_role_arn

  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids

  node_instance_type = var.node_instance_type
  node_desired_size  = var.node_desired_size
  node_min_size      = var.node_min_size
  node_max_size      = var.node_max_size
  node_disk_size_gb  = var.node_disk_size_gb

  allowed_cidr_blocks          = var.allowed_cidr_blocks
  kms_key_deletion_window_days = var.kms_key_deletion_window_days
  log_retention_days           = var.log_retention_days
}
