# ══════════════════════════════════════════════════════════════
# EKS Module — Hardened cluster and worker node group
#
# Security controls implemented:
#   [IAM]        OIDC provider for IRSA (no node-level AWS creds for pods)
#   [Encryption] KMS envelope encryption for Kubernetes Secrets at rest
#   [Encryption] KMS encryption for EBS node volumes
#   [Logging]    All control plane log types → CloudWatch (api, audit,
#                authenticator, controllerManager, scheduler)
#   [Network]    Private API endpoint enabled; public endpoint CIDR-restricted
#   [Nodes]      IMDSv2 enforced (hop-limit=1 blocks container SSRF to IMDS)
#   [Nodes]      No SSH keypair — SSM Session Manager for shell access
#   [Nodes]      Nodes in private subnets only
#   [Nodes]      Detailed EC2 monitoring enabled
# ══════════════════════════════════════════════════════════════

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# ──────────────────────────────────────────────────────────────
# KMS key — Kubernetes Secrets encryption at rest
# Best Practice: rotate annually, restrict to EKS service + account root
# ──────────────────────────────────────────────────────────────
resource "aws_kms_key" "eks_secrets" {
  description             = "EKS ${var.cluster_name} — secrets envelope encryption"
  deletion_window_in_days = var.kms_key_deletion_window_days
  enable_key_rotation     = true # Annual automatic key rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEKSServiceEncryption"
        Effect = "Allow"
        Principal = { Service = "eks.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.cluster_name}-secrets-kms"
  }
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/${var.cluster_name}-secrets"
  target_key_id = aws_kms_key.eks_secrets.key_id
}

# ──────────────────────────────────────────────────────────────
# KMS key — EBS volumes for worker nodes
# ──────────────────────────────────────────────────────────────
resource "aws_kms_key" "ebs" {
  description             = "EKS ${var.cluster_name} — worker node EBS encryption"
  deletion_window_in_days = var.kms_key_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEBSUseFromThisAccountViaEC2"
        Effect = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id,
            "kms:ViaService"    = "ec2.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "AllowEBSGrantsForAWSResources"
        Effect = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = true
          }
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id,
            "kms:ViaService"    = "ec2.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.cluster_name}-ebs-kms"
  }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.cluster_name}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# ──────────────────────────────────────────────────────────────
# CloudWatch Log Group — control plane audit and API logs
# ──────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.cluster_name}-control-plane-logs"
  }
}

# ──────────────────────────────────────────────────────────────
# Security Groups
# ──────────────────────────────────────────────────────────────

# Cluster (API server) security group
resource "aws_security_group" "cluster" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "EKS cluster API server security group"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.cluster_name}-cluster-sg"
  }
}

# Worker node security group
resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-node-sg"
  description = "EKS worker node security group"
  vpc_id      = var.vpc_id

  # Allow all outbound (nodes need to reach API, AWS services, internet for updates)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name                                        = "${var.cluster_name}-node-sg"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  }
}

# Nodes ↔ Nodes: all traffic (required for pod-to-pod communication)
resource "aws_security_group_rule" "node_internal" {
  security_group_id        = aws_security_group.node.id
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"
  source_security_group_id = aws_security_group.node.id
  description              = "Allow all inter-node traffic (pod networking)"
}

# Control plane → nodes: ephemeral ports (kubelet, kube-proxy, CNI)
resource "aws_security_group_rule" "cluster_to_node_ephemeral" {
  security_group_id        = aws_security_group.node.id
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  description              = "Control plane to node kubelet and services"
}

# Control plane → nodes: HTTPS (required for metrics-server, webhooks)
resource "aws_security_group_rule" "cluster_to_node_443" {
  security_group_id        = aws_security_group.node.id
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  description              = "Control plane HTTPS to nodes"
}

# Nodes → control plane API server
resource "aws_security_group_rule" "node_to_cluster_443" {
  security_group_id        = aws_security_group.cluster.id
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  description              = "Nodes to EKS API server"
}

# ──────────────────────────────────────────────────────────────
# EKS Cluster
# ──────────────────────────────────────────────────────────────
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = var.cluster_role_arn
  version  = var.kubernetes_version

  # Security: envelope encryption for Kubernetes Secrets stored in etcd
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
  }

  vpc_config {
    subnet_ids = var.private_subnet_ids
    security_group_ids = [aws_security_group.cluster.id]

    # Security: private endpoint so nodes communicate with API without public internet
    endpoint_private_access = true

    # Public endpoint kept for lab access; restrict or disable in production
    # Set to false and use a VPN/bastion if this is a production cluster
    endpoint_public_access = true
    public_access_cidrs    = var.allowed_cidr_blocks
  }

  # Security: enable ALL control plane log types for full audit trail
  # - api:               all API server requests
  # - audit:             who did what to which resource
  # - authenticator:     IAM/OIDC authentication events
  # - controllerManager: reconciliation loops
  # - scheduler:         pod scheduling decisions
  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  # Ensure the log group exists before the cluster tries to write to it
  depends_on = [aws_cloudwatch_log_group.eks]

  tags = {
    Name = var.cluster_name
  }
}

# ──────────────────────────────────────────────────────────────
# OIDC Provider — enables IRSA (IAM Roles for Service Accounts)
# Best Practice: use IRSA instead of node-level instance profile
# permissions for pod workloads. Each pod gets its own scoped role.
# ──────────────────────────────────────────────────────────────
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = {
    Name = "${var.cluster_name}-oidc-provider"
  }
}

# ──────────────────────────────────────────────────────────────
# Launch Template — worker node security hardening
# ──────────────────────────────────────────────────────────────
resource "aws_launch_template" "node" {
  name_prefix   = "${var.cluster_name}-node-lt-"
  # No image_id here — EKS managed node group selects the EKS-optimized AMI
  # based on ami_type set on the node group resource below

  # Security: encrypted EBS root volume with CMK
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.node_disk_size_gb
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
      delete_on_termination = true
    }
  }

  # Security: enforce IMDSv2 to prevent SSRF attacks against the instance metadata
  # hop_limit=1 ensures containers cannot reach the IMDS (only host process can)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only — v1 is disabled
    http_put_response_hop_limit = 1          # Blocks container SSRF to IMDS
    instance_metadata_tags      = "enabled"
  }

  # Security: no SSH key — use SSM Session Manager for interactive access
  # key_name is intentionally NOT set

  # Enable detailed CloudWatch monitoring (1-minute granularity)
  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.cluster_name}-worker-node"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.cluster_name}-worker-ebs"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ──────────────────────────────────────────────────────────────
# EKS Managed Node Group — two worker nodes
# ──────────────────────────────────────────────────────────────
resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-workers"
  node_role_arn   = var.node_role_arn

  # Security: nodes ONLY in private subnets — no direct internet exposure
  subnet_ids = var.private_subnet_ids

  # Amazon Linux 2 EKS-optimized AMI (x86_64)
  ami_type       = "AL2_x86_64"
  instance_types = [var.node_instance_type]

  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  # Rolling update: replace one node at a time to preserve cluster availability
  update_config {
    max_unavailable = 1
  }

  # Security: no remote SSH access — use SSM Session Manager
  # remote_access block is intentionally omitted

  labels = {
    role        = "worker"
    environment = "lab"
  }

  tags = {
    Name = "${var.cluster_name}-worker-node-group"
  }
}
