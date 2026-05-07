# ══════════════════════════════════════════════════════════════
# IAM Module — Least-privilege roles for EKS
#
# Security controls implemented:
#   - EKS cluster role: only AWS-managed policies required by EKS
#   - Node role: minimal set (CNI, ECR read-only, CloudWatch)
#   - Node role: SSM access instead of SSH (no keypair needed)
#   - Node role: NO admin/broad permissions — IRSA is used per workload
#   - IRSA is enabled via OIDC provider (created in eks module)
# ══════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────
# EKS Cluster Role
# Only the EKS service can assume this role.
# ──────────────────────────────────────────────────────────────
resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# AWS-managed policy required by EKS to manage cluster infrastructure
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# Allows EKS to manage VPC resources (ENIs, security groups) for the cluster
resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

# ──────────────────────────────────────────────────────────────
# EKS Node Role
# Nodes assume this role. Principle: only what kubelet/CNI needs.
# ──────────────────────────────────────────────────────────────
resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Required for the node to join the cluster
resource "aws_iam_role_policy_attachment" "node_eks_worker" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

# Required for the VPC CNI plugin to assign pod IPs
resource "aws_iam_role_policy_attachment" "node_eks_cni" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

# Read-only access to pull images from ECR
resource "aws_iam_role_policy_attachment" "node_ecr_readonly" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Security: SSM Session Manager replaces SSH — no keypair required on nodes
resource "aws_iam_role_policy_attachment" "node_ssm" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch Agent — enables Container Insights and node-level metrics
resource "aws_iam_role_policy_attachment" "node_cloudwatch" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# ──────────────────────────────────────────────────────────────
# Instance Profile — wraps the node role for EC2 launch template
# ──────────────────────────────────────────────────────────────
resource "aws_iam_instance_profile" "eks_node" {
  name = "${var.cluster_name}-node-profile"
  role = aws_iam_role.eks_node.name
}
