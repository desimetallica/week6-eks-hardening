# ──────────────────────────────────────────────────────────────
# Global
# ──────────────────────────────────────────────────────────────
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "eu-south-1"
}

variable "environment" {
  description = "Environment name (lab, dev, prod)"
  type        = string
  default     = "lab"
}

# ──────────────────────────────────────────────────────────────
# EKS cluster
# ──────────────────────────────────────────────────────────────
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "eks-hardening-lab"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.31"
}

# ──────────────────────────────────────────────────────────────
# Networking
# ──────────────────────────────────────────────────────────────
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (EKS worker nodes)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (load balancers only)"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}

# ──────────────────────────────────────────────────────────────
# Worker nodes
# ──────────────────────────────────────────────────────────────
variable "node_instance_type" {
  description = "EC2 instance type for worker nodes (minimum t3.medium for EKS)"
  type        = string
  default     = "t3.medium"
}

variable "node_desired_size" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 3
}

variable "node_disk_size_gb" {
  description = "EBS root volume size in GB for worker nodes"
  type        = number
  default     = 20
}

# ──────────────────────────────────────────────────────────────
# Security
# ──────────────────────────────────────────────────────────────
variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to reach the EKS public API endpoint. RESTRICT TO YOUR IP in production."
  type        = list(string)
  default     = ["0.0.0.0/0"] # TODO: replace with your IP/32 before deploying
}

variable "kms_key_deletion_window_days" {
  description = "Waiting period in days before KMS key deletion"
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 30
}
