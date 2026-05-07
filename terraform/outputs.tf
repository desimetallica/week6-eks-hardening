output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = module.eks.cluster_endpoint
}

output "kubeconfig_command" {
  description = "AWS CLI command to update your local kubeconfig for this cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${var.cluster_name}"
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN — use this when creating IRSA roles for workloads"
  value       = module.eks.oidc_provider_arn
}

output "oidc_provider_url" {
  description = "OIDC provider URL — use this when creating IRSA trust policies"
  value       = module.eks.oidc_provider_url
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (worker nodes)"
  value       = module.vpc.private_subnet_ids
}

output "kms_secrets_key_arn" {
  description = "ARN of the KMS key used for Kubernetes Secrets encryption"
  value       = module.eks.kms_key_arn
}
