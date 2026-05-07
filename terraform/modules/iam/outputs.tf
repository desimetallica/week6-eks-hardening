output "cluster_role_arn" {
  description = "IAM role ARN for the EKS cluster control plane"
  value       = aws_iam_role.eks_cluster.arn
}

output "node_role_arn" {
  description = "IAM role ARN for EKS worker nodes"
  value       = aws_iam_role.eks_node.arn
}

output "node_role_name" {
  description = "IAM role name for EKS worker nodes"
  value       = aws_iam_role.eks_node.name
}
