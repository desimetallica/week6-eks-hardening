provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "week6-eks-hardening"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
