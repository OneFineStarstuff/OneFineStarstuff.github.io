terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Terraform Module: Confidential Enclave Deployment for Sentinel v2.4
# Supports AMD SEV-SNP and Intel TDX nodes in G-SIFI multi-region environments.

variable "region" {
  description = "The target cloud region for the enclave"
  type        = string
  default     = "us-east-1"
}

variable "subnet_id" {
  description = "The subnet ID to deploy into (non-default VPC recommended)"
  type        = string
  default     = "subnet-0123456789abcdef0"
}

variable "enclave_type" {
  description = "Type of confidential computing enclave"
  type        = string
  default     = "sev-snp" # or "tdx"
}

resource "aws_instance" "sentinel_cee_node" {
  ami           = "ami-0123456789abcdef0" # Hardened Sentinel OS with vTPM support
  instance_type = "r6a.4xlarge"           # Instance type with SEV-SNP support
  monitoring    = true                    # Enable detailed monitoring
  subnet_id     = var.subnet_id

  cpu_options {
    amd_sev_snp = var.enclave_type == "sev-snp" ? "enabled" : "disabled"
  }

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    instance_metadata_tags = "enabled"
  }

  tags = {
    Name        = "sentinel-cee-v2.4-${var.region}"
    Environment = "production-gsifi"
    Governance  = "Sentinel-v2.4"
  }
}

# Placeholder for vTPM remote attestation check and PCR binding
output "enclave_id" {
  value = aws_instance.sentinel_cee_node.id
}
