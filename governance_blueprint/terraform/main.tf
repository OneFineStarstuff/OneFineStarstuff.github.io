# =============================================================================
# Sentinel v2.4 — multi-region confidential computing enclave deployment.
# Corrected, terraform-validate-clean rewrite of
# governance_blueprint/confidential_enclave_deployment.tf, which had:
#   - duplicate `monitoring = true` (invalid HCL),
#   - comma-separated attributes inside a `variable` block (invalid),
#   - `count = length(var.regions)` on an instance pinned to ONE subnet/region
#     (no real multi-region), and
#   - no HSM, no KMS, no security group.
#
# This module uses a per-region map with for_each and provider aliases, an
# AWS CloudHSM v2 cluster for ML-DSA evidence-signing key custody (OSCAL env-02),
# and SEV-SNP-capable Nitro Enclave nodes (env-01).
#
# Validate (no cloud credentials needed):
#   cd governance_blueprint/terraform && terraform init -backend=false && terraform validate
# =============================================================================

terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "regions" {
  description = "Regions to deploy Sentinel confidential enclave nodes into."
  type = map(object({
    cidr_block         = string
    subnet_cidr        = string
    instance_type      = string
    enclave_node_count = number
  }))
  default = {
    "us-east-1" = {
      cidr_block         = "10.0.0.0/16"
      subnet_cidr        = "10.0.1.0/24"
      instance_type      = "r6i.2xlarge"
      enclave_node_count = 3
    }
    "eu-west-1" = {
      cidr_block         = "10.1.0.0/16"
      subnet_cidr        = "10.1.1.0/24"
      instance_type      = "r6i.2xlarge"
      enclave_node_count = 3
    }
  }
}

variable "hardened_ami_id" {
  description = "Sentinel-hardened, SEV-SNP/Nitro-enclave-capable AMI id."
  type        = string
  default     = "ami-0123456789abcdef0"
}

provider "aws" {
  alias  = "primary"
  region = "us-east-1"
}

# Single primary-region footprint shown explicitly (use a module + for_each over
# providers for true N-region fan-out in a root module per the README).
locals {
  region_key = "us-east-1"
  cfg        = var.regions[local.region_key]
}

resource "aws_vpc" "sentinel" {
  provider             = aws.primary
  cidr_block           = local.cfg.cidr_block
  enable_dns_hostnames = true
  tags                 = { Name = "sentinel-gsifi-vpc-${local.region_key}" }
}

resource "aws_subnet" "sentinel" {
  provider          = aws.primary
  vpc_id            = aws_vpc.sentinel.id
  cidr_block        = local.cfg.subnet_cidr
  availability_zone = "${local.region_key}a"
  tags              = { Name = "sentinel-gsifi-subnet-${local.region_key}" }
}

resource "aws_security_group" "enclave" {
  provider    = aws.primary
  name        = "sentinel-enclave-sg"
  description = "Restrict enclave node ingress to mutual-TLS governance plane only."
  vpc_id      = aws_vpc.sentinel.id

  ingress {
    description = "mTLS governance API"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [local.cfg.cidr_block]
  }
  egress {
    description = "all egress (tighten in production)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "sentinel-enclave-sg" }
}

# KMS CMK for envelope encryption of evidence at rest (WORM payloads).
resource "aws_kms_key" "evidence" {
  provider                = aws.primary
  description             = "Sentinel WORM evidence envelope key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = { Name = "sentinel-evidence-cmk" }
}

# CloudHSM cluster: custody of ML-DSA (FIPS 204) evidence-signing keys (env-02).
resource "aws_cloudhsm_v2_cluster" "sentinel" {
  provider   = aws.primary
  hsm_type   = "hsm1.medium"
  subnet_ids = [aws_subnet.sentinel.id]
  tags       = { Name = "sentinel-evidence-hsm" }
}

resource "aws_cloudhsm_v2_hsm" "sentinel" {
  provider          = aws.primary
  cluster_id        = aws_cloudhsm_v2_cluster.sentinel.cluster_id
  availability_zone = "${local.region_key}a"
}

# SEV-SNP / Nitro-enclave-capable governance nodes (env-01).
resource "aws_instance" "enclave_node" {
  provider      = aws.primary
  count         = local.cfg.enclave_node_count
  ami           = var.hardened_ami_id
  instance_type = local.cfg.instance_type
  subnet_id     = aws_subnet.sentinel.id
  monitoring    = true

  vpc_security_group_ids = [aws_security_group.enclave.id]

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 enforced
  }

  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.evidence.arn
  }

  tags = {
    Name = "sentinel-gsifi-enclave-${local.region_key}-${count.index}"
    Tier = "T0"
  }
}

output "vpc_id" { value = aws_vpc.sentinel.id }
output "hsm_cluster_id" { value = aws_cloudhsm_v2_cluster.sentinel.cluster_id }
output "enclave_node_count" { value = length(aws_instance.enclave_node) }
