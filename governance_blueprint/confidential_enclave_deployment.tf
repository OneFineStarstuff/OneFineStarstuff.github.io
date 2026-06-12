# Terraform blueprint for G-SIFI multi-region confidential computing enclaves
# Supporting AMD SEV-SNP and Intel TDX for Sentinel v2.4 environments.

terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azure = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

variable "regions" {
  type    = list(string)
  default = ["us-east-1", "eu-west-1", "ap-southeast-1"]
}

# AWS Nitro Enclave provisioning (example)
resource "aws_instance" "sentinel_enclave_node" {
  count         = length(var.regions)
  ami           = "ami-sentinel-hardened-v2.4"
  instance_type = "r6i.2xlarge" # Supports Nitro Enclaves

  enclave_options {
    enabled = true
  }

  # vTPM and Attestation configuration
  # PCR_MATCH=TRUE enforcement via IAM and KMS policies
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name        = "Sentinel-GSIFI-Enclave-${count.index}"
    Governance  = "v2.4"
    Attestation = "vTPM-PCR"
  }
}

# Azure Confidential Computing (Intel TDX) provisioning (example)
resource "azurerm_linux_virtual_machine" "sentinel_tdx_node" {
  name                = "sentinel-tdx-node"
  resource_group_name = "sentinel-governance-rg"
  location            = "West Europe"
  size                = "Standard_DC4es_v5" # Intel TDX capable

  # Attestation agent initialization script
  user_data = base64encode(file("scripts/init_attestation.sh"))

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    security_encryption_type = "VMGuestStateOnly" # Confidential disk encryption
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-confidential-vm-jammy"
    sku       = "22_04-lts-cvm"
    version   = "latest"
  }
}
