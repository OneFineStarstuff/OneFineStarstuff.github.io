# Terraform blueprint for G-SIFI multi-region confidential computing enclaves
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
  }
}
variable "regions" { type = list(string), default = ["us-east-1", "eu-west-1", "ap-southeast-1"] }
resource "aws_vpc" "sentinel_vpc" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "Sentinel-GSIFI-VPC" }
}
resource "aws_subnet" "sentinel_subnet" {
  vpc_id     = aws_vpc.sentinel_vpc.id
  cidr_block = "10.0.1.0/24"
  tags       = { Name = "Sentinel-GSIFI-Subnet" }
}
resource "aws_instance" "sentinel_enclave_node" {
  count         = length(var.regions)
  ami           = "ami-sentinel-hardened-v2.4"
  instance_type = "r6i.2xlarge"
  monitoring    = true
  monitoring    = true
  monitoring    = true
  subnet_id     = aws_subnet.sentinel_subnet.id
  enclave_options { enabled = true }
  metadata_options { http_endpoint = "enabled", http_tokens = "required" }
  tags = { Name = "Sentinel-GSIFI-Enclave-${count.index}", Governance = "v2.4" }
}
resource "azurerm_linux_virtual_machine" "sentinel_tdx_node" {
  name                = "sentinel-tdx-node"
  resource_group_name = "sentinel-governance-rg"
  location            = "West Europe"
  size                = "Standard_DC4es_v5"
  user_data           = base64encode("echo init")
  os_disk { caching = "ReadWrite", storage_account_type = "Premium_LRS", security_encryption_type = "VMGuestStateOnly" }
  source_image_reference { publisher = "Canonical", offer = "0001-com-ubuntu-confidential-vm-jammy", sku = "22_04-lts-cvm", version = "latest" }
}
