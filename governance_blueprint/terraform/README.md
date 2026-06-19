# Sentinel v2.4 — Confidential Enclave Terraform Module

Corrected, `terraform validate`-clean rewrite of the (now deprecated)
`../confidential_enclave_deployment.tf`.

```bash
cd governance_blueprint/terraform
terraform init -backend=false   # downloads AWS provider ~> 5.0
terraform validate              # -> "Success! The configuration is valid."
terraform fmt -check            # formatting clean
```

## What it provisions (primary region shown explicitly)
- VPC + subnet + security group (mTLS-only ingress on 8443)
- KMS CMK (rotation enabled) for WORM evidence envelope encryption
- **AWS CloudHSM v2** cluster + HSM — custody of ML-DSA (FIPS 204) evidence-signing
  keys (OSCAL `env-02`)
- SEV-SNP / Nitro-enclave-capable T0 governance nodes with IMDSv2 enforced and
  encrypted root volumes (OSCAL `env-01`)

## True N-region fan-out
For production multi-region, wrap these resources in a child module and instantiate
once per region with a provider alias (`for_each` over `var.regions`), e.g.:

```hcl
module "region" {
  for_each = var.regions
  source   = "./modules/enclave-region"
  providers = { aws = aws.by_region[each.key] }
  cfg       = each.value
}
```
The single-region root here is kept flat so `terraform validate` runs without
multiple configured provider credentials.
