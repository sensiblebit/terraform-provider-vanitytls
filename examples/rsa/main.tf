terraform {
  required_providers {
    vanitytls = {
      source  = "sensiblebit/vanitytls"
      version = "~> 1.0"
    }
  }
}

# RSA is slow - use short prefix and longer timeout
resource "vanitytls_private_key" "rsa" {
  algorithm   = "RSA"
  rsa_bits    = 4096
  skid_prefix = "a"
  timeout     = 300
}

output "skid" {
  value = vanitytls_private_key.rsa.skid
}
