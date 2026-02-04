terraform {
  required_providers {
    vanitytls = {
      source  = "sensiblebit/vanitytls"
      version = "~> 1.0"
    }
  }
}

# Default: ECDSA P256
resource "vanitytls_private_key" "default" {
  skid_prefix = "cafe"
}

output "default_skid" {
  value = vanitytls_private_key.default.skid
}
