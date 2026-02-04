terraform {
  required_providers {
    vanitytls = {
      source  = "sensiblebit/vanitytls"
      version = "~> 1.0"
    }
  }
}

resource "vanitytls_private_key" "ed25519" {
  algorithm   = "ED25519"
  skid_prefix = "ed"
}

output "skid" {
  value = vanitytls_private_key.ed25519.skid
}

output "public_key" {
  value = vanitytls_private_key.ed25519.public_key_pem
}
