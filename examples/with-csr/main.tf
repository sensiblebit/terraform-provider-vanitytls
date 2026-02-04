terraform {
  required_providers {
    vanitytls = {
      source  = "sensiblebit/vanitytls"
      version = "~> 1.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Generate key with vanity SKID
resource "vanitytls_private_key" "server" {
  skid_prefix = "c0de"
}

# Use with hashicorp/tls for CSR
resource "tls_cert_request" "server" {
  private_key_pem = vanitytls_private_key.server.private_key_pem

  subject {
    common_name  = "server.example.com"
    organization = "Example Corp"
  }

  dns_names = [
    "server.example.com",
    "*.example.com",
  ]
}

output "skid" {
  value = vanitytls_private_key.server.skid
}

output "csr" {
  value = tls_cert_request.server.cert_request_pem
}
