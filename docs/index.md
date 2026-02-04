---
page_title: "Provider: vanitytls"
description: |-
  Generate TLS private keys with vanity Subject Key Identifiers (SKID).
---

# VanityTLS Provider

Generate TLS private keys where the Subject Key Identifier (SKID) starts with a prefix you choose.

## What is a SKID?

The Subject Key Identifier is a hash of the public key, used to identify certificates and keys. This provider lets you generate keys with SKIDs that start with a specific hex prefix like `cafe`, `c0de`, or `dead`.

## Why?

- **Key identification**: Quickly identify keys by their SKID prefix
- **Organization**: Use prefixes to categorize keys (e.g., `ca` for CA keys, `srv` for servers)
- **Fun**: Generate keys with memorable SKIDs

## Example Usage

```hcl
terraform {
  required_providers {
    vanitytls = {
      source  = "sensiblebit/vanitytls"
      version = "~> 1.0"
    }
  }
}

resource "vanitytls_private_key" "example" {
  skid_prefix = "cafe"
}

output "skid" {
  value = vanitytls_private_key.example.skid
}
```

## Supported Algorithms

| Algorithm | Speed | Use Case |
|-----------|-------|----------|
| ECDSA (default) | Fast | General TLS, modern systems |
| ED25519 | Fastest | Modern TLS (Chrome 137+, Firefox 129+, Safari 17+) |
| RSA | Slow | Legacy compatibility |

## Performance

Longer prefixes take exponentially longer to find:

| Prefix Length | ECDSA/ED25519 | RSA |
|---------------|---------------|-----|
| 1-2 chars | instant | instant |
| 3-4 chars | <1 sec | seconds |
| 5 chars | ~5 sec | minutes |
| 6+ chars | minutes | may timeout |

Default timeout is 120 seconds. Increase with `timeout` attribute for longer prefixes.
