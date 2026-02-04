---
page_title: "vanitytls_private_key Resource - vanitytls"
description: |-
  Generates a private key with a vanity Subject Key Identifier (SKID) prefix.
---

# vanitytls_private_key (Resource)

Generates a TLS private key where the SKID starts with your chosen hex prefix.

## Example Usage

### Basic (ECDSA P256)

```hcl
resource "vanitytls_private_key" "example" {
  skid_prefix = "cafe"
}
```

### ED25519

```hcl
resource "vanitytls_private_key" "ed25519" {
  algorithm   = "ED25519"
  skid_prefix = "ed"
}
```

### ECDSA P384

```hcl
resource "vanitytls_private_key" "p384" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
  skid_prefix = "beef"
}
```

### RSA

```hcl
resource "vanitytls_private_key" "rsa" {
  algorithm   = "RSA"
  rsa_bits    = 4096
  skid_prefix = "a"      # Keep short - RSA is slow
  timeout     = 300      # May need more time
}
```

### With CSR (using hashicorp/tls)

```hcl
resource "vanitytls_private_key" "server" {
  skid_prefix = "c0de"
}

resource "tls_cert_request" "server" {
  private_key_pem = vanitytls_private_key.server.private_key_pem

  subject {
    common_name  = "server.example.com"
    organization = "Example Corp"
  }

  dns_names = ["server.example.com"]
}
```

## Schema

### Required

- `skid_prefix` (String) - Hex prefix (1-8 characters) that the SKID must start with. Case-insensitive.

### Optional

- `algorithm` (String) - Key algorithm. One of `ECDSA` (default), `ED25519`, or `RSA`.
- `ecdsa_curve` (String) - ECDSA curve. One of `P256` (default), `P384`, or `P521`. Only used when algorithm is ECDSA.
- `rsa_bits` (Number) - RSA key size. One of `2048` (default), `3072`, or `4096`. Only used when algorithm is RSA.
- `timeout` (Number) - Maximum seconds to search for a matching key. Default: `120`.

### Read-Only

- `id` (String) - The full SKID (same as `skid`).
- `private_key_pem` (String, Sensitive) - PEM-encoded private key.
- `public_key_pem` (String) - PEM-encoded public key.
- `skid` (String) - Full Subject Key Identifier (40 hex characters).

## How SKID is Calculated

The SKID is calculated per [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093):

1. Marshal the public key to PKIX/DER format
2. Extract the SubjectPublicKey bit string
3. SHA-256 hash the SubjectPublicKey bytes
4. Truncate to 160 bits (20 bytes = 40 hex characters)

## Performance Notes

Key generation uses all CPU cores in parallel. Expected search times:

| Prefix | Expected Keys | ECDSA/ED25519 | RSA 2048 |
|--------|---------------|---------------|----------|
| 1 char | ~16 | instant | instant |
| 2 char | ~256 | instant | ~1 sec |
| 3 char | ~4K | instant | ~10 sec |
| 4 char | ~65K | <1 sec | ~3 min |
| 5 char | ~1M | ~5 sec | timeout |
| 6 char | ~16M | ~1 min | timeout |

RSA key generation is ~100x slower than ECDSA/ED25519. For RSA, use short prefixes and increase timeout.

## Update Behavior

Only `timeout` can be updated in-place. Changes to `algorithm`, `ecdsa_curve`, `rsa_bits`, or `skid_prefix` will trigger resource replacement (destroy and recreate).

## Import

Import is not supported. Keys are generated, not fetched from an external source.
