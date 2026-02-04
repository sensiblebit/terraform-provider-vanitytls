# Terraform Provider for Vanity TLS Keys

A Terraform provider for generating private keys with vanity Subject Key Identifiers (SKID).

## Quick Start

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
  skid_prefix = "c0de"
}

output "skid" {
  value = vanitytls_private_key.example.skid
}
```

## Features

- Generate private keys with custom SKID prefixes (1-8 hex chars)
- Supports ECDSA (P256, P384, P521), ED25519, and RSA
- Parallel key generation using all CPU cores
- Configurable timeout (default: 120 seconds)
- No external dependencies - pure local computation

## Resource: vanitytls_private_key

### Arguments

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `skid_prefix` | string | Yes | - | Hex prefix (1-8 chars) for SKID |
| `algorithm` | string | No | `ECDSA` | `ECDSA`, `ED25519`, or `RSA` |
| `ecdsa_curve` | string | No | `P256` | `P256`, `P384`, or `P521` |
| `rsa_bits` | number | No | `2048` | `2048`, `3072`, or `4096` |
| `timeout` | number | No | `120` | Max seconds to search |

### Attributes

| Name | Description |
|------|-------------|
| `id` | Full SKID (unique identifier) |
| `private_key_pem` | PEM-encoded private key (sensitive) |
| `public_key_pem` | PEM-encoded public key |
| `skid` | Full Subject Key Identifier (40 hex chars) |

## Performance

| Prefix | ECDSA | ED25519 | RSA 2048 |
|--------|-------|---------|----------|
| 1 hex | instant | instant | instant |
| 2 hex | instant | instant | ~1 sec |
| 3 hex | instant | instant | ~10 sec |
| 4 hex | <1 sec | <1 sec | ~3 min |
| 5 hex | ~5-10 sec | ~3-5 sec | timeout |
| 6 hex | ~1-2 min | ~1 min | timeout |

RSA is ~100x slower than ECDSA/ED25519. Use short prefixes or increase timeout.

## Examples

### ED25519 Key
```hcl
resource "vanitytls_private_key" "ed25519" {
  algorithm   = "ED25519"
  skid_prefix = "ed"
}
```

### RSA Key
```hcl
resource "vanitytls_private_key" "rsa" {
  algorithm   = "RSA"
  rsa_bits    = 4096
  skid_prefix = "a"
  timeout     = 300
}
```

### With hashicorp/tls for CSR
```hcl
resource "vanitytls_private_key" "ca" {
  skid_prefix = "ca"
}

resource "tls_cert_request" "ca" {
  private_key_pem = vanitytls_private_key.ca.private_key_pem
  subject {
    common_name = "My CA"
  }
}
```

---

# Technical Reference

## Architecture

### Provider Framework

Uses **Terraform Plugin Framework** (not SDK v2):
- `github.com/hashicorp/terraform-plugin-framework`
- Schema via structs with `tfsdk` tags
- Resources implement `resource.Resource` interface

### File Structure

```
internal/provider/
├── provider.go                    # Provider configuration (no-op)
├── provider_test.go               # Provider unit tests
├── private_key_resource.go        # Main resource implementation
└── private_key_resource_test.go   # Unit + acceptance tests
```

### No External Dependencies

- No API calls, no network required
- All computation in Terraform process
- Keys stored only in Terraform state

## Resource Lifecycle

### Create
1. Validate `skid_prefix` (1-8 hex chars)
2. Determine algorithm and params
3. Spawn `runtime.NumCPU()` worker goroutines
4. Generate keys until prefix match or timeout
5. Encode to PEM and store in state

### Read
No-op - state is source of truth

### Update
Only `timeout` can be updated in-place. Changes to `algorithm`, `ecdsa_curve`, `rsa_bits`, or `skid_prefix` trigger replacement.

### Delete
No-op - key only exists in state

### Import
Not supported (keys are generated, not fetched)

## SKID Calculation (RFC 7093)

```go
// 1. Marshal public key to PKIX/DER
der, _ := x509.MarshalPKIXPublicKey(publicKey)

// 2. Extract SubjectPublicKey bit string
var spki struct {
    Algorithm        struct { ... }
    SubjectPublicKey asn1.BitString
}
asn1.Unmarshal(der, &spki)

// 3. SHA-256, truncated to 160 bits
hash := sha256.Sum256(spki.SubjectPublicKey.Bytes)
skid := hex.EncodeToString(hash[:20])  // 40 hex chars
```

## Parallel Generation

- Workers: `runtime.NumCPU()` goroutines
- First match wins via `sync.Once`
- Others terminate via `done` channel
- Context timeout enforces max duration

## Supported Algorithms

| Algorithm | Options | PEM Type |
|-----------|---------|----------|
| ECDSA | P256, P384, P521 | `EC PRIVATE KEY` |
| ED25519 | (none) | `PRIVATE KEY` (PKCS#8) |
| RSA | 2048, 3072, 4096 | `RSA PRIVATE KEY` |

## Testing

### Unit Tests
```bash
go test -v ./... -run 'Test[^Acc]'
```

### Acceptance Tests
```bash
TF_ACC=1 go test -v ./... -timeout 10m
```

### Test Coverage
- All ECDSA curves (P256, P384, P521)
- ED25519
- RSA (short prefix)
- Timeout behavior
- Invalid input validation
- Case-insensitive prefix
- RequiresReplace behavior

## Development

### Build
```bash
go build -o terraform-provider-vanitytls
```

### Local Testing
```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "sensiblebit/vanitytls" = "/path/to/terraform-provider-vanitytls"
  }
  direct {}
}
```

## Publishing

1. Public repo named `terraform-provider-{NAME}`
2. GPG signing required
3. GitHub secrets:
   - `GPG_PRIVATE_KEY`
   - `GPG_PRIVATE_KEY_PASSPHRASE`
4. Tag and push: `git tag v1.0.0 && git push origin v1.0.0`
5. GoReleaser builds multi-platform binaries

## Code Patterns

- `planmodifier.UseStateForUnknown()` - computed fields
- `stringplanmodifier.RequiresReplace()` - immutable fields
- `Sensitive: true` - private keys
- Custom validators: `validator.String` interface
- Custom plan modifiers: `planmodifier.Int64` interface
