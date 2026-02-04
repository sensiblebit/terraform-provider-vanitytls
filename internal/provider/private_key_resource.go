package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &PrivateKeyResource{}

type PrivateKeyResource struct{}

type PrivateKeyResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Algorithm     types.String `tfsdk:"algorithm"`
	ECDSACurve    types.String `tfsdk:"ecdsa_curve"`
	RSABits       types.Int64  `tfsdk:"rsa_bits"`
	SKIDPrefix    types.String `tfsdk:"skid_prefix"`
	Timeout       types.Int64  `tfsdk:"timeout"`
	PrivateKeyPEM types.String `tfsdk:"private_key_pem"`
	PublicKeyPEM  types.String `tfsdk:"public_key_pem"`
	SKID          types.String `tfsdk:"skid"`
}

func NewPrivateKeyResource() resource.Resource {
	return &PrivateKeyResource{}
}

func (r *PrivateKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_private_key"
}

func (r *PrivateKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a private key with a vanity SKID prefix.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"algorithm": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Default:       stringdefault.StaticString("ECDSA"),
				Description:   "Key algorithm: ECDSA (default), ED25519, or RSA.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"ecdsa_curve": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Default:       stringdefault.StaticString("P256"),
				Description:   "ECDSA curve: P256 (default), P384, or P521. Only used when algorithm is ECDSA.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"rsa_bits": schema.Int64Attribute{
				Optional:      true,
				Computed:      true,
				Default:       int64default.StaticInt64(2048),
				Description:   "RSA key size: 2048 (default), 3072, or 4096. Only used when algorithm is RSA.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"skid_prefix": schema.StringAttribute{
				Required:      true,
				Description:   "Hex prefix (1-8 characters) that the SKID must start with.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"timeout": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(120),
				Description: "Maximum seconds to search for a matching key. Default: 120.",
			},
			"private_key_pem": schema.StringAttribute{
				Computed:      true,
				Sensitive:     true,
				Description:   "PEM-encoded private key.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"public_key_pem": schema.StringAttribute{
				Computed:      true,
				Description:   "PEM-encoded public key.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"skid": schema.StringAttribute{
				Computed:      true,
				Description:   "Full Subject Key Identifier (40 hex characters).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *PrivateKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PrivateKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	algo := data.Algorithm.ValueString()
	curve := data.ECDSACurve.ValueString()
	bits := int(data.RSABits.ValueInt64())
	prefix := strings.ToLower(data.SKIDPrefix.ValueString())
	timeout := data.Timeout.ValueInt64()

	// Validate inputs
	if algo != "ECDSA" && algo != "ED25519" && algo != "RSA" {
		resp.Diagnostics.AddError("Invalid algorithm", "algorithm must be ECDSA, ED25519, or RSA")
		return
	}
	if curve != "P256" && curve != "P384" && curve != "P521" {
		resp.Diagnostics.AddError("Invalid ECDSA curve", "ecdsa_curve must be P256, P384, or P521")
		return
	}
	if bits != 2048 && bits != 3072 && bits != 4096 {
		resp.Diagnostics.AddError("Invalid RSA key size", "rsa_bits must be 2048, 3072, or 4096")
		return
	}
	if len(prefix) < 1 || len(prefix) > 8 {
		resp.Diagnostics.AddError("Invalid SKID prefix length", "skid_prefix must be 1-8 hex characters")
		return
	}
	for _, c := range prefix {
		if !strings.ContainsRune("0123456789abcdef", c) {
			resp.Diagnostics.AddError("Invalid SKID prefix", "skid_prefix must contain only hex characters (0-9, a-f)")
			return
		}
	}

	// Generate
	genCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	priv, skid, err := findKey(genCtx, algo, curve, bits, prefix)
	if err != nil {
		resp.Diagnostics.AddError("Key generation failed", err.Error())
		return
	}

	privPEM, pubPEM := encodePEM(priv)
	data.ID = types.StringValue(skid)
	data.PrivateKeyPEM = types.StringValue(string(privPEM))
	data.PublicKeyPEM = types.StringValue(string(pubPEM))
	data.SKID = types.StringValue(skid)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PrivateKeyResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

func (r *PrivateKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var state PrivateKeyResourceModel
	var plan PrivateKeyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only timeout can be updated without replace
	state.Timeout = plan.Timeout

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PrivateKeyResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// findKey generates keys in parallel until one matches the SKID prefix.
// Uses all CPU cores. First match wins; other goroutines stop immediately.
func findKey(ctx context.Context, algo, curve string, bits int, prefix string) (crypto.PrivateKey, string, error) {
	type result struct {
		privateKey crypto.PrivateKey
		skid       string
	}

	found := make(chan result, 1)
	done := make(chan struct{})
	var once sync.Once

	// Start one worker per CPU core
	numWorkers := runtime.NumCPU()
	for range numWorkers {
		go func() {
			for {
				// Check if we should stop
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				default:
					// Continue generating keys
				}

				// Generate a key based on algorithm
				privateKey, publicKey := generateKey(algo, curve, bits)
				if privateKey == nil {
					continue
				}

				// Check if SKID matches prefix
				skid := computeSKID(publicKey)
				if strings.HasPrefix(skid, prefix) {
					// First match wins - signal all workers to stop
					once.Do(func() {
						found <- result{privateKey, skid}
						close(done)
					})
					return
				}
			}
		}()
	}

	// Wait for a match or timeout
	select {
	case match := <-found:
		return match.privateKey, match.skid, nil
	case <-ctx.Done():
		// Don't close(done) here - workers will exit via ctx.Done()
		// Closing here could race with a worker's once.Do closing done
		return nil, "", fmt.Errorf("timeout: no key found with prefix %q", prefix)
	}
}

// generateKey creates a new key pair for the given algorithm.
// Returns nil if key generation fails.
func generateKey(algo, curve string, bits int) (crypto.PrivateKey, crypto.PublicKey) {
	switch algo {
	case "ECDSA":
		var ecCurve elliptic.Curve
		switch curve {
		case "P384":
			ecCurve = elliptic.P384()
		case "P521":
			ecCurve = elliptic.P521()
		default:
			ecCurve = elliptic.P256()
		}
		key, err := ecdsa.GenerateKey(ecCurve, rand.Reader)
		if err != nil {
			return nil, nil
		}
		return key, &key.PublicKey

	case "ED25519":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil
		}
		return privateKey, publicKey

	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil
		}
		return key, &key.PublicKey

	default:
		return nil, nil
	}
}

// subjectPublicKeyInfo mirrors the ASN.1 structure in X.509 certificates.
// We only need to extract the SubjectPublicKey field.
type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue
	SubjectPublicKey asn1.BitString
}

// computeSKID calculates the Subject Key Identifier per RFC 7093:
// SHA-256 hash of the SubjectPublicKey, truncated to 160 bits (20 bytes).
func computeSKID(pub crypto.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)

	var spki subjectPublicKeyInfo
	_, _ = asn1.Unmarshal(der, &spki) // Error ignored: der is valid PKIX from x509.MarshalPKIXPublicKey

	hash := sha256.Sum256(spki.SubjectPublicKey.Bytes)
	return hex.EncodeToString(hash[:20])
}

// encodePEM converts a private key to PEM-encoded private and public key bytes.
func encodePEM(priv crypto.PrivateKey) (privateKeyPEM []byte, publicKeyPEM []byte) {
	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		privDER, _ := x509.MarshalECPrivateKey(key)
		pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	case ed25519.PrivateKey:
		privDER, _ := x509.MarshalPKCS8PrivateKey(key)
		pubDER, _ := x509.MarshalPKIXPublicKey(key.Public())
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	case *rsa.PrivateKey:
		privDER := x509.MarshalPKCS1PrivateKey(key)
		pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
		publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	}

	return privateKeyPEM, publicKeyPEM
}
