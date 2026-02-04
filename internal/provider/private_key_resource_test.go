package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"vanitytls": providerserver.NewProtocol6WithError(New()),
}

func TestComputeSKID(t *testing.T) {
	// Helper to validate SKID format
	validateSKID := func(skid, keyType string) {
		if len(skid) != 40 {
			t.Errorf("%s SKID wrong length: got %d, want 40", keyType, len(skid))
		}
		for _, c := range skid {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("%s SKID contains non-hex character: %c", keyType, c)
			}
		}
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validateSKID(computeSKID(&ec.PublicKey), "ECDSA")

	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	validateSKID(computeSKID(edPub), "ED25519")

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	validateSKID(computeSKID(&rk.PublicKey), "RSA")
}

func TestEncodePEM(t *testing.T) {
	// Helper to validate PEM encoding
	validatePEM := func(privPEM, pubPEM []byte, expectedPrivType, keyType string) {
		privBlock, _ := pem.Decode(privPEM)
		pubBlock, _ := pem.Decode(pubPEM)
		if privBlock == nil {
			t.Errorf("%s private key PEM decode failed", keyType)
			return
		}
		if pubBlock == nil {
			t.Errorf("%s public key PEM decode failed", keyType)
			return
		}
		if privBlock.Type != expectedPrivType {
			t.Errorf("%s private key type: got %q, want %q", keyType, privBlock.Type, expectedPrivType)
		}
		if pubBlock.Type != "PUBLIC KEY" {
			t.Errorf("%s public key type: got %q, want %q", keyType, pubBlock.Type, "PUBLIC KEY")
		}
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, pub := encodePEM(ec)
	validatePEM(priv, pub, "EC PRIVATE KEY", "ECDSA")

	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	priv, pub = encodePEM(ed)
	validatePEM(priv, pub, "PRIVATE KEY", "ED25519")

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv, pub = encodePEM(rk)
	validatePEM(priv, pub, "RSA PRIVATE KEY", "RSA")
}

func TestFindKey(t *testing.T) {
	tests := []struct {
		name   string
		algo   string
		curve  string
		bits   int
		prefix string
	}{
		{"ECDSA", "ECDSA", "P256", 0, "a"},
		{"ED25519", "ED25519", "", 0, "b"},
		{"RSA", "RSA", "", 2048, "c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			key, skid, err := findKey(ctx, tt.algo, tt.curve, tt.bits, tt.prefix)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if key == nil {
				t.Error("key is nil")
			}
			if !strings.HasPrefix(skid, tt.prefix) {
				t.Errorf("skid %q does not have prefix %q", skid, tt.prefix)
			}
		})
	}
}

func TestFindKeyTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err := findKey(ctx, "ECDSA", "P256", 0, "abcdef12")
	if err == nil {
		t.Error("expected timeout")
	}
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name  string
		algo  string
		curve string
		bits  int
	}{
		{"ECDSA_P256", "ECDSA", "P256", 0},
		{"ECDSA_P384", "ECDSA", "P384", 0},
		{"ECDSA_P521", "ECDSA", "P521", 0},
		{"ED25519", "ED25519", "", 0},
		{"RSA_2048", "RSA", "", 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub := generateKey(tt.algo, tt.curve, tt.bits)
			if priv == nil || pub == nil {
				t.Errorf("generateKey(%s, %s, %d) returned nil", tt.algo, tt.curve, tt.bits)
			}
		})
	}

	t.Run("UnknownAlgorithm", func(t *testing.T) {
		priv, pub := generateKey("UNKNOWN", "", 0)
		if priv != nil || pub != nil {
			t.Error("generateKey with unknown algo should return nil")
		}
	})
}

// Resource unit tests

func TestNewPrivateKeyResource(t *testing.T) {
	r := NewPrivateKeyResource()
	if r == nil {
		t.Error("NewPrivateKeyResource returned nil")
	}
}

func TestPrivateKeyResourceMetadata(t *testing.T) {
	r := &PrivateKeyResource{}
	req := resource.MetadataRequest{ProviderTypeName: "vanitytls"}
	resp := &resource.MetadataResponse{}

	r.Metadata(context.Background(), req, resp)

	if resp.TypeName != "vanitytls_private_key" {
		t.Errorf("expected vanitytls_private_key, got %s", resp.TypeName)
	}
}

func TestPrivateKeyResourceSchema(t *testing.T) {
	r := &PrivateKeyResource{}
	req := resource.SchemaRequest{}
	resp := &resource.SchemaResponse{}

	r.Schema(context.Background(), req, resp)

	// Verify all expected attributes exist
	attrs := resp.Schema.Attributes
	expectedAttrs := []string{"id", "algorithm", "ecdsa_curve", "rsa_bits", "skid_prefix", "timeout", "private_key_pem", "public_key_pem", "skid"}
	for _, attr := range expectedAttrs {
		if _, ok := attrs[attr]; !ok {
			t.Errorf("missing attribute: %s", attr)
		}
	}

	// Verify skid_prefix is required
	if skidAttr, ok := attrs["skid_prefix"].(schema.StringAttribute); ok {
		if !skidAttr.Required {
			t.Error("skid_prefix should be required")
		}
	}
}

func TestPrivateKeyResourceNoOpMethods(t *testing.T) {
	r := &PrivateKeyResource{}
	ctx := context.Background()

	// Read and Delete are no-ops - verify they don't panic
	r.Read(ctx, resource.ReadRequest{}, &resource.ReadResponse{})
	r.Delete(ctx, resource.DeleteRequest{}, &resource.DeleteResponse{})
}

// Acceptance tests

func TestAccECDSA(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = "ab"
}`,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "algorithm", "ECDSA"),
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "ecdsa_curve", "P256"),
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "timeout", "120"),
				tfresource.TestMatchResourceAttr("vanitytls_private_key.test", "skid", regexp.MustCompile(`^ab`)),
			),
		}},
	})
}

func TestAccED25519(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  algorithm   = "ED25519"
  skid_prefix = "12"
}`,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "algorithm", "ED25519"),
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "timeout", "120"),
				tfresource.TestMatchResourceAttr("vanitytls_private_key.test", "skid", regexp.MustCompile(`^12`)),
			),
		}},
	})
}

func TestAccRSA(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  algorithm   = "RSA"
  skid_prefix = "9"
  timeout     = 300
}`,
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "algorithm", "RSA"),
				tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "rsa_bits", "2048"),
				tfresource.TestMatchResourceAttr("vanitytls_private_key.test", "skid", regexp.MustCompile(`^9`)),
			),
		}},
	})
}

func TestAccInvalidAlgo(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  algorithm   = "BAD"
  skid_prefix = "ab"
}`,
			ExpectError: regexp.MustCompile(`ECDSA|ED25519|RSA`),
		}},
	})
}

func TestAccInvalidPrefix(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = "xyz"
}`,
			ExpectError: regexp.MustCompile(`hex`),
		}},
	})
}

func TestAccInvalidCurve(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  ecdsa_curve = "P999"
  skid_prefix = "ab"
}`,
			ExpectError: regexp.MustCompile(`P256|P384|P521`),
		}},
	})
}

func TestAccInvalidRSABits(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  algorithm   = "RSA"
  rsa_bits    = 1024
  skid_prefix = "ab"
}`,
			ExpectError: regexp.MustCompile(`2048|3072|4096`),
		}},
	})
}

func TestAccInvalidPrefixTooLong(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = "abcdef123"
}`,
			ExpectError: regexp.MustCompile(`1-8`),
		}},
	})
}

func TestAccInvalidPrefixEmpty(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = ""
}`,
			ExpectError: regexp.MustCompile(`1-8`),
		}},
	})
}

func TestAccTimeout(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = "abcdef99"
  timeout     = 1
}`,
			ExpectError: regexp.MustCompile(`timeout`),
		}},
	})
}

func TestAccUpdateTimeout(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = "ab"
  timeout     = 120
}`,
				Check: tfresource.TestMatchResourceAttr("vanitytls_private_key.test", "skid", regexp.MustCompile(`^ab`)),
			},
			{
				Config: `
resource "vanitytls_private_key" "test" {
  skid_prefix = "ab"
  timeout     = 180
}`,
				Check: tfresource.TestCheckResourceAttr("vanitytls_private_key.test", "timeout", "180"),
			},
		},
	})
}
