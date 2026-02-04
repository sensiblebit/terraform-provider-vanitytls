package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
)

func TestProviderMetadata(t *testing.T) {
	p := New()
	req := provider.MetadataRequest{}
	resp := &provider.MetadataResponse{}

	p.Metadata(context.Background(), req, resp)

	if resp.TypeName != "vanitytls" {
		t.Errorf("expected TypeName 'vanitytls', got %q", resp.TypeName)
	}
}

func TestProviderSchema(t *testing.T) {
	p := New()
	req := provider.SchemaRequest{}
	resp := &provider.SchemaResponse{}

	p.Schema(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected schema errors: %v", resp.Diagnostics)
	}

	// Provider should have no configuration attributes
	if len(resp.Schema.Attributes) != 0 {
		t.Errorf("expected no attributes, got %d", len(resp.Schema.Attributes))
	}
}

func TestProviderResources(t *testing.T) {
	p := &VanityTLSProvider{}
	resources := p.Resources(context.Background())

	if len(resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(resources))
	}
}

func TestProviderDataSources(t *testing.T) {
	p := &VanityTLSProvider{}
	dataSources := p.DataSources(context.Background())

	if len(dataSources) != 0 {
		t.Errorf("expected no data sources, got %d", len(dataSources))
	}
}

func TestProviderConfigure(t *testing.T) {
	p := &VanityTLSProvider{}
	req := provider.ConfigureRequest{}
	resp := &provider.ConfigureResponse{}

	p.Configure(context.Background(), req, resp)

	// Configure is a no-op, should not produce errors
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected configure errors: %v", resp.Diagnostics)
	}
}
