package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &VanityTLSProvider{}

type VanityTLSProvider struct{}

func New() provider.Provider {
	return &VanityTLSProvider{}
}

func (p *VanityTLSProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vanitytls"
}

func (p *VanityTLSProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for generating TLS keys with vanity Subject Key Identifiers (SKID).",
	}
}

func (p *VanityTLSProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *VanityTLSProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPrivateKeyResource,
	}
}

func (p *VanityTLSProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
