package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/terraprovider/go-exoscc/adminapi"
	"github.com/terraprovider/go-exoscc/purview"
	"github.com/terraprovider/terraform-provider-scc/internal/clients"
	"github.com/terraprovider/tf-msadmin/authschema"
)

// sccProvider implements the Security & Compliance ("Purview") provider.
type sccProvider struct{ version string }

// New returns the provider constructor for the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &sccProvider{version: version} }
}

func (p *sccProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "scc"
	resp.Version = p.version
}

// providerModel embeds the shared azuread/azurerm-aligned auth block and adds
// the organization routing hint (required for compliance/Purview routing under
// app-only auth).
type providerModel struct {
	authschema.Model
	Organization types.String `tfsdk:"organization"`
}

func (p *sccProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	attrs := authschema.Attributes()
	attrs["organization"] = schema.StringAttribute{
		Optional:    true,
		Description: "Tenant routing domain (contoso.onmicrosoft.com); required for compliance routing under app-only.",
	}
	resp.Schema = schema.Schema{
		Description: "Manage Microsoft Purview / Security & Compliance via the Admin API. Authentication mirrors the AzureAD/AzureRM providers (ARM_*/AZURE_* env vars supported).",
		Attributes:  attrs,
	}
}

func (p *sccProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Explicit config overlaid onto the ARM_*/AZURE_* environment.
	cfg := m.Config()

	tp, err := cfg.Build()
	if err != nil {
		resp.Diagnostics.AddError("Authentication configuration error", err.Error())
		return
	}

	// Resolve the tenant GUID from the token (the Admin API path needs the tid claim).
	tok, err := tp.Token(ctx, adminapi.SCC.Resource)
	if err != nil {
		resp.Diagnostics.AddError("Authentication failed", err.Error())
		return
	}
	tid := jwtClaim(tok, "tid")
	if tid == "" {
		resp.Diagnostics.AddError("Authentication failed", "could not read tenant id (tid) from the access token")
		return
	}

	org := m.Organization.ValueString()
	admin, err := adminapi.New(adminapi.Options{
		Cloud:        adminapi.SCC,
		TenantID:     tid,
		Tokens:       tp,
		Organization: org,
	})
	if err != nil {
		resp.Diagnostics.AddError("Client initialisation error", err.Error())
		return
	}

	c := &clients.Client{Admin: admin, SCC: purview.New(admin), TenantID: tid}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *sccProvider) Resources(_ context.Context) []func() resource.Resource {
	return generatedResources()
}

func (p *sccProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return generatedDataSources()
}

func jwtClaim(jwt, name string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(b, &claims) != nil {
		return ""
	}
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}
