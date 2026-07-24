terraform {
  required_providers {
    scc = {
      source = "terraprovider/scc"
    }
  }
}

# Authentication mirrors the AzureAD / AzureRM providers. Any ARM_*/AZURE_*
# environment variable is picked up automatically; values below are optional
# overrides. App-only (client secret) example:
provider "scc" {
  tenant_id     = var.tenant_id
  client_id     = var.client_id
  client_secret = var.client_secret

  # Required for Purview/compliance routing under app-only auth:
  organization = "contoso.onmicrosoft.com"
}
