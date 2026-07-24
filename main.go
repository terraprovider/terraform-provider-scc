// terraform-provider-scc is a Terraform/OpenTofu provider for Microsoft Purview /
// Security & Compliance, generated from the ExchangeOnlineManagement cmdlet
// metadata (Connect-IPPSSession surface) via go-exoscc.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/terraprovider/terraform-provider-scc/internal/provider"
)

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// Registry address; the same module publishes to the OpenTofu registry too.
		Address: "registry.terraform.io/terraprovider/scc",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
