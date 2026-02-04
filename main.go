package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/sensiblebit/terraform-provider-vanitytls/internal/provider"
)

func main() {
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/sensiblebit/vanitytls",
	}

	err := providerserver.Serve(context.Background(), provider.New, opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
