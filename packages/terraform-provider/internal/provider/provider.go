// Package provider implements a Terraform provider for the Vane API.
package provider

import (
	"github.com/vane-build/terraform-provider-vane/internal/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// New returns the Vane provider.
func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VANE_URL", "http://localhost:3000"),
				Description: "Base URL of the Vane API server.",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("VANE_API_KEY", ""),
				Description: "Default API key. Individual resources may override this.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"vane_company": resourceCompany(),
			"vane_agent":   resourceAgent(),
			"vane_api_key": resourceAPIKey(),
		},
		ConfigureFunc: configure,
	}
}

func configure(d *schema.ResourceData) (interface{}, error) {
	return &client.Config{
		URL:    d.Get("url").(string),
		APIKey: d.Get("api_key").(string),
	}, nil
}
