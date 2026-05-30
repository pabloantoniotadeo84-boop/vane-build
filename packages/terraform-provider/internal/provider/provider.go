// Package provider implements a Terraform provider for the Counsel API.
package provider

import (
	"github.com/counsel/terraform-provider-counsel/internal/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// New returns the Counsel provider.
func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("COUNSEL_URL", "http://localhost:3000"),
				Description: "Base URL of the Counsel API server.",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("COUNSEL_API_KEY", ""),
				Description: "Default API key. Individual resources may override this.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"counsel_company": resourceCompany(),
			"counsel_agent":   resourceAgent(),
			"counsel_api_key": resourceAPIKey(),
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
