package provider

import (
	"context"
	"fmt"

	"github.com/counsel/terraform-provider-counsel/internal/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCompany() *schema.Resource {
	return &schema.Resource{
		Description: "Creates a Counsel company tenant. Each company gets its own" +
			" Ed25519 key pair, attestation chain, and bootstrap API key.",

		Create: resourceCompanyCreate,
		Read:   resourceCompanyRead,
		// Companies are immutable after creation — no Update.
		Update: resourceCompanyUpdate,
		Delete: resourceCompanyDelete,

		// Import: terraform import counsel_company.acme <bootstrap-api-key>
		// The import ID is the bootstrap API key returned at creation time.
		Importer: &schema.ResourceImporter{
			StateContext: resourceCompanyImport,
		},

		Schema: map[string]*schema.Schema{
			"company_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique company identifier.",
			},
			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				ForceNew:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Arbitrary string key/value metadata stored with the company.",
			},
			"spiffe_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "SPIFFE ID assigned to this company.",
			},
			"registered_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ISO 8601 timestamp of company registration.",
			},
			"api_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Bootstrap API key. Shown once at creation; stored in Terraform state.",
			},
		},
	}
}

func resourceCompanyCreate(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	companyID := d.Get("company_id").(string)

	metadata := map[string]interface{}{}
	if v, ok := d.GetOk("metadata"); ok {
		for k, val := range v.(map[string]interface{}) {
			metadata[k] = val
		}
	}

	result, err := c.CreateCompany(companyID, metadata)
	if err != nil {
		return fmt.Errorf("create company %q: %w", companyID, err)
	}

	d.SetId(companyID)
	d.Set("spiffe_id", result["spiffeId"])
	d.Set("registered_at", result["registeredAt"])
	d.Set("api_key", result["apiKey"])
	return nil
}

func resourceCompanyRead(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	apiKey := d.Get("api_key").(string)

	result, err := c.GetCompany(apiKey)
	if err != nil {
		return fmt.Errorf("read company %q: %w", d.Id(), err)
	}
	if result == nil {
		// Company is gone; remove from state.
		d.SetId("")
		return nil
	}

	d.SetId(result["companyId"].(string))
	d.Set("company_id", result["companyId"])
	d.Set("spiffe_id", result["spiffeId"])
	d.Set("registered_at", result["registeredAt"])
	return nil
}

// resourceCompanyUpdate is a no-op because all fields are ForceNew.
// It exists so Terraform does not complain about missing Update when the
// schema has no mutable fields — the SDK still requires the function.
func resourceCompanyUpdate(_ *schema.ResourceData, _ interface{}) error {
	return nil
}

// resourceCompanyDelete is intentionally a no-op. The Counsel API does not
// expose a company deletion endpoint; removing a company requires direct
// database access. Terraform will still remove the resource from state.
func resourceCompanyDelete(_ *schema.ResourceData, _ interface{}) error {
	return nil
}

// resourceCompanyImport sets the api_key from the import ID so that
// resourceCompanyRead can authenticate and populate the rest of the fields.
func resourceCompanyImport(_ context.Context, d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	// The import ID is the bootstrap API key.
	d.Set("api_key", d.Id())
	return []*schema.ResourceData{d}, nil
}
