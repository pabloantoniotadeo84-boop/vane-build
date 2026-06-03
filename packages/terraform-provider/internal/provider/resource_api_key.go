package provider

import (
	"fmt"

	"github.com/vane-build/terraform-provider-vane/internal/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAPIKey() *schema.Resource {
	return &schema.Resource{
		Description: "Creates an additional API key scoped to a Vane company." +
			" The key value is shown once and stored in Terraform state.",

		Create: resourceAPIKeyCreate,
		Read:   resourceAPIKeyRead,
		// Label is immutable — no Update; Terraform will ForceNew on label change.
		Update: resourceAPIKeyUpdate,
		Delete: resourceAPIKeyDelete,

		// API keys cannot be imported because the key value is shown only once
		// and cannot be retrieved from the server after creation.

		Schema: map[string]*schema.Schema{
			"auth_api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Company API key used to authenticate the key-creation request.",
			},
			"label": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Human-readable label for the key.",
			},
			"key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The generated API key value. Store this — it cannot be retrieved again.",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ISO 8601 creation timestamp.",
			},
		},
	}
}

func resourceAPIKeyCreate(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	authKey := d.Get("auth_api_key").(string)
	label   := d.Get("label").(string)

	result, err := c.CreateAPIKey(authKey, label)
	if err != nil {
		return fmt.Errorf("create API key: %w", err)
	}

	key := result["key"].(string)
	d.SetId(key)
	d.Set("key", key)
	d.Set("created_at", result["createdAt"])
	return nil
}

// resourceAPIKeyRead verifies the key is still valid by listing all keys for the
// company and checking whether this key's ID appears in the list.
func resourceAPIKeyRead(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	// Authenticate with the stored key itself; if it was revoked it will return 401.
	storedKey := d.Get("key").(string)
	if storedKey == "" {
		storedKey = d.Id()
	}

	keys, err := c.GetAPIKeys(storedKey)
	if err != nil {
		return fmt.Errorf("read API key: %w", err)
	}
	if keys == nil {
		// Auth failed — key is gone.
		d.SetId("")
		return nil
	}

	// Confirm this specific key still exists in the list.
	found := false
	for _, k := range keys {
		if k["key"] == d.Id() {
			found = true
			if v, ok := k["createdAt"].(string); ok {
				d.Set("created_at", v)
			}
			break
		}
	}
	if !found {
		d.SetId("")
	}
	return nil
}

// resourceAPIKeyUpdate is a no-op because label is ForceNew.
func resourceAPIKeyUpdate(_ *schema.ResourceData, _ interface{}) error {
	return nil
}

// resourceAPIKeyDelete revokes the key via DELETE /v1/keys/:key.
func resourceAPIKeyDelete(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	authKey    := d.Get("auth_api_key").(string)
	keyToDelete := d.Id()

	if err := c.DeleteAPIKey(authKey, keyToDelete); err != nil {
		return fmt.Errorf("delete API key %q: %w", keyToDelete, err)
	}
	return nil
}
