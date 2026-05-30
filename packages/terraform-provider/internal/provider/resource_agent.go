package provider

import (
	"fmt"

	"github.com/counsel/terraform-provider-counsel/internal/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAgent() *schema.Resource {
	return &schema.Resource{
		Description: "Registers an agent under a Counsel company.",

		Create: resourceAgentCreate,
		Read:   resourceAgentRead,
		Update: resourceAgentUpdate,
		Delete: resourceAgentDelete,

		// Import: terraform import counsel_agent.bot "<agent-id>/<company-api-key>"
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"agent_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique agent identifier within the company.",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Company API key used to authenticate the registration request.",
			},
			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Arbitrary string key/value metadata stored with the agent.",
			},
			"spiffe_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "SPIFFE ID assigned to this agent.",
			},
			"registered_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ISO 8601 timestamp of agent registration.",
			},
		},
	}
}

func resourceAgentCreate(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	agentID := d.Get("agent_id").(string)
	apiKey  := d.Get("api_key").(string)

	metadata := map[string]interface{}{}
	if v, ok := d.GetOk("metadata"); ok {
		for k, val := range v.(map[string]interface{}) {
			metadata[k] = val
		}
	}

	result, err := c.RegisterAgent(apiKey, agentID, metadata)
	if err != nil {
		return fmt.Errorf("register agent %q: %w", agentID, err)
	}

	d.SetId(agentID)
	d.Set("spiffe_id", result["spiffeId"])
	d.Set("registered_at", result["registeredAt"])
	return nil
}

func resourceAgentRead(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	agentID := d.Get("agent_id").(string)
	apiKey  := d.Get("api_key").(string)

	result, err := c.GetAgent(apiKey, agentID)
	if err != nil {
		return fmt.Errorf("read agent %q: %w", agentID, err)
	}
	if result == nil {
		d.SetId("")
		return nil
	}

	d.Set("spiffe_id", result["spiffeId"])
	d.Set("registered_at", result["registeredAt"])
	if meta, ok := result["metadata"].(map[string]interface{}); ok {
		stringMeta := make(map[string]string, len(meta))
		for k, v := range meta {
			stringMeta[k] = fmt.Sprintf("%v", v)
		}
		d.Set("metadata", stringMeta)
	}
	return nil
}

// resourceAgentUpdate re-registers the agent with updated metadata.
// POST /v1/agents/register uses INSERT OR REPLACE so it is idempotent.
func resourceAgentUpdate(d *schema.ResourceData, m interface{}) error {
	cfg := m.(*client.Config)
	c := client.New(cfg)

	agentID := d.Get("agent_id").(string)
	apiKey  := d.Get("api_key").(string)

	metadata := map[string]interface{}{}
	if v, ok := d.GetOk("metadata"); ok {
		for k, val := range v.(map[string]interface{}) {
			metadata[k] = val
		}
	}

	result, err := c.RegisterAgent(apiKey, agentID, metadata)
	if err != nil {
		return fmt.Errorf("update agent %q: %w", agentID, err)
	}
	d.Set("spiffe_id", result["spiffeId"])
	d.Set("registered_at", result["registeredAt"])
	return nil
}

// resourceAgentDelete is a no-op. The Counsel API does not expose an agent
// deletion endpoint. Terraform removes the resource from state only.
func resourceAgentDelete(_ *schema.ResourceData, _ interface{}) error {
	return nil
}
