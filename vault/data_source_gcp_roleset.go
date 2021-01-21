package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

func gcpRolesetDataSource() *schema.Resource {
	return &schema.Resource{
		Read: gcpRolesetDataSourceRead,

		Schema: map[string]*schema.Schema{
			"roleset": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "GCP Secret Engine, Service Account Roleset to read credentials from.",
				ForceNew:    true,
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "GCP Secret Engine Backend to read credentials from.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"version": {
				Type:     schema.TypeInt,
				Required: false,
				Optional: true,
				ForceNew: true,
				Default:  latestSecretVersion,
			},
			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},
		},
	}
}

func gcpRolesetDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	roleset := d.Get("roleset").(string)

	rolesetPath := backend + "/roleset/" + roleset

	resp, err := client.Logical().Read(rolesetPath)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Roleset details %#v", resp)

	if resp == nil {
		return fmt.Errorf("no roleset found at %q", rolesetPath)
	}

	d.SetId(rolesetPath)

	dataMap := map[string]string{}
	for k, v := range resp.Data {
		if vs, ok := v.(string); ok {
			dataMap[k] = vs
		} else {
			vBytes, _ := json.Marshal(v)
			dataMap[k] = string(vBytes)
		}
	}
	d.Set("data", dataMap)

	if resp.Data["secret_type"] != "service_account_key" {
		return fmt.Errorf("roleset '%s' cannot generate service account keys (has secret type %s)", roleset, resp.Data["secret_type"])
	}

	return nil
}
