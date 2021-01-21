package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

func gcpServiceAccountKeyResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: gcpServiceAccountKeyResourceCreate,
		Read:   gcpServiceAccountKeyResourceRead,
		Delete: gcpServiceAccountKeyResourceDelete,

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
			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The TTL period of the token.",
			},

			// Computed
			"private_key_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client secret for credentials to query the Azure APIs.",
				Sensitive:   true,
			},

			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},

			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},

			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func gcpServiceAccountKeyResourceCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	roleset := d.Get("roleset").(string)

	rolesetPath := backend + "/key/" + roleset

	data := map[string][]string{}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = []string{v.(string)}
	}

	log.Printf("[DEBUG] Reading %q from Vault with data %#v", rolesetPath, data)

	secret, err := client.Logical().ReadWithData(rolesetPath, data)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return fmt.Errorf("no secret found at %q", rolesetPath)
	}

	d.SetId(rolesetPath)

	d.Set("private_key_data", secret.Data["private_key_data"])
	d.Set("lease_id", secret.LeaseID)
	d.Set("lease_duration", secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	d.Set("lease_renewable", secret.Renewable)

	return nil
}

func gcpServiceAccountKeyResourceRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func gcpServiceAccountKeyResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	data := map[string]interface{}{
		"lease_id": d.Get("lease_id").(string),
	}

	log.Printf("[DEBUG] Revoking Vault lease %#v", data)
	resp, err := client.Logical().Write("sys/leases/revoke", data)
	if err != nil {
		return fmt.Errorf("error revoking Vault lease %#v", data)
	}

	if resp == nil {
		log.Printf("[WARN] Vault lease %#v is already expired, removing from state", data)
		d.SetId("")
		return nil
	}

	return nil
}
