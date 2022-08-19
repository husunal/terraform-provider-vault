package provider

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	vault_consts "github.com/hashicorp/vault/sdk/helper/consts"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestProviderMeta_GetNSClient(t *testing.T) {
	rootClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		client       *api.Client
		resourceData *schema.ResourceData
		ns           string
		expectNs     string
		wantErr      bool
		expectErr    error
		calls        int
	}{
		{
			name:         "no-client",
			client:       nil,
			resourceData: &schema.ResourceData{},
			wantErr:      true,
			expectErr:    errors.New("root api.Client not set, init with NewProviderMeta()"),
		},
		{
			name:         "no-resource-data",
			client:       &api.Client{},
			resourceData: nil,
			wantErr:      true,
			expectErr:    errors.New("provider ResourceData not set, init with NewProviderMeta()"),
		},
		{
			name:   "basic-no-root-ns",
			client: rootClient,
			resourceData: schema.TestResourceDataRaw(t,
				map[string]*schema.Schema{
					"namespace": {
						Type:     schema.TypeString,
						Required: true,
					},
				},
				map[string]interface{}{},
			),
			ns:       "foo",
			expectNs: "foo",
		},
		{
			name:   "basic-root-ns",
			client: rootClient,
			resourceData: schema.TestResourceDataRaw(t,
				map[string]*schema.Schema{
					"namespace": {
						Type:     schema.TypeString,
						Required: true,
					},
				},
				map[string]interface{}{
					"namespace": "bar",
				},
			),
			ns:       "foo",
			expectNs: "bar/foo",
			calls:    5,
		},
		{
			name:   "basic-root-ns-trimmed",
			client: rootClient,
			resourceData: schema.TestResourceDataRaw(t,
				map[string]*schema.Schema{
					"namespace": {
						Type:     schema.TypeString,
						Required: true,
					},
				},
				map[string]interface{}{
					"namespace": "bar",
				},
			),
			ns:       "/foo/",
			expectNs: "bar/foo",
			calls:    5,
		},
	}

	assertClientCache := func(t *testing.T, p *ProviderMeta, expectedCache map[string]*api.Client) {
		t.Helper()

		if !reflect.DeepEqual(expectedCache, p.clientCache) {
			t.Errorf("GetNSClient() expected Client cache %#v, actual %#v", expectedCache, p.clientCache)
		}
	}

	assertClientNs := func(t *testing.T, c *api.Client, expectNs string) {
		actualNs := c.Headers().Get(vault_consts.NamespaceHeaderName)
		if actualNs != expectNs {
			t.Errorf("GetNSClient() got ns = %v, want %v", actualNs, expectNs)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ProviderMeta{
				client:       tt.client,
				resourceData: tt.resourceData,
			}
			got, err := p.GetNSClient(tt.ns)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetNSClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GetNSClient() expected an err, actual %#v", err)
				}

				if !reflect.DeepEqual(err, tt.expectErr) {
					t.Errorf("GetNSClient() expected err %#v, actual %#v", tt.expectErr, err)
				}

				var expectedCache map[string]*api.Client
				assertClientCache(t, p, expectedCache)

				return
			}

			assertClientCache(t, p, map[string]*api.Client{
				tt.expectNs: got,
			})
			assertClientNs(t, got, tt.expectNs)

			// test cache locking
			if tt.calls > 0 {
				var wg sync.WaitGroup
				p.clientCache = nil
				wg.Add(tt.calls)
				for i := 0; i < tt.calls; i++ {
					go func() {
						defer wg.Done()
						got, err := p.GetNSClient(tt.ns)
						if err != nil {
							t.Error(err)
							return
						}

						assertClientCache(t, p, map[string]*api.Client{
							tt.expectNs: got,
						})
						assertClientNs(t, got, tt.expectNs)
					}()
				}
				wg.Wait()
			}
		})
	}
}

func TestGetClient(t *testing.T) {
	rootClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// testing schema.ResourceDiff is not covered here
	// since its field members are private.

	rscData := func(t *testing.T, set bool, ns string) interface{} {
		i := schema.TestResourceDataRaw(t,
			map[string]*schema.Schema{
				consts.FieldNamespace: {
					Type:     schema.TypeString,
					Required: true,
				},
			},
			map[string]interface{}{},
		)
		if set {
			if err := i.Set(consts.FieldNamespace, ns); err != nil {
				t.Fatal(err)
			}
		}
		return i
	}

	instanceState := func(_ *testing.T, set bool, ns string) interface{} {
		i := &terraform.InstanceState{
			Attributes: map[string]string{},
		}
		if set {
			i.Attributes[consts.FieldNamespace] = ns
		}
		return i
	}

	tests := []struct {
		name      string
		meta      interface{}
		ifcNS     string
		envNS     string
		want      string
		wantErr   bool
		expectErr error
		setAttr   bool
		ifaceFunc func(t *testing.T, set bool, ns string) interface{}
	}{
		{
			name:  "string",
			ifcNS: "ns1-string",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: func(t *testing.T, set bool, ns string) interface{} {
				return "ns1-string"
			},
			want:    "ns1-string",
			setAttr: true,
		},
		{
			name:  "rsc-data",
			ifcNS: "ns1-rsc-data",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: rscData,
			want:      "ns1-rsc-data",
			setAttr:   true,
		},
		{
			name:  "inst-state",
			ifcNS: "ns1-inst-state",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			want:      "ns1-inst-state",
			setAttr:   true,
			ifaceFunc: instanceState,
		},
		{
			name: "import-env",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: instanceState,
			envNS:     "ns1-import-env",
			want:      "ns1-import-env",
			setAttr:   false,
		},
		{
			name: "ignore-env-rsc-data",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: rscData,
			ifcNS:     "ns1",
			envNS:     "ns1-import-env",
			want:      "ns1",
			setAttr:   true,
		},
		{
			name: "ignore-env-inst-state",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: instanceState,
			ifcNS:     "ns1",
			envNS:     "ns1-import-env",
			want:      "ns1",
			setAttr:   true,
		},
		{
			name: "error-unsupported-type",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: func(t *testing.T, set bool, ns string) interface{} {
				return nil
			},
			wantErr:   true,
			expectErr: fmt.Errorf("GetClient() called with unsupported type <nil>"),
		},
		{
			name:      "error-not-provider-meta",
			meta:      nil,
			wantErr:   true,
			expectErr: fmt.Errorf("meta argument must be a *provider.ProviderMeta, not <nil>"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.meta != nil {
				m := tt.meta.(*ProviderMeta)
				m.resourceData = schema.TestResourceDataRaw(t,
					map[string]*schema.Schema{
						consts.FieldNamespace: {
							Type:     schema.TypeString,
							Required: true,
						},
					},
					map[string]interface{}{},
				)
				tt.meta = m
			}

			var i interface{}
			if tt.ifaceFunc != nil {
				i = tt.ifaceFunc(t, tt.setAttr, tt.ifcNS)
			}

			// set ns in env
			if tt.envNS != "" {
				if err := os.Setenv(consts.EnvVarVaultNamespaceImport, tt.envNS); err != nil {
					t.Fatal(err)
				}
				defer os.Unsetenv(consts.EnvVarVaultNamespaceImport)
			}

			got, err := GetClient(i, tt.meta)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetClient() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(err, tt.expectErr) {
					t.Errorf("GetClient() expected err %#v, actual %#v", tt.expectErr, err)
				}
				return
			}

			actual := got.Headers().Get(vault_consts.NamespaceHeaderName)
			if !reflect.DeepEqual(actual, tt.want) {
				t.Errorf("GetClient() got = %v, want %v", actual, tt.want)
			}
		})
	}
}