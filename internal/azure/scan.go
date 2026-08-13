package azure

import (
	"context"
	"fmt"
	"github.com/Georgy03/zerodock/internal/checks"
	"strings"
)

type Output struct {
	Title    string
	Tier     checks.Tier
	Accounts map[string]checks.Result
}

var controls = map[string]string{
	"azure.storage.public_containers": "Azure blob containers exposed publicly", "azure.storage.https_only": "Azure Storage accounts without HTTPS-only traffic", "azure.storage.min_tls": "Azure Storage accounts below TLS 1.2", "azure.nsg.open_rules": "Azure NSG rules open to the internet", "azure.sql.public_access": "Azure SQL public network access", "azure.sql.tde": "Azure SQL databases without Transparent Data Encryption", "azure.keyvault.soft_delete": "Azure Key Vaults without soft delete or purge protection", "azure.identity.security_defaults": "Microsoft Entra Security Defaults", "azure.identity.global_admins": "Microsoft Entra Global Administrator count", "azure.monitor.activity_log": "Azure Activity Log export", "azure.disk.encryption": "Azure managed disks without customer-managed keys",
}

func Scan(ctx context.Context, c *Client, scope Scope) map[string]Output {
	o := map[string]Output{}
	for id, title := range controls {
		o[id] = Output{Title: title, Tier: checks.ProviderAttested, Accounts: map[string]checks.Result{}}
	}
	for _, sub := range scope.Subscriptions {
		storage(ctx, c, sub, o)
		nsg(ctx, c, sub, o)
		sql(ctx, c, sub, o)
		vault(ctx, c, sub, o)
		activity(ctx, c, sub, o)
		disks(ctx, c, sub, o)
	}
	defaults, admins := identity(ctx, c)
	for _, sub := range scope.Subscriptions {
		o["azure.identity.security_defaults"].Accounts[sub] = defaults
		o["azure.identity.global_admins"].Accounts[sub] = admins
	}
	return o
}
func res(n int, f []string, e error) checks.Result {
	if e != nil {
		return checks.Result{Status: checks.StatusError, Count: n, Findings: append(f, e.Error())}
	}
	if len(f) > 0 {
		return checks.Result{Status: checks.StatusFail, Count: n, Findings: f}
	}
	return checks.Result{Status: checks.StatusPass, Count: n}
}
func storage(ctx context.Context, c *Client, s string, o map[string]Output) {
	var out struct {
		Value []struct {
			Name       string `json:"name"`
			ID         string `json:"id"`
			Properties struct {
				HTTPS bool   `json:"supportsHttpsTrafficOnly"`
				TLS   string `json:"minimumTlsVersion"`
			} `json:"properties"`
		} `json:"value"`
	}
	e := c.arm(ctx, "/subscriptions/"+s+"/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", &out)
	var pub, https, tls []string
	for _, a := range out.Value {
		if !a.Properties.HTTPS {
			https = append(https, "storage account "+a.Name+" has supportsHttpsTrafficOnly=false")
		}
		if a.Properties.TLS != "TLS1_2" && a.Properties.TLS != "TLS1_3" {
			tls = append(tls, "storage account "+a.Name+" minimumTlsVersion is "+a.Properties.TLS)
		}
		var containers struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					Access string `json:"publicAccess"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := c.arm(ctx, a.ID+"/blobServices/default/containers?api-version=2023-01-01", &containers); err != nil {
			e = err
			continue
		}
		for _, container := range containers.Value {
			if strings.EqualFold(container.Properties.Access, "Blob") || strings.EqualFold(container.Properties.Access, "Container") {
				pub = append(pub, fmt.Sprintf("storage account %s container %s has publicAccess=%s", a.Name, container.Name, container.Properties.Access))
			}
		}
	}
	o["azure.storage.public_containers"].Accounts[s] = res(len(out.Value), pub, e)
	o["azure.storage.https_only"].Accounts[s] = res(len(out.Value), https, e)
	o["azure.storage.min_tls"].Accounts[s] = res(len(out.Value), tls, e)
}
func nsg(ctx context.Context, c *Client, s string, o map[string]Output) {
	var out struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				Rules []struct {
					Name       string `json:"name"`
					Properties struct {
						Direction, Access, Source string
						Protocol                  string `json:"protocol"`
						DestinationPortRange      string `json:"destinationPortRange"`
					} `json:"properties"`
				} `json:"securityRules"`
			} `json:"properties"`
		} `json:"value"`
	}
	e := c.arm(ctx, "/subscriptions/"+s+"/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01", &out)
	ports := map[string]bool{"22": true, "3389": true, "1433": true, "3306": true, "5432": true}
	var f []string
	n := 0
	for _, g := range out.Value {
		for _, r := range g.Properties.Rules {
			n++
			p := r.Properties
			if !strings.EqualFold(p.Direction, "Inbound") || !strings.EqualFold(p.Access, "Allow") || !(p.Source == "*" || strings.EqualFold(p.Source, "Internet")) {
				continue
			}
			if ports[p.DestinationPortRange] || p.DestinationPortRange == "*" || p.DestinationPortRange == "0-65535" {
				f = append(f, fmt.Sprintf("NSG %s rule %s permits Internet inbound access to %s", g.Name, r.Name, p.DestinationPortRange))
			}
		}
	}
	o["azure.nsg.open_rules"].Accounts[s] = res(n, f, e)
}
func sql(ctx context.Context, c *Client, s string, o map[string]Output) {
	var servers struct {
		Value []struct {
			Name, ID   string
			Properties struct {
				Public string `json:"publicNetworkAccess"`
			} `json:"properties"`
		} `json:"value"`
	}
	e := c.arm(ctx, "/subscriptions/"+s+"/providers/Microsoft.Sql/servers?api-version=2023-08-01-preview", &servers)
	var pub, tde []string
	n := 0
	for _, server := range servers.Value {
		n++
		if strings.EqualFold(server.Properties.Public, "Enabled") {
			pub = append(pub, "SQL server "+server.Name+" has publicNetworkAccess enabled")
		}
		var dbs struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := c.arm(ctx, server.ID+"/databases?api-version=2023-08-01-preview", &dbs); err != nil {
			e = err
			continue
		}
		for _, db := range dbs.Value {
			var encryption struct {
				Properties struct {
					Status string `json:"status"`
				} `json:"properties"`
			}
			if err := c.arm(ctx, server.ID+"/databases/"+db.Name+"/transparentDataEncryption/current?api-version=2023-08-01-preview", &encryption); err != nil {
				e = err
				continue
			}
			if !strings.EqualFold(encryption.Properties.Status, "Enabled") {
				tde = append(tde, "SQL database "+server.Name+"/"+db.Name+" has Transparent Data Encryption disabled")
			}
		}
	}
	o["azure.sql.public_access"].Accounts[s] = res(n, pub, e)
	o["azure.sql.tde"].Accounts[s] = res(n, tde, e)
}
func vault(ctx context.Context, c *Client, s string, o map[string]Output) {
	var out struct {
		Value []struct {
			Name       string
			Properties struct {
				Soft  bool `json:"enableSoftDelete"`
				Purge bool `json:"enablePurgeProtection"`
			} `json:"properties"`
		} `json:"value"`
	}
	e := c.arm(ctx, "/subscriptions/"+s+"/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01", &out)
	var f []string
	for _, v := range out.Value {
		if !v.Properties.Soft || !v.Properties.Purge {
			f = append(f, "Key Vault "+v.Name+" does not enable both soft delete and purge protection")
		}
	}
	o["azure.keyvault.soft_delete"].Accounts[s] = res(len(out.Value), f, e)
}
func activity(ctx context.Context, c *Client, s string, o map[string]Output) {
	var out struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	e := c.arm(ctx, "/subscriptions/"+s+"/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview", &out)
	var f []string
	if e == nil && len(out.Value) == 0 {
		f = []string{"subscription has no diagnostic setting exporting the Activity Log"}
	}
	o["azure.monitor.activity_log"].Accounts[s] = res(len(out.Value), f, e)
}
func disks(ctx context.Context, c *Client, s string, o map[string]Output) {
	var out struct {
		Value []struct {
			Name       string
			Properties struct {
				Encryption struct {
					Type string `json:"type"`
				} `json:"encryption"`
			} `json:"properties"`
		} `json:"value"`
	}
	e := c.arm(ctx, "/subscriptions/"+s+"/providers/Microsoft.Compute/disks?api-version=2023-10-02", &out)
	var f []string
	for _, d := range out.Value {
		if d.Properties.Encryption.Type != "EncryptionAtRestWithCustomerKey" {
			f = append(f, "managed disk "+d.Name+" does not use encryption at rest with a customer-managed key")
		}
	}
	o["azure.disk.encryption"].Accounts[s] = res(len(out.Value), f, e)
}
func identity(ctx context.Context, c *Client) (checks.Result, checks.Result) {
	var defaults struct {
		Enabled bool `json:"isEnabled"`
	}
	e := c.graph(ctx, "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", &defaults)
	var f []string
	if !defaults.Enabled {
		f = []string{"Security Defaults are disabled; Conditional Access may be an alternative but is not treated as a pass"}
	}
	d := res(1, f, e)
	var roles struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	e = c.graph(ctx, "/v1.0/directoryRoles?$filter=roleTemplateId%20eq%20'62e90394-69f5-4237-9190-012177145e10'", &roles)
	count := 0
	for _, role := range roles.Value {
		var members struct {
			Value []any `json:"value"`
		}
		if err := c.graph(ctx, "/v1.0/directoryRoles/"+role.ID+"/members", &members); err != nil {
			e = err
			continue
		}
		count += len(members.Value)
	}
	var admins []string
	if count > 5 {
		admins = []string{fmt.Sprintf("%d Global Administrators found; more than 5", count)}
	}
	return d, res(count, admins, e)
}
