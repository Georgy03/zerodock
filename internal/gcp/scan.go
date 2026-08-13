package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Georgy03/zerodock/internal/checks"
)

type Output struct {
	Title    string
	Tier     checks.Tier
	Accounts map[string]checks.Result
}

var controls = map[string]string{
	"gcp.storage.public": "GCP Cloud Storage buckets exposed publicly", "gcp.storage.uniform_access": "GCP Cloud Storage buckets without uniform bucket-level access",
	"gcp.iam.sa_key_age": "GCP user-managed service-account keys older than 90 days", "gcp.iam.primitive_roles": "GCP project members with primitive Owner or Editor roles",
	"gcp.compute.open_firewall": "GCP firewall rules open to the internet", "gcp.compute.public_ips": "GCP Compute instances with external IPs",
	"gcp.sql.public_ip": "GCP Cloud SQL instances with unrestricted public IP", "gcp.sql.ssl_required": "GCP Cloud SQL instances without required SSL", "gcp.sql.backup_enabled": "GCP Cloud SQL instances without adequate backups",
	"gcp.kms.key_rotation": "GCP KMS keys without automatic rotation", "gcp.logging.audit_config": "GCP organization Data Access audit logging",
}

func Scan(ctx context.Context, c *Client, scope Scope, now time.Time) map[string]Output {
	outputs := make(map[string]Output, len(controls))
	for id, title := range controls {
		outputs[id] = Output{Title: title, Tier: checks.ProviderAttested, Accounts: map[string]checks.Result{}}
	}
	for _, project := range scope.Projects {
		outputs["gcp.storage.public"].Accounts[project] = storagePublic(ctx, c, project)
		outputs["gcp.storage.uniform_access"].Accounts[project] = storageUniformAccess(ctx, c, project)
		outputs["gcp.iam.sa_key_age"].Accounts[project] = serviceAccountKeyAge(ctx, c, project, now)
		outputs["gcp.iam.primitive_roles"].Accounts[project] = primitiveRoles(ctx, c, project)
		outputs["gcp.compute.open_firewall"].Accounts[project] = openFirewalls(ctx, c, project)
		outputs["gcp.compute.public_ips"].Accounts[project] = publicIPs(ctx, c, project)
		sql := cloudSQL(ctx, c, project)
		outputs["gcp.sql.public_ip"].Accounts[project] = sql.publicIP
		outputs["gcp.sql.ssl_required"].Accounts[project] = sql.ssl
		outputs["gcp.sql.backup_enabled"].Accounts[project] = sql.backup
		outputs["gcp.kms.key_rotation"].Accounts[project] = kmsRotation(ctx, c, project)
	}
	// The policy is organization-level evidence, but duplicating the same
	// provider response under every listed project keeps the report's existing
	// per-project shape complete and makes a coverage gap impossible to hide.
	audit := auditConfig(ctx, c, scope.OrganizationID)
	for _, project := range scope.Projects {
		outputs["gcp.logging.audit_config"].Accounts[project] = audit
	}
	return outputs
}

func result(count int, findings []string, err error) checks.Result {
	if err != nil {
		return checks.Result{Status: checks.StatusError, Count: count, Findings: append(findings, err.Error())}
	}
	if len(findings) > 0 {
		return checks.Result{Status: checks.StatusFail, Count: count, Findings: findings}
	}
	return checks.Result{Status: checks.StatusPass, Count: count}
}
func listBuckets(ctx context.Context, c *Client, project string) ([]struct {
	Name string `json:"name"`
	IAM  struct {
		Uniform struct {
			Enabled bool `json:"enabled"`
		} `json:"uniformBucketLevelAccess"`
	} `json:"iamConfiguration"`
}, error) {
	var out struct {
		Items []struct {
			Name string `json:"name"`
			IAM  struct {
				Uniform struct {
					Enabled bool `json:"enabled"`
				} `json:"uniformBucketLevelAccess"`
			} `json:"iamConfiguration"`
		} `json:"items"`
	}
	if err := c.get(ctx, storageURL+"/storage/v1/b?project="+project, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
func storagePublic(ctx context.Context, c *Client, p string) checks.Result {
	buckets, err := listBuckets(ctx, c, p)
	if err != nil {
		return result(0, nil, err)
	}
	var f []string
	for _, b := range buckets {
		var policy struct {
			Bindings []struct {
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if e := c.get(ctx, storageURL+"/storage/v1/b/"+b.Name+"/iam", &policy); e != nil {
			return result(len(buckets), f, e)
		}
		for _, binding := range policy.Bindings {
			for _, m := range binding.Members {
				if m == "allUsers" || m == "allAuthenticatedUsers" {
					f = append(f, fmt.Sprintf("bucket %s grants access to %s", b.Name, m))
				}
			}
		}
	}
	return result(len(buckets), f, nil)
}
func storageUniformAccess(ctx context.Context, c *Client, p string) checks.Result {
	buckets, err := listBuckets(ctx, c, p)
	if err != nil {
		return result(0, nil, err)
	}
	var f []string
	for _, b := range buckets {
		if !b.IAM.Uniform.Enabled {
			f = append(f, "bucket "+b.Name+" has uniform bucket-level access disabled")
		}
	}
	return result(len(buckets), f, nil)
}
func serviceAccountKeyAge(ctx context.Context, c *Client, p string, now time.Time) checks.Result {
	var accounts struct {
		Accounts []struct {
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if err := c.get(ctx, iamURL+"/v1/projects/"+p+"/serviceAccounts", &accounts); err != nil {
		return result(0, nil, err)
	}
	n := 0
	var f []string
	for _, a := range accounts.Accounts {
		var keys struct {
			Keys []struct {
				Name       string `json:"name"`
				Type       string `json:"keyType"`
				ValidAfter string `json:"validAfterTime"`
			} `json:"keys"`
		}
		if err := c.get(ctx, iamURL+"/v1/"+a.Name+"/keys?keyTypes=USER_MANAGED", &keys); err != nil {
			return result(n, f, err)
		}
		for _, k := range keys.Keys {
			if k.Type != "USER_MANAGED" {
				continue
			}
			n++
			created, e := time.Parse(time.RFC3339, k.ValidAfter)
			if e != nil {
				return result(n, f, e)
			}
			if now.Sub(created) > 90*24*time.Hour {
				f = append(f, fmt.Sprintf("service-account key %s is older than 90 days", k.Name))
			}
		}
	}
	return result(n, f, nil)
}
func primitiveRoles(ctx context.Context, c *Client, p string) checks.Result {
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	err := c.post(ctx, resourceManagerURL+"/v3/projects/"+p+":getIamPolicy", map[string]any{}, &policy)
	var f []string
	for _, b := range policy.Bindings {
		if b.Role == "roles/owner" || b.Role == "roles/editor" {
			for _, m := range b.Members {
				f = append(f, fmt.Sprintf("%s has %s at project scope", m, b.Role))
			}
		}
	}
	return result(len(policy.Bindings), f, err)
}
func openFirewalls(ctx context.Context, c *Client, p string) checks.Result {
	var out struct {
		Items map[string]struct {
			Firewalls []struct {
				Name     string   `json:"name"`
				Disabled bool     `json:"disabled"`
				Source   []string `json:"sourceRanges"`
				Allowed  []struct {
					IP    string   `json:"IPProtocol"`
					Ports []string `json:"ports"`
				} `json:"allowed"`
			} `json:"firewalls"`
		} `json:"items"`
	}
	err := c.get(ctx, computeURL+"/compute/v1/projects/"+p+"/aggregated/firewalls", &out)
	n := 0
	var f []string
	ports := map[string]bool{"22": true, "3389": true, "3306": true, "5432": true, "27017": true}
	for _, scope := range out.Items {
		for _, rule := range scope.Firewalls {
			n++
			if rule.Disabled || !contains(rule.Source, "0.0.0.0/0") {
				continue
			}
			for _, a := range rule.Allowed {
				if a.IP == "all" || a.IP == "tcp" {
					for _, port := range a.Ports {
						if ports[port] || port == "0-65535" {
							f = append(f, fmt.Sprintf("firewall rule %s allows 0.0.0.0/0 to TCP %s", rule.Name, port))
						}
					}
				}
			}
		}
	}
	return result(n, f, err)
}
func publicIPs(ctx context.Context, c *Client, p string) checks.Result {
	var out struct {
		Items map[string]struct {
			Instances []struct {
				Name       string `json:"name"`
				Interfaces []struct {
					Configs []struct {
						NAT string `json:"natIP"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
			} `json:"instances"`
		} `json:"items"`
	}
	err := c.get(ctx, computeURL+"/compute/v1/projects/"+p+"/aggregated/instances", &out)
	n := 0
	var f []string
	for _, scope := range out.Items {
		for _, i := range scope.Instances {
			n++
			for _, ni := range i.Interfaces {
				for _, a := range ni.Configs {
					if a.NAT != "" {
						f = append(f, fmt.Sprintf("instance %s has external IP %s", i.Name, a.NAT))
					}
				}
			}
		}
	}
	return result(n, f, err)
}

type sqlResults struct{ publicIP, ssl, backup checks.Result }

func cloudSQL(ctx context.Context, c *Client, p string) sqlResults {
	var out struct {
		Items []struct {
			Name     string `json:"name"`
			Settings struct {
				RequireSSL bool       `json:"requireSsl"`
				Authorized []struct{} `json:"authorizedNetworks"`
				Backup     struct {
					Enabled   bool `json:"enabled"`
					Retention struct {
						Retained int `json:"retainedBackups"`
					} `json:"backupRetentionSettings"`
				} `json:"backupConfiguration"`
			} `json:"settings"`
			IP []struct {
				Type    string `json:"type"`
				Address string `json:"ipAddress"`
			} `json:"ipAddresses"`
		} `json:"items"`
	}
	err := c.get(ctx, sqlAdminURL+"/v1/projects/"+p+"/instances", &out)
	var pub, ssl, backup []string
	for _, i := range out.Items {
		external := false
		for _, ip := range i.IP {
			if ip.Type == "PRIMARY" {
				external = true
			}
		}
		if external && len(i.Settings.Authorized) == 0 {
			pub = append(pub, "Cloud SQL instance "+i.Name+" has public IP without authorized-network restrictions")
		}
		if !i.Settings.RequireSSL {
			ssl = append(ssl, "Cloud SQL instance "+i.Name+" has requireSsl disabled")
		}
		if !i.Settings.Backup.Enabled || i.Settings.Backup.Retention.Retained < 7 {
			backup = append(backup, "Cloud SQL instance "+i.Name+" has automated backups disabled or retention under 7 days")
		}
	}
	return sqlResults{result(len(out.Items), pub, err), result(len(out.Items), ssl, err), result(len(out.Items), backup, err)}
}
func kmsRotation(ctx context.Context, c *Client, p string) checks.Result {
	var locations struct {
		Locations []struct {
			LocationID string `json:"locationId"`
		} `json:"locations"`
	}
	if err := c.get(ctx, kmsURL+"/v1/projects/"+p+"/locations", &locations); err != nil {
		return result(0, nil, err)
	}
	n := 0
	var f []string
	for _, l := range locations.Locations {
		var rings struct {
			KeyRings []struct {
				Name string `json:"name"`
			} `json:"keyRings"`
		}
		if err := c.get(ctx, kmsURL+"/v1/projects/"+p+"/locations/"+l.LocationID+"/keyRings", &rings); err != nil {
			return result(n, f, err)
		}
		for _, ring := range rings.KeyRings {
			var keys struct {
				CryptoKeys []struct {
					Name     string `json:"name"`
					Rotation string `json:"rotationPeriod"`
				} `json:"cryptoKeys"`
			}
			if err := c.get(ctx, kmsURL+"/v1/"+ring.Name+"/cryptoKeys", &keys); err != nil {
				return result(n, f, err)
			}
			for _, key := range keys.CryptoKeys {
				n++
				if key.Rotation == "" {
					f = append(f, "KMS key "+key.Name+" has no rotation period")
				}
			}
		}
	}
	return result(n, f, nil)
}
func auditConfig(ctx context.Context, c *Client, org string) checks.Result {
	var policy struct {
		Audit []struct {
			Service string `json:"service"`
			Configs []struct {
				Type string `json:"logType"`
			} `json:"auditLogConfigs"`
		} `json:"auditConfigs"`
	}
	err := c.post(ctx, resourceManagerURL+"/v3/organizations/"+org+":getIamPolicy", map[string]any{}, &policy)
	read, write := false, false
	for _, a := range policy.Audit {
		if a.Service != "allServices" {
			continue
		}
		for _, x := range a.Configs {
			read = read || x.Type == "DATA_READ"
			write = write || x.Type == "DATA_WRITE"
		}
	}
	var f []string
	if !read || !write {
		f = []string{"organization Data Access audit logs do not enable both DATA_READ and DATA_WRITE for allServices"}
	}
	return result(len(policy.Audit), f, err)
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
