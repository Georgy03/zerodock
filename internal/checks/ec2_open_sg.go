package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// sensitivePorts lists network "ports" (think of them like different doors
// into a computer, each used for a different purpose) that are especially
// dangerous to leave open to the whole internet, because they're commonly
// used for remote login or direct database access — exactly what an
// attacker wants.
//
//	22    = SSH   (remote command-line login to Linux servers)
//	3389  = RDP   (remote desktop login to Windows servers)
//	3306  = MySQL database
//	5432  = PostgreSQL database
//	27017 = MongoDB database
var sensitivePorts = map[int32]string{
	22:    "SSH",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
}

func init() {
	Register(Check{
		ID:    "aws.ec2.open_sg",
		Title: "Security groups open to the internet on sensitive ports",
		Tier:  ProviderAttested,
		Run:   ec2OpenSG,
	})
}

// A "security group" is AWS's version of a firewall: a set of rules that
// say which network traffic is allowed in and out of a server. Each rule
// (called an "IP permission") says something like "allow traffic on ports
// 80-443, coming from this range of internet addresses". This check looks
// for rules that allow one of our sensitivePorts in from ANYWHERE on the
// internet (the special address ranges 0.0.0.0/0 or ::/0, which mean
// "every possible address").
func ec2OpenSG(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := ec2.NewFromConfig(regionalCfg)

		var findings []string
		count := 0

		paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}

			for _, sg := range page.SecurityGroups {
				count++

				// A security group can have many "inbound" rules
				// (IpPermissions). Check each rule against each
				// sensitive port.
				for _, perm := range sg.IpPermissions {
					for port, name := range sensitivePorts {
						if !permissionCoversPort(perm, port) {
							// This rule doesn't even mention
							// this port — nothing to flag.
							continue
						}

						if cidr, ok := openToInternet(perm); ok {
							findings = append(findings, fmt.Sprintf(
								"%s: security group %s (%s) allows %s from %s on port %d (%s)",
								regionalCfg.Region,
								aws.ToString(sg.GroupId),
								aws.ToString(sg.GroupName),
								name,
								cidr,
								port,
								name,
							))
						}
					}
				}
			}
		}

		return findings, count, nil
	})
}

// permissionCoversPort answers: "does this particular rule apply to this
// specific port number?" A rule specifies a range like "from port 20 to
// port 25", and we check whether our target port falls inside that range.
func permissionCoversPort(perm ec2types.IpPermission, port int32) bool {
	from, to := int32(-1), int32(-1)
	if perm.FromPort != nil {
		from = *perm.FromPort
	}
	if perm.ToPort != nil {
		to = *perm.ToPort
	}

	// A special case: FromPort and ToPort both being -1 is AWS's way of
	// saying "this rule isn't about specific ports at all — it allows
	// ALL ports" (this happens when the rule's protocol is "-1", meaning
	// "all traffic"). In that case, every port — including ours — is
	// covered.
	if from == -1 && to == -1 {
		return true
	}

	return port >= from && port <= to
}

// openToInternet checks whether a rule allows traffic from EVERY address
// on the internet, rather than just a specific, limited range of
// addresses. It returns the matching "wildcard" address range (for
// inclusion in the finding's message) and whether one was found.
//
//	0.0.0.0/0 = every possible IPv4 address (the older internet addressing
//	            system, e.g. 192.168.1.1)
//	::/0      = every possible IPv6 address (the newer, longer addressing
//	            system)
func openToInternet(perm ec2types.IpPermission) (string, bool) {
	for _, r := range perm.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return "0.0.0.0/0", true
		}
	}
	for _, r := range perm.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return "::/0", true
		}
	}
	return "", false
}
