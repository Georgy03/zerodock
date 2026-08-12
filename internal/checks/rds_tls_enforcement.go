package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	Register(Check{ID: "aws.rds.tls_enforcement", Title: "RDS parameter groups that do not require TLS", Tier: ProviderAttested, Run: rdsTLSEnforcement})
}

type rdsTLSParameter struct {
	name     string
	insecure func(string) (bool, bool)
}

// tlsParameterForFamily returns the engine's authoritative TLS-enforcement
// parameter and a parser yielding (isInsecure, isRecognized). Unknown values
// become check errors rather than being silently treated as secure.
func tlsParameterForFamily(family string) (rdsTLSParameter, bool) {
	family = strings.ToLower(family)
	switch {
	case strings.Contains(family, "postgres"):
		return rdsTLSParameter{name: "rds.force_ssl", insecure: boolParameterIsOff}, true
	case strings.Contains(family, "mysql"):
		return rdsTLSParameter{name: "require_secure_transport", insecure: boolParameterIsOff}, true
	default:
		return rdsTLSParameter{}, false
	}
}

func boolParameterIsOff(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "off", "false":
		return true, true
	case "1", "on", "true":
		return false, true
	default:
		return false, false
	}
}

func rdsTLSEnforcement(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := rds.NewFromConfig(regionalCfg)
		var findings []string
		count := 0

		groups := rds.NewDescribeDBParameterGroupsPaginator(client, &rds.DescribeDBParameterGroupsInput{})
		for groups.HasMorePages() {
			page, err := groups.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}
			for _, group := range page.DBParameterGroups {
				parameter, supported := tlsParameterForFamily(aws.ToString(group.DBParameterGroupFamily))
				if !supported {
					continue
				}
				name := aws.ToString(group.DBParameterGroupName)
				value, err := dbParameterValue(ctx, client, name, parameter.name)
				if err != nil {
					return nil, 0, fmt.Errorf("DB parameter group %s: %w", name, err)
				}
				insecure, recognized := parameter.insecure(value)
				if !recognized {
					return nil, 0, fmt.Errorf("DB parameter group %s: unrecognized %s value %q", name, parameter.name, value)
				}
				count++
				if insecure {
					findings = append(findings, fmt.Sprintf("%s: RDS DB parameter group %s has %s=%s", regionalCfg.Region, name, parameter.name, value))
				}
			}
		}

		clusterGroups := rds.NewDescribeDBClusterParameterGroupsPaginator(client, &rds.DescribeDBClusterParameterGroupsInput{})
		for clusterGroups.HasMorePages() {
			page, err := clusterGroups.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}
			for _, group := range page.DBClusterParameterGroups {
				parameter, supported := tlsParameterForFamily(aws.ToString(group.DBParameterGroupFamily))
				if !supported {
					continue
				}
				name := aws.ToString(group.DBClusterParameterGroupName)
				value, err := dbClusterParameterValue(ctx, client, name, parameter.name)
				if err != nil {
					return nil, 0, fmt.Errorf("DB cluster parameter group %s: %w", name, err)
				}
				insecure, recognized := parameter.insecure(value)
				if !recognized {
					return nil, 0, fmt.Errorf("DB cluster parameter group %s: unrecognized %s value %q", name, parameter.name, value)
				}
				count++
				if insecure {
					findings = append(findings, fmt.Sprintf("%s: RDS DB cluster parameter group %s has %s=%s", regionalCfg.Region, name, parameter.name, value))
				}
			}
		}

		return findings, count, nil
	})
}

func dbParameterValue(ctx context.Context, client *rds.Client, group, parameter string) (string, error) {
	out, err := client.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
		DBParameterGroupName: aws.String(group),
		Filters:              []rdstypes.Filter{{Name: aws.String("parameter-name"), Values: []string{parameter}}},
	})
	if err != nil {
		return "", err
	}
	if len(out.Parameters) != 1 || out.Parameters[0].ParameterValue == nil {
		return "", fmt.Errorf("parameter %s was not returned", parameter)
	}
	return aws.ToString(out.Parameters[0].ParameterValue), nil
}

func dbClusterParameterValue(ctx context.Context, client *rds.Client, group, parameter string) (string, error) {
	out, err := client.DescribeDBClusterParameters(ctx, &rds.DescribeDBClusterParametersInput{
		DBClusterParameterGroupName: aws.String(group),
		Filters:                     []rdstypes.Filter{{Name: aws.String("parameter-name"), Values: []string{parameter}}},
	})
	if err != nil {
		return "", err
	}
	if len(out.Parameters) != 1 || out.Parameters[0].ParameterValue == nil {
		return "", fmt.Errorf("parameter %s was not returned", parameter)
	}
	return aws.ToString(out.Parameters[0].ParameterValue), nil
}
