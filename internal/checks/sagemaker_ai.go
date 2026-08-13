package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

func init() {
	Register(Check{ID: "aws.sagemaker.endpoint_encryption", Title: "SageMaker endpoints without KMS encryption", Tier: ProviderAttested, Run: sagemakerEndpointEncryption})
	Register(Check{ID: "aws.sagemaker.endpoint_network", Title: "SageMaker endpoints outside a VPC", Tier: ProviderAttested, Run: sagemakerEndpointNetwork})
	Register(Check{ID: "aws.sagemaker.notebook_internet", Title: "SageMaker notebooks with direct internet access", Tier: ProviderAttested, Run: sagemakerNotebookInternet})
	Register(Check{ID: "aws.sagemaker.notebook_encryption", Title: "SageMaker notebooks without KMS encryption", Tier: ProviderAttested, Run: sagemakerNotebookEncryption})
	Register(Check{ID: "aws.sagemaker.network_isolation", Title: "SageMaker workloads without network isolation", Tier: ProviderAttested, Run: sagemakerNetworkIsolation})
}

func sagemakerNetworkIsolation(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := sagemaker.NewFromConfig(regionalCfg)
		var findings, evidence []string
		count := 0
		type category struct{ checked, protected int }
		var modelCounts, trainingCounts, processingCounts, domainCounts category
		models := sagemaker.NewListModelsPaginator(client, &sagemaker.ListModelsInput{})
		for models.HasMorePages() {
			page, err := models.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, err
			}
			for _, item := range page.Models {
				count++
				modelCounts.checked++
				model, err := client.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: item.ModelName})
				if err != nil {
					return findings, evidence, count, err
				}
				if !aws.ToBool(model.EnableNetworkIsolation) {
					findings = append(findings, fmt.Sprintf("%s: SageMaker model %s has EnableNetworkIsolation=false and its container can make external network calls", regionalCfg.Region, aws.ToString(item.ModelName)))
				} else {
					modelCounts.protected++
				}
			}
		}
		trainings := sagemaker.NewListTrainingJobsPaginator(client, &sagemaker.ListTrainingJobsInput{})
		for trainings.HasMorePages() {
			page, err := trainings.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, err
			}
			for _, item := range page.TrainingJobSummaries {
				count++
				trainingCounts.checked++
				job, err := client.DescribeTrainingJob(ctx, &sagemaker.DescribeTrainingJobInput{TrainingJobName: item.TrainingJobName})
				if err != nil {
					return findings, evidence, count, err
				}
				if !aws.ToBool(job.EnableNetworkIsolation) {
					findings = append(findings, fmt.Sprintf("%s: SageMaker training job %s has EnableNetworkIsolation=false", regionalCfg.Region, aws.ToString(item.TrainingJobName)))
				} else {
					trainingCounts.protected++
				}
			}
		}
		processing := sagemaker.NewListProcessingJobsPaginator(client, &sagemaker.ListProcessingJobsInput{})
		for processing.HasMorePages() {
			page, err := processing.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, err
			}
			for _, item := range page.ProcessingJobSummaries {
				count++
				processingCounts.checked++
				job, err := client.DescribeProcessingJob(ctx, &sagemaker.DescribeProcessingJobInput{ProcessingJobName: item.ProcessingJobName})
				if err != nil {
					return findings, evidence, count, err
				}
				if job.NetworkConfig == nil || !aws.ToBool(job.NetworkConfig.EnableNetworkIsolation) {
					findings = append(findings, fmt.Sprintf("%s: SageMaker processing job %s has network isolation disabled", regionalCfg.Region, aws.ToString(item.ProcessingJobName)))
				} else {
					processingCounts.protected++
				}
			}
		}
		domains := sagemaker.NewListDomainsPaginator(client, &sagemaker.ListDomainsInput{})
		for domains.HasMorePages() {
			page, err := domains.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, err
			}
			for _, item := range page.Domains {
				count++
				domainCounts.checked++
				domain, err := client.DescribeDomain(ctx, &sagemaker.DescribeDomainInput{DomainId: item.DomainId})
				if err != nil {
					return findings, evidence, count, err
				}
				if domain.AppNetworkAccessType != sagemakertypes.AppNetworkAccessTypeVpcOnly {
					findings = append(findings, fmt.Sprintf("%s: SageMaker Studio domain %s is not VPC_ONLY app network access mode", regionalCfg.Region, aws.ToString(item.DomainName)))
				} else {
					domainCounts.protected++
				}
			}
		}
		evidence = append(evidence,
			fmt.Sprintf("%s: Models: %d checked, %d isolated, %d not isolated", regionalCfg.Region, modelCounts.checked, modelCounts.protected, modelCounts.checked-modelCounts.protected),
			fmt.Sprintf("%s: Training jobs: %d checked, %d isolated, %d not isolated", regionalCfg.Region, trainingCounts.checked, trainingCounts.protected, trainingCounts.checked-trainingCounts.protected),
			fmt.Sprintf("%s: Processing jobs: %d checked, %d isolated, %d not isolated", regionalCfg.Region, processingCounts.checked, processingCounts.protected, processingCounts.checked-processingCounts.protected),
			fmt.Sprintf("%s: Studio domains: %d checked, %d VPC_ONLY, %d not VPC_ONLY", regionalCfg.Region, domainCounts.checked, domainCounts.protected, domainCounts.checked-domainCounts.protected),
		)
		return findings, evidence, count, nil
	})
	return MarkNotInUse(result, "no SageMaker models, training jobs, processing jobs, or Studio domains were found in the scanned regions"), err
}

type endpointConfigInspector func(region, endpointName string, config *sagemaker.DescribeEndpointConfigOutput) string

func scanSageMakerEndpoints(ctx context.Context, cfg aws.Config, inspect endpointConfigInspector) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := sagemaker.NewFromConfig(regionalCfg)
		paginator := sagemaker.NewListEndpointsPaginator(client, &sagemaker.ListEndpointsInput{})
		var findings, evidence []string
		count := 0
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, fmt.Errorf("list endpoints: %w", err)
			}
			for _, endpoint := range page.Endpoints {
				count++
				name := aws.ToString(endpoint.EndpointName)
				described, err := client.DescribeEndpoint(ctx, &sagemaker.DescribeEndpointInput{EndpointName: endpoint.EndpointName})
				if err != nil {
					return findings, evidence, count, fmt.Errorf("describe endpoint %s: %w", name, err)
				}
				configName := described.EndpointConfigName
				config, err := client.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: configName})
				if err != nil {
					return findings, evidence, count, fmt.Errorf("describe endpoint config %s: %w", aws.ToString(configName), err)
				}
				if finding := inspect(regionalCfg.Region, name, config); finding != "" {
					findings = append(findings, finding)
				} else {
					evidence = append(evidence, fmt.Sprintf("%s: SageMaker endpoint %s satisfies this control", regionalCfg.Region, name))
				}
			}
		}
		return findings, evidence, count, nil
	})
	return MarkNotInUse(result, "no SageMaker endpoints were found in the scanned regions"), err
}

func sagemakerEndpointEncryption(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	return scanSageMakerEndpoints(ctx, cfg, func(region, endpointName string, config *sagemaker.DescribeEndpointConfigOutput) string {
		if aws.ToString(config.KmsKeyId) == "" {
			return fmt.Sprintf("%s: SageMaker endpoint %s uses an endpoint config without KmsKeyId", region, endpointName)
		}
		return ""
	})
}

func sagemakerEndpointNetwork(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	return scanSageMakerEndpoints(ctx, cfg, func(region, endpointName string, config *sagemaker.DescribeEndpointConfigOutput) string {
		if config.VpcConfig == nil || len(config.VpcConfig.Subnets) == 0 {
			return fmt.Sprintf("%s: SageMaker endpoint %s is not configured inside a VPC", region, endpointName)
		}
		return ""
	})
}

type notebookInspector func(region, notebookName string, notebook *sagemaker.DescribeNotebookInstanceOutput) string

func scanSageMakerNotebooks(ctx context.Context, cfg aws.Config, inspect notebookInspector) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := sagemaker.NewFromConfig(regionalCfg)
		paginator := sagemaker.NewListNotebookInstancesPaginator(client, &sagemaker.ListNotebookInstancesInput{})
		var findings, evidence []string
		count := 0
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, fmt.Errorf("list notebook instances: %w", err)
			}
			for _, summary := range page.NotebookInstances {
				count++
				name := aws.ToString(summary.NotebookInstanceName)
				notebook, err := client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: summary.NotebookInstanceName})
				if err != nil {
					return findings, evidence, count, fmt.Errorf("describe notebook %s: %w", name, err)
				}
				if finding := inspect(regionalCfg.Region, name, notebook); finding != "" {
					findings = append(findings, finding)
				} else {
					evidence = append(evidence, fmt.Sprintf("%s: SageMaker notebook %s satisfies this control", regionalCfg.Region, name))
				}
			}
		}
		return findings, evidence, count, nil
	})
	return MarkNotInUse(result, "no SageMaker notebook instances were found in the scanned regions"), err
}

func sagemakerNotebookInternet(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	return scanSageMakerNotebooks(ctx, cfg, func(region, notebookName string, notebook *sagemaker.DescribeNotebookInstanceOutput) string {
		if notebook.DirectInternetAccess == sagemakertypes.DirectInternetAccessEnabled {
			return fmt.Sprintf("%s: SageMaker notebook %s has DirectInternetAccess enabled", region, notebookName)
		}
		return ""
	})
}

func sagemakerNotebookEncryption(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	return scanSageMakerNotebooks(ctx, cfg, func(region, notebookName string, notebook *sagemaker.DescribeNotebookInstanceOutput) string {
		if aws.ToString(notebook.KmsKeyId) == "" {
			return fmt.Sprintf("%s: SageMaker notebook %s has no KmsKeyId", region, notebookName)
		}
		return ""
	})
}
