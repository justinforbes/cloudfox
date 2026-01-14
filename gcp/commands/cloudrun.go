package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudRunCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDRUN_MODULE_NAME,
	Aliases: []string{"run", "cr"},
	Short:   "Enumerate Cloud Run services and jobs with security analysis",
	Long: `Enumerate Cloud Run services and jobs across projects with security-relevant details.

Features:
- Lists all Cloud Run services and jobs
- Shows security configuration (ingress, VPC, service account)
- Identifies publicly invokable services (allUsers/allAuthenticatedUsers)
- Shows container image, resources, and scaling configuration
- Counts environment variables and secret references
- Generates gcloud commands for further analysis

Security Columns:
- Ingress: INGRESS_TRAFFIC_ALL (public), INTERNAL_ONLY, or INTERNAL_LOAD_BALANCER
- Public: Whether allUsers or allAuthenticatedUsers can invoke the service
- ServiceAccount: The identity the service runs as
- VPCAccess: Network connectivity to VPC resources
- Secrets: Count of secret environment variables and volumes

Attack Surface:
- Public services with ALL ingress are internet-accessible
- Services with default service account may have excessive permissions
- VPC-connected services can access internal resources
- Container images may contain vulnerabilities or secrets`,
	Run: runGCPCloudRunCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudRunModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectServices map[string][]CloudRunService.ServiceInfo // projectID -> services
	ProjectJobs     map[string][]CloudRunService.JobInfo     // projectID -> jobs
	LootMap         map[string]map[string]*internal.LootFile // projectID -> loot files
	PrivescCache    *gcpinternal.PrivescCache                // Cached privesc analysis results
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudRunOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudRunOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudRunOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudRunCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDRUN_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudRunModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectServices: make(map[string][]CloudRunService.ServiceInfo),
		ProjectJobs:     make(map[string][]CloudRunService.JobInfo),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudRunModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get privesc cache from context (populated by --with-privesc flag or all-checks)
	m.PrivescCache = gcpinternal.GetPrivescCacheFromContext(ctx)

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDRUN_MODULE_NAME, m.processProject)

	// Get all resources for stats
	allServices := m.getAllServices()
	allJobs := m.getAllJobs()
	totalResources := len(allServices) + len(allJobs)
	if totalResources == 0 {
		logger.InfoM("No Cloud Run services or jobs found", globals.GCP_CLOUDRUN_MODULE_NAME)
		return
	}

	// Count public services
	publicCount := 0
	for _, svc := range allServices {
		if svc.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d service(s), %d job(s), %d public", len(allServices), len(allJobs), publicCount), globals.GCP_CLOUDRUN_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d service(s), %d job(s)", len(allServices), len(allJobs)), globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllServices returns all services from all projects (for statistics)
func (m *CloudRunModule) getAllServices() []CloudRunService.ServiceInfo {
	var all []CloudRunService.ServiceInfo
	for _, services := range m.ProjectServices {
		all = append(all, services...)
	}
	return all
}

// getAllJobs returns all jobs from all projects (for statistics)
func (m *CloudRunModule) getAllJobs() []CloudRunService.JobInfo {
	var all []CloudRunService.JobInfo
	for _, jobs := range m.ProjectJobs {
		all = append(all, jobs...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudRunModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Run in project: %s", projectID), globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	cs := CloudRunService.New()

	// Initialize loot for this project
	m.mu.Lock()
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["cloudrun-commands"] = &internal.LootFile{
			Name:     "cloudrun-commands",
			Contents: "# Cloud Run Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["cloudrun-env-vars"] = &internal.LootFile{
			Name:     "cloudrun-env-vars",
			Contents: "# Cloud Run Environment Variables\n# Generated by CloudFox\n\n",
		}
		m.LootMap[projectID]["cloudrun-secret-refs"] = &internal.LootFile{
			Name:     "cloudrun-secret-refs",
			Contents: "# Cloud Run Secret Manager References\n# Generated by CloudFox\n# Use: gcloud secrets versions access VERSION --secret=SECRET_NAME --project=PROJECT\n\n",
		}
	}
	m.mu.Unlock()

	// Get services
	services, err := cs.Services(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDRUN_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Run services in project %s", projectID))
	} else {
		m.mu.Lock()
		m.ProjectServices[projectID] = services
		for _, svc := range services {
			m.addServiceToLoot(projectID, svc)
		}
		m.mu.Unlock()
	}

	// Get jobs
	jobs, err := cs.Jobs(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDRUN_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Run jobs in project %s", projectID))
	} else {
		m.mu.Lock()
		m.ProjectJobs[projectID] = jobs
		for _, job := range jobs {
			m.addJobToLoot(projectID, job)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service(s), %d job(s) in project %s", len(services), len(jobs), projectID), globals.GCP_CLOUDRUN_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudRunModule) addServiceToLoot(projectID string, svc CloudRunService.ServiceInfo) {
	commandsLoot := m.LootMap[projectID]["cloudrun-commands"]
	envVarsLoot := m.LootMap[projectID]["cloudrun-env-vars"]
	secretRefsLoot := m.LootMap[projectID]["cloudrun-secret-refs"]

	if commandsLoot == nil {
		return
	}

	// All commands for this service
	commandsLoot.Contents += fmt.Sprintf(
		"## Service: %s (Project: %s, Region: %s)\n"+
			"# Image: %s\n"+
			"# Service Account: %s\n"+
			"# Public: %v\n"+
			"# URL: %s\n\n"+
			"# Describe service:\n"+
			"gcloud run services describe %s --region=%s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud run services get-iam-policy %s --region=%s --project=%s\n"+
			"# List revisions:\n"+
			"gcloud run revisions list --service=%s --region=%s --project=%s\n"+
			"# Invoke the service (if you have run.routes.invoke):\n"+
			"curl -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" %s\n"+
			"# Deploy revision (if you have run.services.update):\n"+
			"gcloud run deploy %s --image=YOUR_IMAGE --region=%s --project=%s\n"+
			"# Read container logs (if you have logging.logEntries.list):\n"+
			"gcloud logging read 'resource.type=\"cloud_run_revision\" resource.labels.service_name=\"%s\"' --project=%s --limit=50\n\n",
		svc.Name, svc.ProjectID, svc.Region,
		svc.ContainerImage,
		svc.ServiceAccount,
		svc.IsPublic,
		svc.URL,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.URL,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.ProjectID,
	)

	// Add environment variables to loot
	if len(svc.EnvVars) > 0 && envVarsLoot != nil {
		envVarsLoot.Contents += fmt.Sprintf("## Service: %s (Project: %s, Region: %s)\n", svc.Name, svc.ProjectID, svc.Region)
		for _, env := range svc.EnvVars {
			if env.Source == "direct" {
				envVarsLoot.Contents += fmt.Sprintf("%s=%s\n", env.Name, env.Value)
			} else {
				envVarsLoot.Contents += fmt.Sprintf("%s=[Secret: %s:%s]\n", env.Name, env.SecretName, env.SecretVersion)
			}
		}
		envVarsLoot.Contents += "\n"
	}

	// Add secret references to loot
	if len(svc.SecretRefs) > 0 && secretRefsLoot != nil {
		secretRefsLoot.Contents += fmt.Sprintf("## Service: %s (Project: %s, Region: %s)\n", svc.Name, svc.ProjectID, svc.Region)
		for _, ref := range svc.SecretRefs {
			if ref.Type == "env" {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Env var: %s\ngcloud secrets versions access %s --secret=%s --project=%s\n",
					ref.EnvVarName, ref.SecretVersion, ref.SecretName, svc.ProjectID,
				)
			} else {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Volume mount: %s\ngcloud secrets versions access latest --secret=%s --project=%s\n",
					ref.MountPath, ref.SecretName, svc.ProjectID,
				)
			}
		}
		secretRefsLoot.Contents += "\n"
	}
}

func (m *CloudRunModule) addJobToLoot(projectID string, job CloudRunService.JobInfo) {
	commandsLoot := m.LootMap[projectID]["cloudrun-commands"]
	envVarsLoot := m.LootMap[projectID]["cloudrun-env-vars"]
	secretRefsLoot := m.LootMap[projectID]["cloudrun-secret-refs"]

	if commandsLoot == nil {
		return
	}

	// All commands for this job
	commandsLoot.Contents += fmt.Sprintf(
		"## Job: %s (Project: %s, Region: %s)\n"+
			"# Image: %s\n"+
			"# Service Account: %s\n\n"+
			"# Describe job:\n"+
			"gcloud run jobs describe %s --region=%s --project=%s\n"+
			"# List executions:\n"+
			"gcloud run jobs executions list --job=%s --region=%s --project=%s\n"+
			"# Execute the job (if you have run.jobs.run):\n"+
			"gcloud run jobs execute %s --region=%s --project=%s\n"+
			"# Update job image (if you have run.jobs.update):\n"+
			"gcloud run jobs update %s --image=YOUR_IMAGE --region=%s --project=%s\n\n",
		job.Name, job.ProjectID, job.Region,
		job.ContainerImage,
		job.ServiceAccount,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
	)

	// Add environment variables to loot
	if len(job.EnvVars) > 0 && envVarsLoot != nil {
		envVarsLoot.Contents += fmt.Sprintf("## Job: %s (Project: %s, Region: %s)\n", job.Name, job.ProjectID, job.Region)
		for _, env := range job.EnvVars {
			if env.Source == "direct" {
				envVarsLoot.Contents += fmt.Sprintf("%s=%s\n", env.Name, env.Value)
			} else {
				envVarsLoot.Contents += fmt.Sprintf("%s=[Secret: %s:%s]\n", env.Name, env.SecretName, env.SecretVersion)
			}
		}
		envVarsLoot.Contents += "\n"
	}

	// Add secret references to loot
	if len(job.SecretRefs) > 0 && secretRefsLoot != nil {
		secretRefsLoot.Contents += fmt.Sprintf("## Job: %s (Project: %s, Region: %s)\n", job.Name, job.ProjectID, job.Region)
		for _, ref := range job.SecretRefs {
			if ref.Type == "env" {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Env var: %s\ngcloud secrets versions access %s --secret=%s --project=%s\n",
					ref.EnvVarName, ref.SecretVersion, ref.SecretName, job.ProjectID,
				)
			} else {
				secretRefsLoot.Contents += fmt.Sprintf(
					"# Volume mount: %s\ngcloud secrets versions access latest --secret=%s --project=%s\n",
					ref.MountPath, ref.SecretName, job.ProjectID,
				)
			}
		}
		secretRefsLoot.Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudRunModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *CloudRunModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectServices {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectJobs {
		projectsWithData[projectID] = true
	}

	// Build project-level outputs
	for projectID := range projectsWithData {
		services := m.ProjectServices[projectID]
		jobs := m.ProjectJobs[projectID]

		tables := m.buildTablesForProject(projectID, services, jobs)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !isCloudRunEmptyLoot(loot.Contents) {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = CloudRunOutput{Table: tables, Loot: lootFiles}
	}

	// Create path builder using the module's hierarchy
	pathBuilder := m.BuildPathBuilder()

	// Write using hierarchical output
	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CLOUDRUN_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *CloudRunModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allServices := m.getAllServices()
	allJobs := m.getAllJobs()

	tables := m.buildTablesForProject("", allServices, allJobs)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !isCloudRunEmptyLoot(loot.Contents) {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := CloudRunOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDRUN_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// isCloudRunEmptyLoot checks if a loot file contains only the header
func isCloudRunEmptyLoot(contents string) bool {
	return strings.HasSuffix(contents, "# WARNING: Only use with proper authorization\n\n") ||
		strings.HasSuffix(contents, "# Generated by CloudFox\n\n") ||
		strings.HasSuffix(contents, "# Use: gcloud secrets versions access VERSION --secret=SECRET_NAME --project=PROJECT\n\n")
}

// buildTablesForProject builds all tables for a given project's services and jobs
func (m *CloudRunModule) buildTablesForProject(projectID string, services []CloudRunService.ServiceInfo, jobs []CloudRunService.JobInfo) []internal.TableFile {
	tableFiles := []internal.TableFile{}

	// Services table
	servicesHeader := []string{
		"Project ID", "Project Name", "Name", "Region", "URL", "Ingress", "Public",
		"Invokers", "Service Account", "Priv Esc", "Default SA", "Image", "VPC Access",
		"Min/Max", "Env Vars", "Secrets", "Hardcoded",
	}

	var servicesBody [][]string
	for _, svc := range services {
		publicStatus := "No"
		if svc.IsPublic {
			publicStatus = "Yes"
		}
		defaultSA := "No"
		if svc.UsesDefaultSA {
			defaultSA = "Yes"
		}
		invokers := "-"
		if len(svc.InvokerMembers) > 0 {
			invokers = strings.Join(svc.InvokerMembers, ", ")
		}
		vpcAccess := "-"
		if svc.VPCAccess != "" {
			vpcAccess = extractName(svc.VPCAccess)
			if svc.VPCEgressSettings != "" {
				vpcAccess += fmt.Sprintf(" (%s)", strings.TrimPrefix(svc.VPCEgressSettings, "VPC_EGRESS_"))
			}
		}
		scaling := fmt.Sprintf("%d/%d", svc.MinInstances, svc.MaxInstances)
		envVars := "-"
		if svc.EnvVarCount > 0 {
			envVars = fmt.Sprintf("%d", svc.EnvVarCount)
		}
		secretCount := svc.SecretEnvVarCount + svc.SecretVolumeCount
		secrets := "-"
		if secretCount > 0 {
			secrets = fmt.Sprintf("%d", secretCount)
		}
		hardcoded := "No"
		if len(svc.HardcodedSecrets) > 0 {
			hardcoded = fmt.Sprintf("Yes (%d)", len(svc.HardcodedSecrets))
		}

		// Check privesc for the service account
		privEsc := "-"
		if m.PrivescCache != nil && m.PrivescCache.IsPopulated() {
			if svc.ServiceAccount != "" {
				privEsc = m.PrivescCache.GetPrivescSummary(svc.ServiceAccount)
			} else {
				privEsc = "No"
			}
		}

		servicesBody = append(servicesBody, []string{
			svc.ProjectID, m.GetProjectName(svc.ProjectID), svc.Name, svc.Region, svc.URL,
			formatIngress(svc.IngressSettings), publicStatus, invokers, svc.ServiceAccount,
			privEsc, defaultSA, svc.ContainerImage, vpcAccess, scaling, envVars, secrets, hardcoded,
		})
	}

	if len(servicesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-services",
			Header: servicesHeader,
			Body:   servicesBody,
		})
	}

	// Jobs table
	jobsHeader := []string{
		"Project ID", "Project Name", "Name", "Region", "Service Account", "Priv Esc", "Default SA",
		"Image", "Tasks", "Parallelism", "Last Execution", "Env Vars", "Secrets", "Hardcoded",
	}

	var jobsBody [][]string
	for _, job := range jobs {
		defaultSA := "No"
		if job.UsesDefaultSA {
			defaultSA = "Yes"
		}
		envVars := "-"
		if job.EnvVarCount > 0 {
			envVars = fmt.Sprintf("%d", job.EnvVarCount)
		}
		secretCount := job.SecretEnvVarCount + job.SecretVolumeCount
		secrets := "-"
		if secretCount > 0 {
			secrets = fmt.Sprintf("%d", secretCount)
		}
		hardcoded := "No"
		if len(job.HardcodedSecrets) > 0 {
			hardcoded = fmt.Sprintf("Yes (%d)", len(job.HardcodedSecrets))
		}
		lastExec := "-"
		if job.LastExecution != "" {
			lastExec = extractName(job.LastExecution)
		}

		// Check privesc for the service account
		jobPrivEsc := "-"
		if m.PrivescCache != nil && m.PrivescCache.IsPopulated() {
			if job.ServiceAccount != "" {
				jobPrivEsc = m.PrivescCache.GetPrivescSummary(job.ServiceAccount)
			} else {
				jobPrivEsc = "No"
			}
		}

		jobsBody = append(jobsBody, []string{
			job.ProjectID, m.GetProjectName(job.ProjectID), job.Name, job.Region,
			job.ServiceAccount, jobPrivEsc, defaultSA, job.ContainerImage,
			fmt.Sprintf("%d", job.TaskCount), fmt.Sprintf("%d", job.Parallelism),
			lastExec, envVars, secrets, hardcoded,
		})
	}

	if len(jobsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-jobs",
			Header: jobsHeader,
			Body:   jobsBody,
		})
	}

	// Hardcoded secrets table
	secretsHeader := []string{
		"Project ID", "Project Name", "Resource Type", "Name", "Region", "Env Var", "Secret Type",
	}

	var secretsBody [][]string
	for _, svc := range services {
		for _, secret := range svc.HardcodedSecrets {
			secretsBody = append(secretsBody, []string{
				svc.ProjectID, m.GetProjectName(svc.ProjectID), "Service",
				svc.Name, svc.Region, secret.EnvVarName, secret.SecretType,
			})
			m.addSecretRemediationToLoot(svc.Name, svc.ProjectID, svc.Region, secret.EnvVarName, "service")
		}
	}
	for _, job := range jobs {
		for _, secret := range job.HardcodedSecrets {
			secretsBody = append(secretsBody, []string{
				job.ProjectID, m.GetProjectName(job.ProjectID), "Job",
				job.Name, job.Region, secret.EnvVarName, secret.SecretType,
			})
			m.addSecretRemediationToLoot(job.Name, job.ProjectID, job.Region, secret.EnvVarName, "job")
		}
	}

	if len(secretsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-secrets",
			Header: secretsHeader,
			Body:   secretsBody,
		})
	}

	return tableFiles
}

// Helper functions

// formatIngress formats ingress settings for display
func formatIngress(ingress string) string {
	switch ingress {
	case "INGRESS_TRAFFIC_ALL":
		return "ALL (Public)"
	case "INGRESS_TRAFFIC_INTERNAL_ONLY":
		return "INTERNAL"
	case "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER":
		return "INT+LB"
	default:
		return ingress
	}
}

// extractName extracts just the name from a resource path
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// addSecretRemediationToLoot adds remediation commands for hardcoded secrets
func (m *CloudRunModule) addSecretRemediationToLoot(resourceName, projectID, region, envVarName, resourceType string) {
	secretName := strings.ToLower(strings.ReplaceAll(envVarName, "_", "-"))

	m.mu.Lock()
	defer m.mu.Unlock()

	commandsLoot := m.LootMap[projectID]["cloudrun-commands"]
	if commandsLoot == nil {
		return
	}

	commandsLoot.Contents += fmt.Sprintf(
		"# CRITICAL: Migrate hardcoded secret %s from %s %s\n"+
			"# 1. Create secret in Secret Manager:\n"+
			"echo -n 'SECRET_VALUE' | gcloud secrets create %s --data-file=- --project=%s\n"+
			"# 2. Grant access to Cloud Run service account:\n"+
			"gcloud secrets add-iam-policy-binding %s --member='serviceAccount:SERVICE_ACCOUNT' --role='roles/secretmanager.secretAccessor' --project=%s\n",
		envVarName, resourceType, resourceName,
		secretName, projectID,
		secretName, projectID,
	)

	if resourceType == "service" {
		commandsLoot.Contents += fmt.Sprintf(
			"# 3. Update Cloud Run service to use secret:\n"+
				"gcloud run services update %s --update-secrets=%s=%s:latest --region=%s --project=%s\n\n",
			resourceName, envVarName, secretName, region, projectID,
		)
	} else {
		commandsLoot.Contents += fmt.Sprintf(
			"# 3. Update Cloud Run job to use secret:\n"+
				"gcloud run jobs update %s --update-secrets=%s=%s:latest --region=%s --project=%s\n\n",
			resourceName, envVarName, secretName, region, projectID,
		)
	}
}
