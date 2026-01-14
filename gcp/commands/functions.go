package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPFunctionsCommand = &cobra.Command{
	Use:     globals.GCP_FUNCTIONS_MODULE_NAME,
	Aliases: []string{"function", "gcf", "cloud-functions"},
	Short:   "Enumerate GCP Cloud Functions with security analysis",
	Long: `Enumerate GCP Cloud Functions across projects with security-relevant details.

Features:
- Lists all Cloud Functions (Gen 2) accessible to the authenticated user
- Shows security configuration (ingress settings, VPC connector, service account)
- Identifies publicly invokable functions (allUsers/allAuthenticatedUsers)
- Shows runtime, trigger type, and trigger configuration
- Counts environment variables and secret references
- Generates gcloud commands for further enumeration and exploitation

Security Columns:
- Ingress: ALL_TRAFFIC (public), INTERNAL_ONLY, or INTERNAL_AND_GCLB
- Public: Whether allUsers or allAuthenticatedUsers can invoke the function
- ServiceAccount: The identity the function runs as (privilege level)
- VPCConnector: Network connectivity to VPC resources
- Secrets: Count of secret environment variables and volumes

Resource IAM Columns:
- Resource Role: The IAM role granted ON this function (e.g., roles/cloudfunctions.invoker)
- Resource Principal: The principal (user/SA/group) who has that role on this function

Attack Surface:
- Public HTTP functions may be directly exploitable
- Functions with default service account may have excessive permissions
- Functions with VPC connectors can access internal resources
- Event triggers reveal integration points (Pub/Sub, Storage, etc.)`,
	Run: runGCPFunctionsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type FunctionsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields - per-project for hierarchical output
	ProjectFunctions map[string][]FunctionsService.FunctionInfo // projectID -> functions
	LootMap          map[string]map[string]*internal.LootFile   // projectID -> loot files
	PrivescCache     *gcpinternal.PrivescCache                  // Cached privesc analysis results
	mu               sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type FunctionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FunctionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FunctionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPFunctionsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_FUNCTIONS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &FunctionsModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectFunctions: make(map[string][]FunctionsService.FunctionInfo),
		LootMap:          make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *FunctionsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get privesc cache from context (populated by --with-privesc flag or all-checks)
	m.PrivescCache = gcpinternal.GetPrivescCacheFromContext(ctx)

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_FUNCTIONS_MODULE_NAME, m.processProject)

	// Get all functions for stats
	allFunctions := m.getAllFunctions()
	if len(allFunctions) == 0 {
		logger.InfoM("No Cloud Functions found", globals.GCP_FUNCTIONS_MODULE_NAME)
		return
	}

	// Count public functions
	publicCount := 0
	for _, fn := range allFunctions {
		if fn.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d function(s), %d PUBLIC", len(allFunctions), publicCount), globals.GCP_FUNCTIONS_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d function(s)", len(allFunctions)), globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// getAllFunctions returns all functions from all projects (for statistics)
func (m *FunctionsModule) getAllFunctions() []FunctionsService.FunctionInfo {
	var all []FunctionsService.FunctionInfo
	for _, functions := range m.ProjectFunctions {
		all = append(all, functions...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *FunctionsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Functions in project: %s", projectID), globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	fs := FunctionsService.New()
	functions, err := fs.Functions(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FUNCTIONS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate functions in project %s", projectID))
		return
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectFunctions[projectID] = functions

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["functions-commands"] = &internal.LootFile{
			Name:     "functions-commands",
			Contents: "# GCP Cloud Functions Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
		m.LootMap[projectID]["functions-env-vars"] = &internal.LootFile{
			Name:     "functions-env-vars",
			Contents: "# Cloud Functions Environment Variables\n# Generated by CloudFox\n# Variable names that may hint at secrets\n\n",
		}
		m.LootMap[projectID]["functions-secrets"] = &internal.LootFile{
			Name:     "functions-secrets",
			Contents: "# Cloud Functions Secret References\n# Generated by CloudFox\n# Secrets used by functions (names only)\n\n",
		}
	}

	for _, fn := range functions {
		m.addFunctionToLoot(projectID, fn)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d function(s) in project %s", len(functions), projectID), globals.GCP_FUNCTIONS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *FunctionsModule) addFunctionToLoot(projectID string, fn FunctionsService.FunctionInfo) {
	commandsLoot := m.LootMap[projectID]["functions-commands"]
	envVarsLoot := m.LootMap[projectID]["functions-env-vars"]
	secretsLoot := m.LootMap[projectID]["functions-secrets"]

	if commandsLoot == nil {
		return
	}

	// All commands for this function
	commandsLoot.Contents += fmt.Sprintf(
		"## Function: %s (Project: %s, Region: %s)\n"+
			"# Runtime: %s, Trigger: %s\n"+
			"# Service Account: %s\n"+
			"# Public: %v, Ingress: %s\n",
		fn.Name, fn.ProjectID, fn.Region,
		fn.Runtime, fn.TriggerType,
		fn.ServiceAccount,
		fn.IsPublic, fn.IngressSettings,
	)

	if fn.TriggerURL != "" {
		commandsLoot.Contents += fmt.Sprintf("# URL: %s\n", fn.TriggerURL)
	}

	if fn.SourceLocation != "" {
		commandsLoot.Contents += fmt.Sprintf("# Source: %s (%s)\n", fn.SourceLocation, fn.SourceType)
	}

	commandsLoot.Contents += fmt.Sprintf(
		"\n# Describe function:\n"+
			"gcloud functions describe %s --region=%s --project=%s --gen2\n"+
			"# Get IAM policy:\n"+
			"gcloud functions get-iam-policy %s --region=%s --project=%s --gen2\n"+
			"# Read logs:\n"+
			"gcloud functions logs read %s --region=%s --project=%s --gen2 --limit=50\n",
		fn.Name, fn.Region, fn.ProjectID,
		fn.Name, fn.Region, fn.ProjectID,
		fn.Name, fn.Region, fn.ProjectID,
	)

	// HTTP invocation commands
	if fn.TriggerType == "HTTP" && fn.TriggerURL != "" {
		commandsLoot.Contents += fmt.Sprintf(
			"# Invoke (GET):\n"+
				"curl -s '%s'\n"+
				"# Invoke (POST with auth):\n"+
				"curl -s -X POST '%s' \\\n"+
				"  -H 'Authorization: Bearer $(gcloud auth print-identity-token)' \\\n"+
				"  -H 'Content-Type: application/json' \\\n"+
				"  -d '{\"test\": \"data\"}'\n",
			fn.TriggerURL,
			fn.TriggerURL,
		)
	}

	// Source download command
	if fn.SourceType == "GCS" && fn.SourceLocation != "" {
		commandsLoot.Contents += fmt.Sprintf(
			"# Download source:\n"+
				"gsutil cp %s ./function-source-%s.zip\n",
			fn.SourceLocation, fn.Name,
		)
	}

	commandsLoot.Contents += "\n"

	// Environment variable names (keep separate - useful for secret hunting)
	if len(fn.EnvVarNames) > 0 && envVarsLoot != nil {
		envVarsLoot.Contents += fmt.Sprintf(
			"## Function: %s (Project: %s)\n",
			fn.Name, fn.ProjectID,
		)
		for _, varName := range fn.EnvVarNames {
			envVarsLoot.Contents += fmt.Sprintf("##   - %s\n", varName)
		}
		envVarsLoot.Contents += "\n"
	}

	// Secret references (keep separate - useful for secret hunting)
	if (len(fn.SecretEnvVarNames) > 0 || len(fn.SecretVolumeNames) > 0) && secretsLoot != nil {
		secretsLoot.Contents += fmt.Sprintf(
			"## Function: %s (Project: %s)\n",
			fn.Name, fn.ProjectID,
		)
		if len(fn.SecretEnvVarNames) > 0 {
			secretsLoot.Contents += "## Secret Environment Variables:\n"
			for _, secretName := range fn.SecretEnvVarNames {
				secretsLoot.Contents += fmt.Sprintf("##   - %s\n", secretName)
			}
		}
		if len(fn.SecretVolumeNames) > 0 {
			secretsLoot.Contents += "## Secret Volumes:\n"
			for _, volName := range fn.SecretVolumeNames {
				secretsLoot.Contents += fmt.Sprintf("##   - %s\n", volName)
			}
		}
		secretsLoot.Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *FunctionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *FunctionsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, functions := range m.ProjectFunctions {
		body := m.functionsToTableBody(functions)
		tables := []internal.TableFile{{
			Name:   globals.GCP_FUNCTIONS_MODULE_NAME,
			Header: header,
			Body:   body,
		}}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !isEmptyLootFile(loot.Contents) {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = FunctionsOutput{Table: tables, Loot: lootFiles}
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
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_FUNCTIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *FunctionsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getTableHeader()
	allFunctions := m.getAllFunctions()
	body := m.functionsToTableBody(allFunctions)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !isEmptyLootFile(loot.Contents) {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	tableFiles := []internal.TableFile{}
	if len(body) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FUNCTIONS_MODULE_NAME,
			Header: header,
			Body:   body,
		})
	}

	output := FunctionsOutput{
		Table: tableFiles,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_FUNCTIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// isEmptyLootFile checks if a loot file contains only the header
func isEmptyLootFile(contents string) bool {
	return strings.HasSuffix(contents, "# WARNING: Only use with proper authorization\n\n") ||
		strings.HasSuffix(contents, "# Variable names that may hint at secrets\n\n") ||
		strings.HasSuffix(contents, "# Secrets used by functions (names only)\n\n")
}

// getTableHeader returns the functions table header
func (m *FunctionsModule) getTableHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"State",
		"Runtime",
		"Trigger",
		"URL",
		"Ingress",
		"Public",
		"Service Account",
		"Priv Esc",
		"VPC Connector",
		"Secrets",
		"Resource Role",
		"Resource Principal",
	}
}

// functionsToTableBody converts functions to table body rows
func (m *FunctionsModule) functionsToTableBody(functions []FunctionsService.FunctionInfo) [][]string {
	var body [][]string
	for _, fn := range functions {
		// Format trigger info
		triggerInfo := fn.TriggerType
		if fn.TriggerEventType != "" {
			triggerInfo = fn.TriggerType
		}

		// Format URL - no truncation
		url := "-"
		if fn.TriggerURL != "" {
			url = fn.TriggerURL
		}

		// Format VPC connector
		vpcConnector := "-"
		if fn.VPCConnector != "" {
			vpcConnector = fn.VPCConnector
		}

		// Format secrets count
		secretsInfo := "-"
		totalSecrets := fn.SecretEnvVarCount + fn.SecretVolumeCount
		if totalSecrets > 0 {
			secretsInfo = fmt.Sprintf("%d", totalSecrets)
		}

		// Format service account - no truncation
		serviceAccount := fn.ServiceAccount
		if serviceAccount == "" {
			serviceAccount = "-"
		}

		// Check privesc for the service account
		privEsc := "-"
		if m.PrivescCache != nil && m.PrivescCache.IsPopulated() {
			if serviceAccount != "-" {
				privEsc = m.PrivescCache.GetPrivescSummary(serviceAccount)
			} else {
				privEsc = "No"
			}
		}

		// If function has IAM bindings, create one row per binding
		if len(fn.IAMBindings) > 0 {
			for _, binding := range fn.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(fn.ProjectID),
					fn.ProjectID,
					fn.Name,
					fn.Region,
					fn.State,
					fn.Runtime,
					triggerInfo,
					url,
					fn.IngressSettings,
					boolToYesNo(fn.IsPublic),
					serviceAccount,
					privEsc,
					vpcConnector,
					secretsInfo,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// Function has no IAM bindings - single row
			body = append(body, []string{
				m.GetProjectName(fn.ProjectID),
				fn.ProjectID,
				fn.Name,
				fn.Region,
				fn.State,
				fn.Runtime,
				triggerInfo,
				url,
				fn.IngressSettings,
				boolToYesNo(fn.IsPublic),
				serviceAccount,
				privEsc,
				vpcConnector,
				secretsInfo,
				"-",
				"-",
			})
		}
	}
	return body
}
