package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/cloudfox/gcp/commands"
	oauthservice "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	privescservice "github.com/BishopFox/cloudfox/gcp/services/privescService"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var (
	// GCP resources filtering options
	GCPOrganization       string
	GCPProjectID          string
	GCPProjectIDsFilePath string
	GCPProjectIDs         []string
	GCPAllProjects        bool

	// Project name mapping (ProjectID -> DisplayName)
	GCPProjectNames map[string]string

	// Output formatting options
	GCPOutputFormat    string
	GCPOutputDirectory string
	GCPVerbosity       int
	GCPWrapTable       bool
	GCPFlatOutput      bool

	// Privesc analysis flag
	GCPWithPrivesc bool

	// misc options
	// GCPIgnoreCache		bool

	// logger
	GCPLogger = internal.NewLogger()

	// GCP root command
	GCPCommands = &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcloud"},
		Long:    `See "Available Commands" for GCP Modules below`,
		Short:   "See \"Available Commands\" for GCP Modules below",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Initialize project names map
			GCPProjectNames = make(map[string]string)

			// Handle project discovery based on flags
			if GCPAllProjects {
				// Discover all accessible projects
				GCPLogger.InfoM("Discovering all accessible projects...", "gcp")
				orgsSvc := orgsservice.New()
				projects, err := orgsSvc.SearchProjects("")
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("Failed to discover projects: %v. Try using -p or -l flags instead.", err), "gcp")
				}
				for _, proj := range projects {
					if proj.State == "ACTIVE" {
						GCPProjectIDs = append(GCPProjectIDs, proj.ProjectID)
						GCPProjectNames[proj.ProjectID] = proj.DisplayName
					}
				}
				if len(GCPProjectIDs) == 0 {
					GCPLogger.FatalM("No accessible projects found. Check your permissions.", "gcp")
				}
				GCPLogger.InfoM(fmt.Sprintf("Discovered %d project(s)", len(GCPProjectIDs)), "gcp")
			} else if GCPProjectID != "" {
				GCPProjectIDs = append(GCPProjectIDs, GCPProjectID)
				// Resolve project name for single project
				resolveProjectNames(GCPProjectIDs)
			} else if GCPProjectIDsFilePath != "" {
				rawProjectIDs := internal.LoadFileLinesIntoArray(GCPProjectIDsFilePath)
				GCPProjectIDs = deduplicateProjectIDs(rawProjectIDs)
				// Resolve project names for all projects in list
				resolveProjectNames(GCPProjectIDs)
			} else {
				GCPLogger.InfoM("project, project-list, or all-projects flag not given, commands requiring a project ID will fail", "gcp")
			}

			// Create a context with project IDs and names
			ctx := context.WithValue(context.Background(), "projectIDs", GCPProjectIDs)
			ctx = context.WithValue(ctx, "projectNames", GCPProjectNames)

			// Authenticate and get account info
			os := oauthservice.NewOAuthService()
			principal, err := os.WhoAmI()
			if err != nil {
				GCPLogger.FatalM(fmt.Sprintf("could not determine default user credential with error %s.\n\nPlease use default application default credentials: https://cloud.google.com/docs/authentication/application-default-credentials\n\nTry: gcloud auth application-default login", err.Error()), "gcp")
			}
			ctx = context.WithValue(ctx, "account", principal.Email)

			// Build scope hierarchy for hierarchical output (unless --flat-output is set)
			if !GCPFlatOutput && len(GCPProjectIDs) > 0 {
				GCPLogger.InfoM("Building scope hierarchy for hierarchical output...", "gcp")
				orgsSvc := orgsservice.New()
				provider := orgsservice.NewHierarchyProvider(orgsSvc)
				hierarchy, err := gcpinternal.BuildScopeHierarchy(GCPProjectIDs, provider)
				if err != nil {
					GCPLogger.InfoM(fmt.Sprintf("Could not build hierarchy, using flat output: %v", err), "gcp")
				} else {
					ctx = context.WithValue(ctx, "hierarchy", hierarchy)
					// Log hierarchy summary
					if len(hierarchy.Organizations) > 0 {
						GCPLogger.InfoM(fmt.Sprintf("Detected %d organization(s), %d project(s)", len(hierarchy.Organizations), len(hierarchy.Projects)), "gcp")
					} else {
						GCPLogger.InfoM(fmt.Sprintf("Detected %d standalone project(s)", len(hierarchy.StandaloneProjs)), "gcp")
					}
				}
			}

			// If --with-privesc flag is set, run privesc analysis and populate cache
			// This allows individual modules to show the Priv Esc column
			if GCPWithPrivesc && len(GCPProjectIDs) > 0 {
				GCPLogger.InfoM("Running privilege escalation analysis (--with-privesc)...", "gcp")
				privescCache := runPrivescAndPopulateCache(ctx)
				if privescCache != nil && privescCache.IsPopulated() {
					ctx = gcpinternal.SetPrivescCacheInContext(ctx, privescCache)
					GCPLogger.SuccessM("Privesc cache populated - modules will show Priv Esc column", "gcp")
				}
			}

			cmd.SetContext(ctx)
		},
	}
)

// deduplicateProjectIDs removes duplicates, trims whitespace, and filters empty entries
func deduplicateProjectIDs(projectIDs []string) []string {
	seen := make(map[string]bool)
	var result []string
	duplicateCount := 0

	for _, id := range projectIDs {
		// Trim whitespace
		id = strings.TrimSpace(id)

		// Skip empty lines
		if id == "" {
			continue
		}

		// Skip duplicates
		if seen[id] {
			duplicateCount++
			continue
		}

		seen[id] = true
		result = append(result, id)
	}

	if duplicateCount > 0 {
		GCPLogger.InfoM(fmt.Sprintf("Removed %d duplicate project ID(s) from list", duplicateCount), "gcp")
	}

	return result
}

// resolveProjectNames fetches display names for given project IDs
func resolveProjectNames(projectIDs []string) {
	if len(projectIDs) == 0 {
		return
	}

	orgsSvc := orgsservice.New()
	// Fetch all accessible projects and build lookup map
	projects, err := orgsSvc.SearchProjects("")
	if err != nil {
		// Non-fatal: we can continue without display names
		GCPLogger.InfoM("Could not resolve project names, using project IDs only", "gcp")
		for _, id := range projectIDs {
			GCPProjectNames[id] = id // fallback to using ID as name
		}
		return
	}

	// Build lookup from fetched projects
	projectLookup := make(map[string]string)
	for _, proj := range projects {
		projectLookup[proj.ProjectID] = proj.DisplayName
	}

	// Map our project IDs to names
	for _, id := range projectIDs {
		if name, ok := projectLookup[id]; ok {
			GCPProjectNames[id] = name
		} else {
			GCPProjectNames[id] = id // fallback to using ID as name
		}
	}
}

// New RunAllGCPCommands function to execute all child commands
var GCPAllChecksCommand = &cobra.Command{
	Use:   "all-checks",
	Short: "Runs all available GCP commands",
	Long:  `Executes all available GCP commands to collect and display information from all supported GCP services.`,
	Run: func(cmd *cobra.Command, args []string) {
		var executedModules []string
		startTime := time.Now()
		ctx := cmd.Context()

		// Find the privesc command to run first
		var privescCmd *cobra.Command
		for _, childCmd := range GCPCommands.Commands() {
			if childCmd.Use == "privesc" {
				privescCmd = childCmd
				break
			}
		}

		// Run privesc command first (produces output) and populate cache for other modules
		if privescCmd != nil {
			GCPLogger.InfoM("Running privilege escalation analysis first...", "all-checks")
			privescCmd.Run(cmd, args)
			executedModules = append(executedModules, "privesc")

			// After running privesc, populate cache from the analysis for other modules
			privescCache := runPrivescAndPopulateCache(ctx)
			if privescCache != nil && privescCache.IsPopulated() {
				ctx = gcpinternal.SetPrivescCacheInContext(ctx, privescCache)
				cmd.SetContext(ctx)
				GCPLogger.SuccessM("Privesc cache populated - other modules will show Priv Esc column", "all-checks")
			}
			GCPLogger.InfoM("", "all-checks")
		}

		// Count total modules to execute (excluding self, hidden, and privesc which we already ran)
		var modulesToRun []*cobra.Command
		for _, childCmd := range GCPCommands.Commands() {
			if childCmd == cmd { // Skip the run-all command itself
				continue
			}
			if childCmd.Hidden { // Skip hidden commands
				continue
			}
			if childCmd.Use == "privesc" { // Skip privesc since we already ran it
				continue
			}
			modulesToRun = append(modulesToRun, childCmd)
		}
		totalModules := len(modulesToRun)

		GCPLogger.InfoM(fmt.Sprintf("Starting execution of %d modules...", totalModules), "all-checks")
		GCPLogger.InfoM("", "all-checks")

		for i, childCmd := range modulesToRun {
			GCPLogger.InfoM(fmt.Sprintf("[%d/%d] Running: %s", i+1, totalModules, childCmd.Use), "all-checks")
			childCmd.Run(cmd, args)
			executedModules = append(executedModules, childCmd.Use)
		}

		// Print summary
		duration := time.Since(startTime)
		printExecutionSummary(executedModules, duration)
	},
}

// runPrivescAndPopulateCache runs the privesc analysis and returns a populated cache
func runPrivescAndPopulateCache(ctx context.Context) *gcpinternal.PrivescCache {
	cache := gcpinternal.NewPrivescCache()

	// Get project IDs from context
	projectIDs, ok := ctx.Value("projectIDs").([]string)
	if !ok || len(projectIDs) == 0 {
		return cache
	}

	// Get project names from context
	projectNames, _ := ctx.Value("projectNames").(map[string]string)
	if projectNames == nil {
		projectNames = make(map[string]string)
	}

	// Run privesc analysis
	svc := privescservice.New()
	result, err := svc.CombinedPrivescAnalysis(ctx, projectIDs, projectNames)
	if err != nil {
		GCPLogger.ErrorM(fmt.Sprintf("Failed to run privesc analysis: %v", err), "all-checks")
		return cache
	}

	// Convert privesc paths to cache format
	var pathInfos []gcpinternal.PrivescPathInfo
	for _, path := range result.AllPaths {
		pathInfos = append(pathInfos, gcpinternal.PrivescPathInfo{
			Principal:     path.Principal,
			PrincipalType: path.PrincipalType,
			Method:        path.Method,
			RiskLevel:     path.RiskLevel,
			Target:        path.TargetResource,
			Permissions:   path.Permissions,
		})
	}

	// Populate cache
	cache.PopulateFromPaths(pathInfos)

	GCPLogger.InfoM(fmt.Sprintf("Found %d privilege escalation path(s)", len(result.AllPaths)), "all-checks")

	return cache
}

// printExecutionSummary prints a summary of all executed modules
func printExecutionSummary(modules []string, duration time.Duration) {
	GCPLogger.InfoM("", "all-checks") // blank line
	GCPLogger.InfoM("════════════════════════════════════════════════════════════", "all-checks")
	GCPLogger.InfoM("                    EXECUTION SUMMARY                        ", "all-checks")
	GCPLogger.InfoM("════════════════════════════════════════════════════════════", "all-checks")
	GCPLogger.InfoM(fmt.Sprintf("Total modules executed: %d", len(modules)), "all-checks")
	GCPLogger.InfoM(fmt.Sprintf("Total execution time:   %s", formatDuration(duration)), "all-checks")
	GCPLogger.InfoM("", "all-checks")
	GCPLogger.InfoM("Modules executed:", "all-checks")

	// Print modules in columns for better readability
	const columnsPerRow = 4
	for i := 0; i < len(modules); i += columnsPerRow {
		row := "  "
		for j := i; j < i+columnsPerRow && j < len(modules); j++ {
			row += fmt.Sprintf("%-20s", modules[j])
		}
		GCPLogger.InfoM(row, "all-checks")
	}

	GCPLogger.InfoM("", "all-checks")
	GCPLogger.InfoM(fmt.Sprintf("Output directory: %s", GCPOutputDirectory), "all-checks")
	GCPLogger.InfoM("════════════════════════════════════════════════════════════", "all-checks")
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f seconds", d.Seconds())
	} else if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func init() {
	// Globals flags for the GCP commands

	// Allow selection of non-default account to be used when accessing gcloud API
	// TODO

	// Resource filtering options
	// GCPCommands.PersistentFlags().StringVarP(&GCPOrganization, "organization", "o", "", "Organization name or number, repetable")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectID, "project", "p", "", "GCP project ID")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectIDsFilePath, "project-list", "l", "", "Path to a file containing a list of project IDs separated by newlines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPAllProjects, "all-projects", "a", false, "Automatically discover and use all accessible projects")
	// GCPCommands.PersistentFlags().BoolVarP(&GCPConfirm, "yes", "y", false, "Non-interactive mode (like apt/yum)")
	// GCPCommands.PersistentFlags().StringVarP(&GCPOutputFormat, "output", "", "brief", "[\"brief\" | \"wide\" ]")
	GCPCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	// defaultOutputDir is defined in cli.aws
	GCPCommands.PersistentFlags().StringVar(&GCPOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	// GCPCommands.PersistentFlags().IntVarP(&Goroutines, "max-goroutines", "g", 30, "Maximum number of concurrent goroutines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")
	GCPCommands.PersistentFlags().BoolVar(&GCPFlatOutput, "flat-output", false, "Use legacy flat output structure instead of hierarchical per-project directories")
	GCPCommands.PersistentFlags().BoolVar(&GCPWithPrivesc, "with-privesc", false, "Run privilege escalation analysis and add Priv Esc column to output (runs privesc first)")

	// Available commands
	GCPCommands.AddCommand(
		// Core/existing commands
		commands.GCPBucketsCommand,
		commands.GCPArtifactRegistryCommand,
		commands.GCPBigQueryCommand,
		commands.GCPSecretsCommand,
		commands.GCPIAMCommand,
		commands.GCPPermissionsCommand,
		commands.GCPResourceIAMCommand,
		commands.GCPInstancesCommand,
		commands.GCPWhoAmICommand,

		// Compute/serverless commands
		commands.GCPFunctionsCommand,
		commands.GCPCloudRunCommand,
		commands.GCPAppEngineCommand,
		commands.GCPGKECommand,
		commands.GCPCloudSQLCommand,

		// New infrastructure commands
		commands.GCPPubSubCommand,
		commands.GCPKMSCommand,
		commands.GCPLoggingCommand,
		commands.GCPSchedulerCommand,
		commands.GCPDNSCommand,
		commands.GCPFirewallCommand,
		commands.GCPServiceAccountsCommand,
		commands.GCPKeysCommand,
		commands.GCPEndpointsCommand,
		commands.GCPWorkloadIdentityCommand,
		commands.GCPOrganizationsCommand,
		commands.GCPCloudBuildCommand,
		commands.GCPMemorystoreCommand,
		commands.GCPFilestoreCommand,
		commands.GCPSpannerCommand,
		commands.GCPBigtableCommand,

		// Data processing commands
		commands.GCPDataflowCommand,
		commands.GCPComposerCommand,

		// Security/Compliance commands
		commands.GCPVPCSCCommand,
		commands.GCPAssetInventoryCommand,
		commands.GCPSecurityCenterCommand,
		commands.GCPComplianceDashboardCommand,
		commands.GCPBackupInventoryCommand,
		commands.GCPCostSecurityCommand,
		commands.GCPMonitoringAlertsCommand,

		// Network/Infrastructure commands
		commands.GCPLoadBalancersCommand,
		commands.GCPVPCNetworksCommand,
		commands.GCPNetworkTopologyCommand,

		// ML/Data Science commands
		commands.GCPNotebooksCommand,
		commands.GCPDataprocCommand,

		// Zero Trust/Access commands
		commands.GCPIAPCommand,
		commands.GCPBeyondCorpCommand,
		commands.GCPAccessLevelsCommand,

		// Pentest/Exploitation commands
		commands.GCPPrivescCommand,
		commands.GCPOrgPoliciesCommand,
		commands.GCPBucketEnumCommand,
		commands.GCPCrossProjectCommand,
		commands.GCPLoggingGapsCommand,
		commands.GCPSourceReposCommand,
		commands.GCPServiceAgentsCommand,
		commands.GCPDomainWideDelegationCommand,
		commands.GCPPrivateServiceConnectCommand,
		commands.GCPCloudArmorCommand,
		commands.GCPCertManagerCommand,
		commands.GCPLateralMovementCommand,
		commands.GCPDataExfiltrationCommand,
		commands.GCPPublicAccessCommand,

		// All checks (last)
		GCPAllChecksCommand,
	)
}
