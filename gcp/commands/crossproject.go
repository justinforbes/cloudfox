package commands

import (
	"context"
	"fmt"
	"strings"

	crossprojectservice "github.com/BishopFox/cloudfox/gcp/services/crossProjectService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCrossProjectCommand = &cobra.Command{
	Use:     globals.GCP_CROSSPROJECT_MODULE_NAME,
	Aliases: []string{"cross-project", "xproject", "lateral"},
	Short:   "Analyze cross-project access patterns for lateral movement",
	Long: `Analyze cross-project access patterns to identify lateral movement paths and data flows.

This module is designed for penetration testing and identifies:
- Service accounts with access to multiple projects
- Cross-project IAM role bindings
- Potential lateral movement paths between projects
- Cross-project logging sinks (data exfiltration via logs)
- Cross-project Pub/Sub exports (data exfiltration via messages)

Features:
- Maps cross-project service account access
- Identifies cross-project roles (owner, editor, admin)
- Discovers logging sinks sending logs to other projects
- Discovers Pub/Sub subscriptions exporting to other projects (BQ, GCS, push)
- Generates exploitation commands for lateral movement
- Highlights service accounts spanning trust boundaries

WARNING: Requires multiple projects to be specified for effective analysis.
Use -p for single project or -l for project list file.`,
	Run: runGCPCrossProjectCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CrossProjectModule struct {
	gcpinternal.BaseGCPModule

	CrossBindings         []crossprojectservice.CrossProjectBinding
	CrossProjectSAs       []crossprojectservice.CrossProjectServiceAccount
	LateralMovementPaths  []crossprojectservice.LateralMovementPath
	CrossProjectSinks     []crossprojectservice.CrossProjectLoggingSink
	CrossProjectPubSub    []crossprojectservice.CrossProjectPubSubExport
	LootMap               map[string]*internal.LootFile
}

// ------------------------------
// Output Struct
// ------------------------------
type CrossProjectOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CrossProjectOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CrossProjectOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCrossProjectCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CROSSPROJECT_MODULE_NAME)
	if err != nil {
		return
	}

	if len(cmdCtx.ProjectIDs) < 2 {
		cmdCtx.Logger.InfoM("Cross-project analysis works best with multiple projects. Consider using -l to specify a project list.", globals.GCP_CROSSPROJECT_MODULE_NAME)
	}

	module := &CrossProjectModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		CrossBindings:        []crossprojectservice.CrossProjectBinding{},
		CrossProjectSAs:      []crossprojectservice.CrossProjectServiceAccount{},
		LateralMovementPaths: []crossprojectservice.LateralMovementPath{},
		CrossProjectSinks:    []crossprojectservice.CrossProjectLoggingSink{},
		CrossProjectPubSub:   []crossprojectservice.CrossProjectPubSubExport{},
		LootMap:              make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CrossProjectModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Analyzing cross-project access patterns across %d project(s)...", len(m.ProjectIDs)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	svc := crossprojectservice.New()

	// Analyze cross-project bindings
	bindings, err := svc.AnalyzeCrossProjectAccess(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not analyze cross-project access")
	} else {
		m.CrossBindings = bindings
	}

	// Get cross-project service accounts
	sas, err := svc.GetCrossProjectServiceAccounts(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not get cross-project service accounts")
	} else {
		m.CrossProjectSAs = sas
	}

	// Find lateral movement paths
	paths, err := svc.FindLateralMovementPaths(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find lateral movement paths")
	} else {
		m.LateralMovementPaths = paths
	}

	// Find cross-project logging sinks
	sinks, err := svc.FindCrossProjectLoggingSinks(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find cross-project logging sinks")
	} else {
		m.CrossProjectSinks = sinks
	}

	// Find cross-project Pub/Sub exports
	pubsubExports, err := svc.FindCrossProjectPubSubExports(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find cross-project Pub/Sub exports")
	} else {
		m.CrossProjectPubSub = pubsubExports
	}

	if len(m.CrossBindings) == 0 && len(m.CrossProjectSAs) == 0 && len(m.LateralMovementPaths) == 0 &&
		len(m.CrossProjectSinks) == 0 && len(m.CrossProjectPubSub) == 0 {
		logger.InfoM("No cross-project access patterns found", globals.GCP_CROSSPROJECT_MODULE_NAME)
		return
	}

	// Add findings to loot
	for _, binding := range m.CrossBindings {
		m.addBindingToLoot(binding)
	}

	for _, sa := range m.CrossProjectSAs {
		m.addServiceAccountToLoot(sa)
	}

	for _, path := range m.LateralMovementPaths {
		m.addLateralMovementToLoot(path)
	}

	for _, sink := range m.CrossProjectSinks {
		m.addLoggingSinkToLoot(sink)
	}

	for _, export := range m.CrossProjectPubSub {
		m.addPubSubExportToLoot(export)
	}

	logger.SuccessM(fmt.Sprintf("Found %d binding(s), %d SA(s), %d lateral path(s), %d logging sink(s), %d pubsub export(s)",
		len(m.CrossBindings), len(m.CrossProjectSAs), len(m.LateralMovementPaths),
		len(m.CrossProjectSinks), len(m.CrossProjectPubSub)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CrossProjectModule) initializeLootFiles() {
	m.LootMap["crossproject-commands"] = &internal.LootFile{
		Name:     "crossproject-commands",
		Contents: "# Cross-Project Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *CrossProjectModule) addBindingToLoot(binding crossprojectservice.CrossProjectBinding) {
	// Add exploitation commands
	if len(binding.ExploitCommands) > 0 {
		m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
			"# IAM Binding: %s -> %s\n# Principal: %s\n# Role: %s\n",
			binding.SourceProject, binding.TargetProject, binding.Principal, binding.Role,
		)
		for _, cmd := range binding.ExploitCommands {
			m.LootMap["crossproject-commands"].Contents += cmd + "\n"
		}
		m.LootMap["crossproject-commands"].Contents += "\n"
	}
}

// isCrossTenantPrincipal checks if a principal is from outside the organization
func isCrossTenantPrincipal(principal string, projectIDs []string) bool {
	// Extract service account email
	email := strings.TrimPrefix(principal, "serviceAccount:")
	email = strings.TrimPrefix(email, "user:")
	email = strings.TrimPrefix(email, "group:")

	// Check if the email domain is gserviceaccount.com (service account)
	if strings.Contains(email, "@") && strings.Contains(email, ".iam.gserviceaccount.com") {
		// Extract project from SA email
		// Format: NAME@PROJECT.iam.gserviceaccount.com
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			domain := parts[1]
			saProject := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")

			// Check if SA's project is in our project list
			for _, p := range projectIDs {
				if p == saProject {
					return false // It's from within our organization
				}
			}
			return true // External SA
		}
	}

	// Check for compute/appspot service accounts
	if strings.Contains(email, "-compute@developer.gserviceaccount.com") ||
		strings.Contains(email, "@appspot.gserviceaccount.com") {
		// Extract project number/ID
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			projectPart := strings.Split(parts[0], "-")[0]
			for _, p := range projectIDs {
				if strings.Contains(p, projectPart) {
					return false
				}
			}
			return true
		}
	}

	// For regular users, check domain
	if strings.Contains(email, "@") && !strings.Contains(email, "gserviceaccount.com") {
		// Can't determine organization from email alone
		return false
	}

	return false
}

func (m *CrossProjectModule) addServiceAccountToLoot(sa crossprojectservice.CrossProjectServiceAccount) {
	// Add impersonation commands for cross-project SAs
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Cross-project SA: %s (Home: %s)\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
		sa.Email, sa.ProjectID, sa.Email,
	)
}

func (m *CrossProjectModule) addLateralMovementToLoot(path crossprojectservice.LateralMovementPath) {
	// Add lateral movement exploitation commands
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Lateral Movement: %s -> %s\n"+
			"# Principal: %s\n"+
			"# Method: %s\n"+
			"# Target Roles: %s\n",
		path.SourceProject, path.TargetProject,
		path.SourcePrincipal,
		path.AccessMethod,
		strings.Join(path.TargetRoles, ", "),
	)

	if len(path.ExploitCommands) > 0 {
		for _, cmd := range path.ExploitCommands {
			m.LootMap["crossproject-commands"].Contents += cmd + "\n"
		}
	}
	m.LootMap["crossproject-commands"].Contents += "\n"
}

func (m *CrossProjectModule) addLoggingSinkToLoot(sink crossprojectservice.CrossProjectLoggingSink) {
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Cross-Project Logging Sink: %s\n"+
			"# Source Project: %s -> Target Project: %s\n"+
			"# Destination: %s (%s)\n",
		sink.SinkName,
		sink.SourceProject, sink.TargetProject,
		sink.Destination, sink.DestinationType,
	)
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"gcloud logging sinks describe %s --project=%s\n\n",
		sink.SinkName, sink.SourceProject,
	)
}

func (m *CrossProjectModule) addPubSubExportToLoot(export crossprojectservice.CrossProjectPubSubExport) {
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Cross-Project Pub/Sub Export: %s\n"+
			"# Subscription: %s (Source: %s)\n"+
			"# Topic: %s (Project: %s)\n"+
			"# Export Type: %s -> Destination: %s\n",
		export.SubscriptionName,
		export.SubscriptionName, export.SourceProject,
		export.TopicName, export.TopicProject,
		export.ExportType,
		export.ExportDest,
	)
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"gcloud pubsub subscriptions describe %s --project=%s\n\n",
		export.SubscriptionName, export.SourceProject,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CrossProjectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Unified cross-project table with Type column
	header := []string{
		"Source Project Name",
		"Source Project ID",
		"Principal/Resource",
		"Type",
		"Action/Destination",
		"Target Project Name",
		"Target Project ID",
		"External",
	}

	var body [][]string

	// Add cross-project bindings
	for _, binding := range m.CrossBindings {
		external := "No"
		if isCrossTenantPrincipal(binding.Principal, m.ProjectIDs) {
			external = "Yes"
		}

		body = append(body, []string{
			m.GetProjectName(binding.SourceProject),
			binding.SourceProject,
			binding.Principal,
			"IAM Binding",
			binding.Role,
			m.GetProjectName(binding.TargetProject),
			binding.TargetProject,
			external,
		})
	}

	// Add cross-project service accounts (one row per target access)
	for _, sa := range m.CrossProjectSAs {
		for _, access := range sa.TargetAccess {
			// Parse access string (format: "project:role")
			parts := strings.SplitN(access, ":", 2)
			targetProject := ""
			role := access
			if len(parts) == 2 {
				targetProject = parts[0]
				role = parts[1]
			}

			body = append(body, []string{
				m.GetProjectName(sa.ProjectID),
				sa.ProjectID,
				sa.Email,
				"Service Account",
				role,
				m.GetProjectName(targetProject),
				targetProject,
				"No",
			})
		}
	}

	// Add lateral movement paths (one row per target role)
	for _, path := range m.LateralMovementPaths {
		for _, role := range path.TargetRoles {
			body = append(body, []string{
				m.GetProjectName(path.SourceProject),
				path.SourceProject,
				path.SourcePrincipal,
				"Lateral Movement",
				fmt.Sprintf("%s -> %s", path.AccessMethod, role),
				m.GetProjectName(path.TargetProject),
				path.TargetProject,
				"No",
			})
		}
	}

	// Add logging sinks
	for _, sink := range m.CrossProjectSinks {
		filter := sink.Filter
		if filter == "" {
			filter = "(all logs)"
		}

		body = append(body, []string{
			m.GetProjectName(sink.SourceProject),
			sink.SourceProject,
			sink.SinkName,
			"Logging Sink",
			fmt.Sprintf("%s: %s", sink.DestinationType, filter),
			m.GetProjectName(sink.TargetProject),
			sink.TargetProject,
			"No",
		})
	}

	// Add Pub/Sub exports
	for _, export := range m.CrossProjectPubSub {
		body = append(body, []string{
			m.GetProjectName(export.SourceProject),
			export.SourceProject,
			export.SubscriptionName,
			"Pub/Sub Export",
			fmt.Sprintf("%s -> %s", export.ExportType, export.ExportDest),
			m.GetProjectName(export.TargetProject),
			export.TargetProject,
			"No",
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	var tables []internal.TableFile

	if len(body) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "crossproject",
			Header: header,
			Body:   body,
		})
	}

	output := CrossProjectOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
