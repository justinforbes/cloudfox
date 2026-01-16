package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	attackpathservice "github.com/BishopFox/cloudfox/gcp/services/attackpathService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPrivescCommand = &cobra.Command{
	Use:     globals.GCP_PRIVESC_MODULE_NAME,
	Aliases: []string{"pe", "escalate", "priv"},
	Short:   "Identify privilege escalation paths in GCP organizations, folders, and projects",
	Long: `Analyze GCP IAM policies to identify privilege escalation opportunities.

This module examines IAM bindings at organization, folder, project, and resource levels
to find principals with dangerous permissions that could be used to escalate
privileges within the GCP environment.

Detected privilege escalation methods (60+) include:

Service Account Abuse:
- Token Creation (getAccessToken, getOpenIdToken)
- Key Creation (serviceAccountKeys.create, hmacKeys.create)
- Implicit Delegation, SignBlob, SignJwt
- Workload Identity Federation (external identity impersonation)

IAM Policy Modification:
- Project/Folder/Org IAM Policy Modification
- Service Account IAM Policy + SA Creation combo
- Custom Role Create/Update (iam.roles.create/update)
- Org Policy Modification (orgpolicy.policy.set)
- Resource-specific IAM (Pub/Sub, BigQuery, Artifact Registry, Compute, KMS, Source Repos)

Compute & Serverless:
- Compute Instance Metadata Injection (SSH keys, startup scripts)
- Create GCE Instance with privileged SA
- Cloud Functions Create/Update with SA Identity
- Cloud Run Services/Jobs Create/Update with SA Identity
- App Engine Deploy with SA Identity
- Cloud Build SA Abuse

AI/ML:
- Vertex AI Custom Jobs with SA
- Vertex AI Notebooks with SA
- AI Platform Jobs with SA

Data Processing & Orchestration:
- Dataproc Cluster Create / Job Submit
- Cloud Composer Environment Create/Update
- Dataflow Job Create
- Cloud Workflows with SA
- Eventarc Triggers with SA

Scheduling & Tasks:
- Cloud Scheduler HTTP Request with SA
- Cloud Tasks with SA

Other:
- Deployment Manager Deployment
- GKE Cluster Access, Pod Exec, Secrets
- Secret Manager Access
- KMS Key Access / Decrypt
- API Key Creation/Listing`,
	Run: runGCPPrivescCommand,
}

type PrivescModule struct {
	gcpinternal.BaseGCPModule

	// All paths from combined analysis
	AllPaths      []attackpathservice.AttackPath
	OrgPaths      []attackpathservice.AttackPath
	FolderPaths   []attackpathservice.AttackPath
	ProjectPaths  map[string][]attackpathservice.AttackPath // projectID -> paths
	ResourcePaths []attackpathservice.AttackPath

	// Org/folder info
	OrgIDs      []string
	OrgNames    map[string]string
	FolderNames map[string]string

	// Loot
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type PrivescOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivescOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivescOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPPrivescCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PRIVESC_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PrivescModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		AllPaths:      []attackpathservice.AttackPath{},
		OrgPaths:      []attackpathservice.AttackPath{},
		FolderPaths:   []attackpathservice.AttackPath{},
		ProjectPaths:  make(map[string][]attackpathservice.AttackPath),
		ResourcePaths: []attackpathservice.AttackPath{},
		OrgIDs:        []string{},
		OrgNames:      make(map[string]string),
		FolderNames:   make(map[string]string),
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *PrivescModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing privilege escalation paths across organizations, folders, projects, and resources...", globals.GCP_PRIVESC_MODULE_NAME)

	// Use attackpathService with "privesc" path type
	svc := attackpathservice.New()
	result, err := svc.CombinedAttackPathAnalysis(ctx, m.ProjectIDs, m.ProjectNames, "privesc")
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PRIVESC_MODULE_NAME, "Failed to analyze privilege escalation")
		return
	}

	// Store results
	m.AllPaths = result.AllPaths
	m.OrgPaths = result.OrgPaths
	m.FolderPaths = result.FolderPaths
	m.ResourcePaths = result.ResourcePaths
	m.OrgIDs = result.OrgIDs
	m.OrgNames = result.OrgNames
	m.FolderNames = result.FolderNames

	// Organize project paths by project ID
	for _, path := range result.ProjectPaths {
		if path.ScopeType == "project" && path.ScopeID != "" {
			m.ProjectPaths[path.ScopeID] = append(m.ProjectPaths[path.ScopeID], path)
		}
	}

	// Generate loot
	m.generateLoot()

	if len(m.AllPaths) == 0 {
		logger.InfoM("No privilege escalation paths found", globals.GCP_PRIVESC_MODULE_NAME)
		return
	}

	// Count by scope type
	orgCount := len(m.OrgPaths)
	folderCount := len(m.FolderPaths)
	projectCount := len(result.ProjectPaths)
	resourceCount := len(m.ResourcePaths)

	logger.SuccessM(fmt.Sprintf("Found %d privilege escalation path(s): %d org-level, %d folder-level, %d project-level, %d resource-level",
		len(m.AllPaths), orgCount, folderCount, projectCount, resourceCount), globals.GCP_PRIVESC_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *PrivescModule) generateLoot() {
	m.LootMap["privesc-exploit-commands"] = &internal.LootFile{
		Name:     "privesc-exploit-commands",
		Contents: "# GCP Privilege Escalation Exploit Commands\n# Generated by CloudFox\n\n",
	}

	for _, path := range m.AllPaths {
		m.addPathToLoot(path)
	}
}

func (m *PrivescModule) addPathToLoot(path attackpathservice.AttackPath) {
	lootFile := m.LootMap["privesc-exploit-commands"]
	if lootFile == nil {
		return
	}

	scopeInfo := fmt.Sprintf("%s: %s", path.ScopeType, path.ScopeName)
	if path.ScopeName == "" {
		scopeInfo = fmt.Sprintf("%s: %s", path.ScopeType, path.ScopeID)
	}

	lootFile.Contents += fmt.Sprintf(
		"# Method: %s\n"+
			"# Principal: %s (%s)\n"+
			"# Scope: %s\n"+
			"# Target: %s\n"+
			"# Permissions: %s\n"+
			"%s\n\n",
		path.Method,
		path.Principal, path.PrincipalType,
		scopeInfo,
		path.TargetResource,
		strings.Join(path.Permissions, ", "),
		path.ExploitCommand,
	)
}

func (m *PrivescModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PrivescModule) getHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Source Principal",
		"Source Principal Type",
		"Action (Method)",
		"Target Resource",
		"Permissions",
	}
}

func (m *PrivescModule) pathsToTableBody(paths []attackpathservice.AttackPath) [][]string {
	var body [][]string
	for _, path := range paths {
		scopeName := path.ScopeName
		if scopeName == "" {
			scopeName = path.ScopeID
		}

		body = append(body, []string{
			path.ScopeType,
			path.ScopeID,
			scopeName,
			path.Principal,
			path.PrincipalType,
			path.Method,
			path.TargetResource,
			strings.Join(path.Permissions, ", "),
		})
	}
	return body
}

func (m *PrivescModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile
	if paths, ok := m.ProjectPaths[projectID]; ok && len(paths) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "privesc",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(paths),
		})
	}
	return tableFiles
}

func (m *PrivescModule) buildAllTables() []internal.TableFile {
	if len(m.AllPaths) == 0 {
		return nil
	}
	return []internal.TableFile{
		{
			Name:   "privesc",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(m.AllPaths),
		},
	}
}

func (m *PrivescModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *PrivescModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Determine org ID - prefer hierarchy (for consistent output paths across modules),
	// fall back to discovered orgs if hierarchy doesn't have org info
	orgID := ""
	if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	} else if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = PrivescOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 && len(projectTables[0].Body) > 0 {
				outputData.ProjectLevelData[projectID] = PrivescOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = PrivescOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}

func (m *PrivescModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildAllTables()
	lootFiles := m.collectLootFiles()

	output := PrivescOutput{Table: tables, Loot: lootFiles}

	// Determine output scope - use org if available, otherwise fall back to project
	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
		// Use organization scope with [O] prefix format
		scopeType = "organization"
		for _, orgID := range m.OrgIDs {
			scopeIdentifiers = append(scopeIdentifiers, orgID)
			if name, ok := m.OrgNames[orgID]; ok && name != "" {
				scopeNames = append(scopeNames, name)
			} else {
				scopeNames = append(scopeNames, orgID)
			}
		}
	} else {
		// Fall back to project scope
		scopeType = "project"
		scopeIdentifiers = m.ProjectIDs
		for _, id := range m.ProjectIDs {
			scopeNames = append(scopeNames, m.GetProjectName(id))
		}
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIdentifiers,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}
