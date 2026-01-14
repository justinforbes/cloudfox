package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	domainwidedelegationservice "github.com/BishopFox/cloudfox/gcp/services/domainWideDelegationService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPDomainWideDelegationCommand = &cobra.Command{
	Use:     globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME,
	Aliases: []string{"dwd", "delegation", "workspace-delegation"},
	Short:   "Find service accounts with Domain-Wide Delegation to Google Workspace",
	Long: `Find service accounts configured for Domain-Wide Delegation (DWD).

Domain-Wide Delegation allows a service account to impersonate any user in a
Google Workspace domain. This is EXTREMELY powerful and a high-value target.

With DWD + a service account key, an attacker can:
- Read any user's Gmail
- Access any user's Google Drive
- View any user's Calendar
- Enumerate all users and groups via Admin Directory API
- Send emails as any user
- And much more depending on authorized scopes

Detection Method:
- Service accounts with OAuth2 Client ID set have DWD enabled
- The actual authorized scopes are configured in Google Admin Console
- We check for naming patterns that suggest DWD purpose

To Exploit:
1. Obtain a key for the DWD service account
2. Identify a target user email in the Workspace domain
3. Generate tokens with the target user as 'subject'
4. Access Workspace APIs as that user

Note: Scopes must be authorized in Admin Console > Security > API Controls`,
	Run: runGCPDomainWideDelegationCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type DomainWideDelegationModule struct {
	gcpinternal.BaseGCPModule

	ProjectDWDAccounts map[string][]domainwidedelegationservice.DWDServiceAccount // projectID -> accounts
	LootMap            map[string]map[string]*internal.LootFile                   // projectID -> loot files
	mu                 sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type DomainWideDelegationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DomainWideDelegationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DomainWideDelegationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDomainWideDelegationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DomainWideDelegationModule{
		BaseGCPModule:      gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectDWDAccounts: make(map[string][]domainwidedelegationservice.DWDServiceAccount),
		LootMap:            make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DomainWideDelegationModule) getAllDWDAccounts() []domainwidedelegationservice.DWDServiceAccount {
	var all []domainwidedelegationservice.DWDServiceAccount
	for _, accounts := range m.ProjectDWDAccounts {
		all = append(all, accounts...)
	}
	return all
}

func (m *DomainWideDelegationModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME, m.processProject)

	allAccounts := m.getAllDWDAccounts()
	if len(allAccounts) == 0 {
		logger.InfoM("No Domain-Wide Delegation service accounts found", globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		return
	}

	// Count confirmed DWD accounts
	confirmedDWD := 0
	criticalCount := 0
	for _, account := range allAccounts {
		if account.DWDEnabled {
			confirmedDWD++
		}
		if account.RiskLevel == "CRITICAL" {
			criticalCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d potential DWD service account(s) (%d confirmed)", len(allAccounts), confirmedDWD), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)

	if criticalCount > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] %d DWD accounts with keys - can impersonate Workspace users!", criticalCount), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DomainWideDelegationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking DWD service accounts in project: %s", projectID), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["dwd-commands"] = &internal.LootFile{
			Name:     "dwd-commands",
			Contents: "# Domain-Wide Delegation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	svc := domainwidedelegationservice.New()
	accounts, err := svc.GetDWDServiceAccounts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME,
			fmt.Sprintf("Could not check DWD service accounts in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.ProjectDWDAccounts[projectID] = accounts

	for _, account := range accounts {
		m.addAccountToLoot(projectID, account)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS && len(accounts) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d DWD account(s) in project %s", len(accounts), projectID), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DomainWideDelegationModule) addAccountToLoot(projectID string, account domainwidedelegationservice.DWDServiceAccount) {
	lootFile := m.LootMap[projectID]["dwd-commands"]
	if lootFile == nil {
		return
	}

	// Add exploit commands for each account
	if len(account.ExploitCommands) > 0 {
		lootFile.Contents += fmt.Sprintf(
			"## Service Account: %s (Project: %s)\n"+
				"# DWD Enabled: %v\n"+
				"# OAuth2 Client ID: %s\n"+
				"# Keys: %d user-managed key(s)\n",
			account.Email, account.ProjectID,
			account.DWDEnabled,
			account.OAuth2ClientID,
			len(account.Keys),
		)
		// List key details
		for _, key := range account.Keys {
			lootFile.Contents += fmt.Sprintf(
				"#   - Key ID: %s (Created: %s, Expires: %s, Algorithm: %s)\n",
				key.KeyID, key.CreatedAt, key.ExpiresAt, key.KeyAlgorithm,
			)
		}
		lootFile.Contents += "\n"
		for _, cmd := range account.ExploitCommands {
			lootFile.Contents += cmd + "\n"
		}
		lootFile.Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *DomainWideDelegationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *DomainWideDelegationModule) getHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"Email",
		"DWD Enabled",
		"OAuth2 Client ID",
		"Key ID",
		"Key Created",
		"Key Expires",
		"Key Algorithm",
	}
}

func (m *DomainWideDelegationModule) accountsToTableBody(accounts []domainwidedelegationservice.DWDServiceAccount) [][]string {
	var body [][]string
	for _, account := range accounts {
		dwdStatus := "No"
		if account.DWDEnabled {
			dwdStatus = "Yes"
		}

		clientID := account.OAuth2ClientID
		if clientID == "" {
			clientID = "-"
		}

		if len(account.Keys) > 0 {
			// One row per key
			for _, key := range account.Keys {
				body = append(body, []string{
					account.ProjectID,
					m.GetProjectName(account.ProjectID),
					account.Email,
					dwdStatus,
					clientID,
					key.KeyID,
					key.CreatedAt,
					key.ExpiresAt,
					key.KeyAlgorithm,
				})
			}
		} else {
			// Account with no keys - still show it
			body = append(body, []string{
				account.ProjectID,
				m.GetProjectName(account.ProjectID),
				account.Email,
				dwdStatus,
				clientID,
				"-",
				"-",
				"-",
				"-",
			})
		}
	}
	return body
}

func (m *DomainWideDelegationModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if accounts, ok := m.ProjectDWDAccounts[projectID]; ok && len(accounts) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "domain-wide-delegation",
			Header: m.getHeader(),
			Body:   m.accountsToTableBody(accounts),
		})
	}

	return tableFiles
}

func (m *DomainWideDelegationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID := range m.ProjectDWDAccounts {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = DomainWideDelegationOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}
}

func (m *DomainWideDelegationModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allAccounts := m.getAllDWDAccounts()

	var tables []internal.TableFile

	if len(allAccounts) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "domain-wide-delegation",
			Header: m.getHeader(),
			Body:   m.accountsToTableBody(allAccounts),
		})
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := DomainWideDelegationOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
