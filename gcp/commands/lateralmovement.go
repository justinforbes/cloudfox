package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	GKEService "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

// Module name constant
const GCP_LATERALMOVEMENT_MODULE_NAME string = "lateral-movement"

var GCPLateralMovementCommand = &cobra.Command{
	Use:     GCP_LATERALMOVEMENT_MODULE_NAME,
	Aliases: []string{"lateral", "pivot"},
	Short:   "Map lateral movement paths, credential theft vectors, and pivot opportunities",
	Long: `Identify lateral movement opportunities within and across GCP projects.

This module uses FoxMapper graph data for permission-based analysis combined with
direct enumeration of compute resources for token theft vectors.

Features:
- Maps service account impersonation chains (SA → SA → SA)
- Identifies token creator permissions (lateral movement via impersonation)
- Finds cross-project access paths
- Detects VM metadata abuse vectors
- Analyzes credential storage locations (secrets, environment variables)
- Generates exploitation commands for penetration testing

Prerequisites:
- Run 'foxmapper gcp graph create' for permission-based analysis

This module helps identify how an attacker could move laterally after gaining
initial access to a GCP environment.`,
	Run: runGCPLateralMovementCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

// LateralMovementPath represents a lateral movement opportunity
type LateralMovementPath struct {
	Source         string   // Starting point (principal or resource)
	SourceType     string   // Type of source (serviceAccount, user, compute_instance, etc.)
	Target         string   // Target resource/identity
	Method         string   // How the lateral movement is achieved
	Category       string   // Category of lateral movement
	Permissions    []string // Permissions required
	Description    string   // Human-readable description
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM, LOW
	ExploitCommand string   // Command to exploit
	ProjectID      string   // Project where this path exists
}

// ------------------------------
// Module Struct
// ------------------------------
type LateralMovementModule struct {
	gcpinternal.BaseGCPModule

	// Paths from enumeration
	ProjectPaths    map[string][]LateralMovementPath // projectID -> paths
	AllPaths        []LateralMovementPath            // All paths combined

	// FoxMapper findings
	FoxMapperFindings []foxmapperservice.LateralFinding // FoxMapper-based findings
	FoxMapperCache    *gcpinternal.FoxMapperCache

	// Loot
	LootMap map[string]map[string]*internal.LootFile // projectID -> loot files
	mu      sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LateralMovementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LateralMovementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LateralMovementOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLateralMovementCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_LATERALMOVEMENT_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LateralMovementModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectPaths:      make(map[string][]LateralMovementPath),
		AllPaths:          []LateralMovementPath{},
		FoxMapperFindings: []foxmapperservice.LateralFinding{},
		LootMap:           make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LateralMovementModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping lateral movement paths...", GCP_LATERALMOVEMENT_MODULE_NAME)

	// Get FoxMapper cache from context or try to load it
	m.FoxMapperCache = gcpinternal.GetFoxMapperCacheFromContext(ctx)
	if m.FoxMapperCache == nil || !m.FoxMapperCache.IsPopulated() {
		// Try to load FoxMapper data (org from hierarchy if available)
		orgID := ""
		if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
			orgID = m.Hierarchy.Organizations[0].ID
		}
		m.FoxMapperCache = gcpinternal.TryLoadFoxMapper(orgID, m.ProjectIDs)
	}

	// Process each project for actual token theft vectors
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_LATERALMOVEMENT_MODULE_NAME, m.processProject)

	// Consolidate project paths
	for _, paths := range m.ProjectPaths {
		m.AllPaths = append(m.AllPaths, paths...)
	}

	// Analyze permission-based lateral movement using FoxMapper
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Analyzing permission-based lateral movement using FoxMapper...", GCP_LATERALMOVEMENT_MODULE_NAME)
		svc := m.FoxMapperCache.GetService()
		m.FoxMapperFindings = svc.AnalyzeLateral("")
		if len(m.FoxMapperFindings) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d permission-based lateral movement techniques", len(m.FoxMapperFindings)), GCP_LATERALMOVEMENT_MODULE_NAME)
		}
	} else {
		logger.InfoM("No FoxMapper data found - skipping permission-based analysis. Run 'foxmapper gcp graph create' for full analysis.", GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	// Check results
	hasResults := len(m.AllPaths) > 0 || len(m.FoxMapperFindings) > 0

	if !hasResults {
		logger.InfoM("No lateral movement paths found", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	// Count by category for summary
	categoryCounts := make(map[string]int)
	for _, path := range m.AllPaths {
		categoryCounts[path.Category]++
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s) from enumeration", len(m.AllPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)
	if len(m.FoxMapperFindings) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d permission-based lateral movement technique(s)", len(m.FoxMapperFindings)), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LateralMovementModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["lateral-movement-commands"] = &internal.LootFile{
			Name:     "lateral-movement-commands",
			Contents: "# Lateral Movement Exploit Commands\n# Generated by CloudFox\n\n",
		}
	}
}

func (m *LateralMovementModule) generatePlaybook() *internal.LootFile {
	var sb strings.Builder
	sb.WriteString("# GCP Lateral Movement Playbook\n")
	sb.WriteString("# Generated by CloudFox\n\n")

	// Token theft vectors
	if len(m.AllPaths) > 0 {
		sb.WriteString("## Token Theft Vectors\n\n")

		// Group by category
		byCategory := make(map[string][]LateralMovementPath)
		for _, path := range m.AllPaths {
			byCategory[path.Category] = append(byCategory[path.Category], path)
		}

		for category, paths := range byCategory {
			sb.WriteString(fmt.Sprintf("### %s\n\n", category))
			for _, path := range paths {
				sb.WriteString(fmt.Sprintf("**%s → %s**\n", path.Source, path.Target))
				sb.WriteString(fmt.Sprintf("- Method: %s\n", path.Method))
				sb.WriteString(fmt.Sprintf("- Risk: %s\n", path.RiskLevel))
				sb.WriteString(fmt.Sprintf("- Description: %s\n\n", path.Description))
				if path.ExploitCommand != "" {
					sb.WriteString("```bash\n")
					sb.WriteString(path.ExploitCommand)
					sb.WriteString("\n```\n\n")
				}
			}
		}
	}

	// Permission-based findings from FoxMapper
	if len(m.FoxMapperFindings) > 0 {
		sb.WriteString("## Permission-Based Lateral Movement Techniques\n\n")
		for _, finding := range m.FoxMapperFindings {
			sb.WriteString(fmt.Sprintf("### %s (%s)\n", finding.Technique, finding.Category))
			sb.WriteString(fmt.Sprintf("- Permission: %s\n", finding.Permission))
			sb.WriteString(fmt.Sprintf("- Description: %s\n", finding.Description))
			sb.WriteString(fmt.Sprintf("- Principals with access: %d\n\n", len(finding.Principals)))
			if finding.Exploitation != "" {
				sb.WriteString("```bash\n")
				sb.WriteString(finding.Exploitation)
				sb.WriteString("\n```\n\n")
			}
		}
	}

	return &internal.LootFile{
		Name:     "lateral-movement-playbook",
		Contents: sb.String(),
	}
}

func (m *LateralMovementModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing lateral movement paths in project: %s", projectID), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	// 1. Find impersonation chains
	m.findImpersonationChains(ctx, projectID, logger)

	// 2. Find token theft vectors (compute instances, functions, etc.)
	m.findTokenTheftVectors(ctx, projectID, logger)
}

// findImpersonationChains finds service account impersonation paths
func (m *LateralMovementModule) findImpersonationChains(ctx context.Context, projectID string, logger internal.Logger) {
	iamService := IAMService.New()

	// Get all service accounts (without keys - not needed for impersonation analysis)
	serviceAccounts, err := iamService.ServiceAccountsBasic(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
			fmt.Sprintf("Could not get service accounts in project %s", projectID))
		return
	}

	// For each SA, check who can impersonate it
	for _, sa := range serviceAccounts {
		impersonationInfo, err := iamService.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
		if err != nil {
			continue
		}

		// Token creators can impersonate
		for _, creator := range impersonationInfo.TokenCreators {
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			riskLevel := "HIGH"
			if impersonationInfo.RiskLevel == "CRITICAL" {
				riskLevel = "CRITICAL"
			}

			path := LateralMovementPath{
				Source:      creator,
				SourceType:  shared.GetPrincipalType(creator),
				Target:      sa.Email,
				Method:      "Impersonate (Get Token)",
				Category:    "Service Account Impersonation",
				Permissions: []string{"iam.serviceAccounts.getAccessToken"},
				Description: fmt.Sprintf("%s can impersonate %s", creator, sa.Email),
				RiskLevel:   riskLevel,
				ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", sa.Email),
				ProjectID:   projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}

		// Key creators can create persistent access
		for _, creator := range impersonationInfo.KeyCreators {
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			path := LateralMovementPath{
				Source:      creator,
				SourceType:  shared.GetPrincipalType(creator),
				Target:      sa.Email,
				Method:      "Create Key",
				Category:    "Service Account Key Creation",
				Permissions: []string{"iam.serviceAccountKeys.create"},
				Description: fmt.Sprintf("%s can create keys for %s", creator, sa.Email),
				RiskLevel:   "CRITICAL",
				ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", sa.Email),
				ProjectID:   projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}
}

// findTokenTheftVectors finds compute resources where tokens can be stolen
func (m *LateralMovementModule) findTokenTheftVectors(ctx context.Context, projectID string, logger internal.Logger) {
	// Find Compute Engine instances with service accounts
	m.findComputeInstanceVectors(ctx, projectID, logger)

	// Find Cloud Functions with service accounts
	m.findCloudFunctionVectors(ctx, projectID, logger)

	// Find Cloud Run services with service accounts
	m.findCloudRunVectors(ctx, projectID, logger)

	// Find GKE clusters with node service accounts
	m.findGKEVectors(ctx, projectID, logger)
}

// findComputeInstanceVectors finds compute instances where tokens can be stolen via metadata server
func (m *LateralMovementModule) findComputeInstanceVectors(ctx context.Context, projectID string, logger internal.Logger) {
	computeService := ComputeEngineService.New()

	instances, err := computeService.Instances(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get compute instances in project %s", projectID))
		}
		return
	}

	for _, instance := range instances {
		if len(instance.ServiceAccounts) == 0 {
			continue
		}

		for _, sa := range instance.ServiceAccounts {
			if sa.Email == "" {
				continue
			}

			path := LateralMovementPath{
				Source:      instance.Name,
				SourceType:  "compute_instance",
				Target:      sa.Email,
				Method:      "Steal Token (Metadata)",
				Category:    "Compute Instance Token Theft",
				Permissions: []string{"compute.instances.get", "compute.instances.osLogin"},
				Description: fmt.Sprintf("Access to instance %s allows stealing token for %s", instance.Name, sa.Email),
				RiskLevel:   "HIGH",
				ExploitCommand: fmt.Sprintf(`# SSH into instance and steal token
gcloud compute ssh %s --zone=%s --project=%s --command='curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'`,
					instance.Name, instance.Zone, projectID),
				ProjectID: projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}
}

// findCloudFunctionVectors finds Cloud Functions where tokens can be stolen
func (m *LateralMovementModule) findCloudFunctionVectors(ctx context.Context, projectID string, logger internal.Logger) {
	functionsService := FunctionsService.New()

	functions, err := functionsService.Functions(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get Cloud Functions in project %s", projectID))
		}
		return
	}

	for _, fn := range functions {
		if fn.ServiceAccount == "" {
			continue
		}

		exploitCmd := fmt.Sprintf(`# Deploy function with target SA to steal token
# Requires: cloudfunctions.functions.create + iam.serviceAccounts.actAs
gcloud functions deploy token-theft-poc \
    --gen2 --runtime=python311 --region=%s \
    --entry-point=steal_token --trigger-http --allow-unauthenticated \
    --service-account=%s --project=%s`,
			fn.Region, fn.ServiceAccount, projectID)

		path := LateralMovementPath{
			Source:      fn.Name,
			SourceType:  "cloud_function",
			Target:      fn.ServiceAccount,
			Method:      "Steal Token (Function)",
			Category:    "Cloud Function Token Theft",
			Permissions: []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"},
			Description: fmt.Sprintf("Cloud Function %s runs with SA %s", fn.Name, fn.ServiceAccount),
			RiskLevel:   "HIGH",
			ExploitCommand: exploitCmd,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findCloudRunVectors finds Cloud Run services where tokens can be stolen
func (m *LateralMovementModule) findCloudRunVectors(ctx context.Context, projectID string, logger internal.Logger) {
	cloudRunService := CloudRunService.New()

	services, err := cloudRunService.Services(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get Cloud Run services in project %s", projectID))
		}
		return
	}

	for _, svc := range services {
		if svc.ServiceAccount == "" {
			continue
		}

		exploitCmd := fmt.Sprintf(`# Deploy Cloud Run service with target SA to steal token
# Requires: run.services.create + iam.serviceAccounts.actAs
gcloud run deploy token-theft-poc \
    --image gcr.io/%s/token-theft-poc \
    --region=%s --service-account=%s \
    --allow-unauthenticated --project=%s`,
			projectID, svc.Region, svc.ServiceAccount, projectID)

		path := LateralMovementPath{
			Source:      svc.Name,
			SourceType:  "cloud_run",
			Target:      svc.ServiceAccount,
			Method:      "Steal Token (Container)",
			Category:    "Cloud Run Token Theft",
			Permissions: []string{"run.services.create", "iam.serviceAccounts.actAs"},
			Description: fmt.Sprintf("Cloud Run service %s runs with SA %s", svc.Name, svc.ServiceAccount),
			RiskLevel:   "HIGH",
			ExploitCommand: exploitCmd,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findGKEVectors finds GKE clusters/node pools where tokens can be stolen
func (m *LateralMovementModule) findGKEVectors(ctx context.Context, projectID string, logger internal.Logger) {
	gkeService := GKEService.New()

	clusters, nodePools, err := gkeService.Clusters(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get GKE clusters in project %s", projectID))
		}
		return
	}

	// Track cluster SAs to avoid duplicates in node pools
	clusterSAs := make(map[string]string)

	for _, cluster := range clusters {
		if cluster.NodeServiceAccount != "" {
			clusterSAs[cluster.Name] = cluster.NodeServiceAccount

			var exploitCmd string
			if cluster.WorkloadIdentity != "" {
				exploitCmd = fmt.Sprintf(`# Cluster uses Workload Identity - tokens are pod-specific
gcloud container clusters get-credentials %s --location=%s --project=%s
kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
					cluster.Name, cluster.Location, projectID)
			} else {
				exploitCmd = fmt.Sprintf(`# Cluster uses node SA - all pods can access node SA
gcloud container clusters get-credentials %s --location=%s --project=%s
kubectl exec -it <pod> -- curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"`,
					cluster.Name, cluster.Location, projectID)
			}

			path := LateralMovementPath{
				Source:      cluster.Name,
				SourceType:  "gke_cluster",
				Target:      cluster.NodeServiceAccount,
				Method:      "Steal Token (Pod)",
				Category:    "GKE Cluster Token Theft",
				Permissions: []string{"container.clusters.getCredentials", "container.pods.exec"},
				Description: fmt.Sprintf("GKE cluster %s uses node SA %s", cluster.Name, cluster.NodeServiceAccount),
				RiskLevel:   "HIGH",
				ExploitCommand: exploitCmd,
				ProjectID:   projectID,
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}

	// Process node pools with different SAs than their cluster
	for _, np := range nodePools {
		clusterSA := clusterSAs[np.ClusterName]
		if np.ServiceAccount == "" || np.ServiceAccount == clusterSA {
			continue
		}

		exploitCmd := fmt.Sprintf(`# Node pool %s uses specific SA
gcloud container clusters get-credentials %s --location=%s --project=%s
# Exec into pod running on this node pool and steal token`,
			np.Name, np.ClusterName, np.Location, projectID)

		path := LateralMovementPath{
			Source:      fmt.Sprintf("%s/%s", np.ClusterName, np.Name),
			SourceType:  "gke_nodepool",
			Target:      np.ServiceAccount,
			Method:      "Steal Token (Pod)",
			Category:    "GKE Node Pool Token Theft",
			Permissions: []string{"container.clusters.getCredentials", "container.pods.exec"},
			Description: fmt.Sprintf("GKE node pool %s/%s uses SA %s", np.ClusterName, np.Name, np.ServiceAccount),
			RiskLevel:   "HIGH",
			ExploitCommand: exploitCmd,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LateralMovementModule) addPathToLoot(path LateralMovementPath, projectID string) {
	lootFile := m.LootMap[projectID]["lateral-movement-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# Method: %s\n"+
			"# Category: %s\n"+
			"# Source: %s (%s)\n"+
			"# Target: %s\n"+
			"# Permissions: %s\n"+
			"%s\n\n",
		path.Method,
		path.Category,
		path.Source, path.SourceType,
		path.Target,
		strings.Join(path.Permissions, ", "),
		path.ExploitCommand,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LateralMovementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *LateralMovementModule) getHeader() []string {
	return []string{
		"Project",
		"Source",
		"Source Type",
		"Target",
		"Method",
		"Category",
		"Risk Level",
	}
}

func (m *LateralMovementModule) getFoxMapperHeader() []string {
	return []string{
		"Technique",
		"Category",
		"Permission",
		"Description",
		"Principal Count",
	}
}

func (m *LateralMovementModule) pathsToTableBody(paths []LateralMovementPath) [][]string {
	var body [][]string
	for _, path := range paths {
		body = append(body, []string{
			m.GetProjectName(path.ProjectID),
			path.Source,
			path.SourceType,
			path.Target,
			path.Method,
			path.Category,
			path.RiskLevel,
		})
	}
	return body
}

func (m *LateralMovementModule) foxMapperFindingsToTableBody() [][]string {
	var body [][]string
	for _, f := range m.FoxMapperFindings {
		body = append(body, []string{
			f.Technique,
			f.Category,
			f.Permission,
			f.Description,
			fmt.Sprintf("%d", len(f.Principals)),
		})
	}
	return body
}

func (m *LateralMovementModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if paths, ok := m.ProjectPaths[projectID]; ok && len(paths) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "lateral-movement",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(paths),
		})
	}

	return tableFiles
}

func (m *LateralMovementModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Generate playbook once for all projects
	playbook := m.generatePlaybook()
	playbookAdded := false

	// Iterate over ALL projects, not just ones with enumerated paths
	for _, projectID := range m.ProjectIDs {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		// Add playbook to first project only
		if playbook != nil && playbook.Contents != "" && !playbookAdded {
			lootFiles = append(lootFiles, *playbook)
			playbookAdded = true
		}

		// Add FoxMapper findings table to first project only
		if len(m.FoxMapperFindings) > 0 && projectID == m.ProjectIDs[0] {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "lateral-movement-permissions",
				Header: m.getFoxMapperHeader(),
				Body:   m.foxMapperFindingsToTableBody(),
			})
		}

		// Only add to output if we have tables or loot
		if len(tableFiles) > 0 || len(lootFiles) > 0 {
			outputData.ProjectLevelData[projectID] = LateralMovementOutput{Table: tableFiles, Loot: lootFiles}
		}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
	}
}

func (m *LateralMovementModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := []internal.TableFile{}

	if len(m.AllPaths) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-movement",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(m.AllPaths),
		})
	}

	if len(m.FoxMapperFindings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-movement-permissions",
			Header: m.getFoxMapperHeader(),
			Body:   m.foxMapperFindingsToTableBody(),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	// Add playbook
	playbook := m.generatePlaybook()
	if playbook != nil && playbook.Contents != "" {
		lootFiles = append(lootFiles, *playbook)
	}

	output := LateralMovementOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
