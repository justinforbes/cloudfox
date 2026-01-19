package crossprojectservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iam "google.golang.org/api/iam/v1"
	logging "google.golang.org/api/logging/v2"
	pubsub "google.golang.org/api/pubsub/v1"
)

type CrossProjectService struct {
	session *gcpinternal.SafeSession
}

func New() *CrossProjectService {
	return &CrossProjectService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *CrossProjectService {
	return &CrossProjectService{
		session: session,
	}
}

// getResourceManagerService returns a Resource Manager service using cached session if available
func (s *CrossProjectService) getResourceManagerService(ctx context.Context) (*cloudresourcemanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetResourceManagerService(ctx, s.session)
	}
	return cloudresourcemanager.NewService(ctx)
}

// getIAMService returns an IAM service using cached session if available
func (s *CrossProjectService) getIAMService(ctx context.Context) (*iam.Service, error) {
	if s.session != nil {
		return sdk.CachedGetIAMService(ctx, s.session)
	}
	return iam.NewService(ctx)
}

// getLoggingService returns a Logging service using cached session if available
func (s *CrossProjectService) getLoggingService(ctx context.Context) (*logging.Service, error) {
	if s.session != nil {
		return sdk.CachedGetLoggingService(ctx, s.session)
	}
	return logging.NewService(ctx)
}

// getPubSubService returns a PubSub service using cached session if available
func (s *CrossProjectService) getPubSubService(ctx context.Context) (*pubsub.Service, error) {
	if s.session != nil {
		return sdk.CachedGetPubSubService(ctx, s.session)
	}
	return pubsub.NewService(ctx)
}

// CrossProjectBinding represents a cross-project IAM binding
type CrossProjectBinding struct {
	SourceProject   string   `json:"sourceProject"`   // Where the principal is from
	TargetProject   string   `json:"targetProject"`   // Where access is granted
	Principal       string   `json:"principal"`       // The service account or user
	PrincipalType   string   `json:"principalType"`   // serviceAccount, user, group
	Role            string   `json:"role"`            // The IAM role granted
	RiskLevel       string   `json:"riskLevel"`       // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons     []string `json:"riskReasons"`     // Why it's risky
	ExploitCommands []string `json:"exploitCommands"` // Commands for exploitation
}

// CrossProjectServiceAccount represents a service account that may have cross-project access
type CrossProjectServiceAccount struct {
	Email         string   `json:"email"`
	ProjectID     string   `json:"projectId"`
	DisplayName   string   `json:"displayName"`
	UniqueID      string   `json:"uniqueId"`
	TargetAccess  []string `json:"targetAccess"` // Other projects this SA can access
}

// LateralMovementPath represents a potential lateral movement path
type LateralMovementPath struct {
	SourceProject      string   `json:"sourceProject"`
	SourcePrincipal    string   `json:"sourcePrincipal"`
	TargetProject      string   `json:"targetProject"`
	AccessMethod       string   `json:"accessMethod"`       // e.g., "impersonation", "direct role"
	TargetRoles        []string `json:"targetRoles"`
	PrivilegeLevel     string   `json:"privilegeLevel"`     // ADMIN, WRITE, READ
	ExploitCommands    []string `json:"exploitCommands"`
}

// CrossProjectLoggingSink represents a logging sink exporting to another project
type CrossProjectLoggingSink struct {
	SourceProject   string `json:"sourceProject"`   // Project where sink is configured
	SinkName        string `json:"sinkName"`        // Name of the logging sink
	Destination     string `json:"destination"`     // Full destination (bucket, BQ, pubsub, etc)
	DestinationType string `json:"destinationType"` // storage, bigquery, pubsub, logging
	TargetProject   string `json:"targetProject"`   // Project where data is sent
	Filter          string `json:"filter"`          // Log filter
	RiskLevel       string `json:"riskLevel"`       // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons     []string `json:"riskReasons"`
}

// CrossProjectPubSubExport represents a Pub/Sub subscription exporting to another project
type CrossProjectPubSubExport struct {
	SourceProject   string `json:"sourceProject"`   // Project where subscription is
	TopicProject    string `json:"topicProject"`    // Project where topic is
	TopicName       string `json:"topicName"`       // Topic name
	SubscriptionName string `json:"subscriptionName"` // Subscription name
	ExportType      string `json:"exportType"`      // push, bigquery, cloudstorage
	ExportDest      string `json:"exportDest"`      // Destination details
	TargetProject   string `json:"targetProject"`   // Project where data is exported to
	RiskLevel       string `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
}

// AnalyzeCrossProjectAccess analyzes cross-project IAM bindings for a set of projects
func (s *CrossProjectService) AnalyzeCrossProjectAccess(projectIDs []string) ([]CrossProjectBinding, error) {
	ctx := context.Background()

	crmService, err := s.getResourceManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	var crossProjectBindings []CrossProjectBinding

	// Build a map of project IDs for quick lookup
	projectMap := make(map[string]bool)
	for _, pid := range projectIDs {
		projectMap[pid] = true
	}

	// Analyze IAM policy of each project
	for _, targetProject := range projectIDs {
		policy, err := crmService.Projects.GetIamPolicy(targetProject, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			continue // Skip projects we can't access
		}

		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				sourceProject := extractProjectFromMember(member)

				// Check if this is cross-project access
				if sourceProject != "" && sourceProject != targetProject {
					// Check if source project is in our analysis scope
					isFromKnownProject := projectMap[sourceProject]

					cpBinding := CrossProjectBinding{
						SourceProject: sourceProject,
						TargetProject: targetProject,
						Principal:     member,
						PrincipalType: extractPrincipalType(member),
						Role:          binding.Role,
						RiskReasons:   []string{},
					}

					// Analyze risk level
					cpBinding.RiskLevel, cpBinding.RiskReasons = s.analyzeBindingRisk(binding.Role, member, isFromKnownProject)
					cpBinding.ExploitCommands = s.generateExploitCommands(cpBinding)

					crossProjectBindings = append(crossProjectBindings, cpBinding)
				}
			}
		}
	}

	return crossProjectBindings, nil
}

// GetCrossProjectServiceAccounts finds service accounts with cross-project access
func (s *CrossProjectService) GetCrossProjectServiceAccounts(projectIDs []string) ([]CrossProjectServiceAccount, error) {
	ctx := context.Background()

	iamService, err := s.getIAMService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "iam.googleapis.com")
	}

	crmService, err := s.getResourceManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	var crossProjectSAs []CrossProjectServiceAccount

	// Build a map of all service accounts by email -> project
	saProjectMap := make(map[string]string)
	allSAs := make(map[string]*CrossProjectServiceAccount)

	// List all service accounts in each project
	for _, projectID := range projectIDs {
		req := iamService.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", projectID))
		err := req.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
			for _, sa := range page.Accounts {
				saProjectMap[sa.Email] = projectID
				allSAs[sa.Email] = &CrossProjectServiceAccount{
					Email:        sa.Email,
					ProjectID:    projectID,
					DisplayName:  sa.DisplayName,
					UniqueID:     sa.UniqueId,
					TargetAccess: []string{},
				}
			}
			return nil
		})
		if err != nil {
			continue // Skip on error
		}
	}

	// Now check each project's IAM policy for service accounts from other projects
	for _, targetProject := range projectIDs {
		policy, err := crmService.Projects.GetIamPolicy(targetProject, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if strings.HasPrefix(member, "serviceAccount:") {
					email := strings.TrimPrefix(member, "serviceAccount:")
					sourceProject := saProjectMap[email]

					// Cross-project access
					if sourceProject != "" && sourceProject != targetProject {
						if sa, exists := allSAs[email]; exists {
							accessDesc := fmt.Sprintf("%s: %s", targetProject, binding.Role)
							sa.TargetAccess = append(sa.TargetAccess, accessDesc)
						}
					}
				}
			}
		}
	}

	// Collect SAs with cross-project access
	for _, sa := range allSAs {
		if len(sa.TargetAccess) > 0 {
			crossProjectSAs = append(crossProjectSAs, *sa)
		}
	}

	return crossProjectSAs, nil
}

// FindLateralMovementPaths identifies lateral movement paths between projects
func (s *CrossProjectService) FindLateralMovementPaths(projectIDs []string) ([]LateralMovementPath, error) {
	ctx := context.Background()

	crmService, err := s.getResourceManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	var paths []LateralMovementPath

	// Analyze each project pair
	for _, sourceProject := range projectIDs {
		for _, targetProject := range projectIDs {
			if sourceProject == targetProject {
				continue
			}

			// Get target project IAM policy
			policy, err := crmService.Projects.GetIamPolicy(targetProject, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
			if err != nil {
				continue
			}

			// Find principals from source project that have access to target
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					memberProject := extractProjectFromMember(member)
					if memberProject == sourceProject {
						path := LateralMovementPath{
							SourceProject:   sourceProject,
							SourcePrincipal: member,
							TargetProject:   targetProject,
							AccessMethod:    "Direct IAM Role",
							TargetRoles:     []string{binding.Role},
							PrivilegeLevel:  categorizePrivilegeLevel(binding.Role),
						}
						path.ExploitCommands = s.generateLateralMovementCommands(path)
						paths = append(paths, path)
					}
				}
			}
		}
	}

	return paths, nil
}

// analyzeBindingRisk determines the risk level of a cross-project binding
func (s *CrossProjectService) analyzeBindingRisk(role, member string, isFromKnownProject bool) (string, []string) {
	var reasons []string
	score := 0

	// High-privilege roles
	highPrivRoles := map[string]bool{
		"roles/owner":                        true,
		"roles/editor":                       true,
		"roles/iam.serviceAccountTokenCreator": true,
		"roles/iam.serviceAccountKeyAdmin":   true,
		"roles/iam.securityAdmin":            true,
		"roles/compute.admin":                true,
		"roles/storage.admin":                true,
		"roles/secretmanager.admin":          true,
	}

	if highPrivRoles[role] {
		reasons = append(reasons, fmt.Sprintf("High-privilege role: %s", role))
		score += 3
	}

	// Admin/editor roles are always concerning
	if strings.Contains(role, "admin") || strings.Contains(role, "Admin") {
		reasons = append(reasons, "Role contains 'admin' permissions")
		score += 2
	}

	if strings.Contains(role, "editor") || strings.Contains(role, "Editor") {
		reasons = append(reasons, "Role contains 'editor' permissions")
		score += 2
	}

	// Service account cross-project is higher risk than user
	if strings.HasPrefix(member, "serviceAccount:") {
		reasons = append(reasons, "Service account has cross-project access (can be automated)")
		score += 1
	}

	// Unknown source project is concerning
	if !isFromKnownProject {
		reasons = append(reasons, "Access from project outside analyzed scope")
		score += 1
	}

	if score >= 4 {
		return "CRITICAL", reasons
	} else if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

// generateExploitCommands generates exploitation commands for a cross-project binding
func (s *CrossProjectService) generateExploitCommands(binding CrossProjectBinding) []string {
	var commands []string

	if binding.PrincipalType == "serviceAccount" {
		email := strings.TrimPrefix(binding.Principal, "serviceAccount:")

		commands = append(commands,
			fmt.Sprintf("# Impersonate SA from %s to access %s:", binding.SourceProject, binding.TargetProject),
			fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", email),
			fmt.Sprintf("# Then use token to access target project:"),
			fmt.Sprintf("gcloud projects describe %s --impersonate-service-account=%s", binding.TargetProject, email),
		)
	}

	// Role-specific exploitation
	if strings.Contains(binding.Role, "storage") {
		commands = append(commands,
			fmt.Sprintf("# List buckets in target project:"),
			fmt.Sprintf("gsutil ls -p %s", binding.TargetProject),
		)
	}

	if strings.Contains(binding.Role, "compute") {
		commands = append(commands,
			fmt.Sprintf("# List instances in target project:"),
			fmt.Sprintf("gcloud compute instances list --project=%s", binding.TargetProject),
		)
	}

	if strings.Contains(binding.Role, "secretmanager") {
		commands = append(commands,
			fmt.Sprintf("# List secrets in target project:"),
			fmt.Sprintf("gcloud secrets list --project=%s", binding.TargetProject),
		)
	}

	return commands
}

// generateLateralMovementCommands generates commands for lateral movement
func (s *CrossProjectService) generateLateralMovementCommands(path LateralMovementPath) []string {
	var commands []string

	if strings.HasPrefix(path.SourcePrincipal, "serviceAccount:") {
		email := strings.TrimPrefix(path.SourcePrincipal, "serviceAccount:")

		commands = append(commands,
			fmt.Sprintf("# Lateral movement from %s to %s via SA impersonation:", path.SourceProject, path.TargetProject),
			fmt.Sprintf("# 1. Get access token for the cross-project SA:"),
			fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", email),
			fmt.Sprintf("# 2. Use the SA to access target project:"),
		)

		// Add role-specific commands
		for _, role := range path.TargetRoles {
			if strings.Contains(role, "owner") || strings.Contains(role, "editor") {
				commands = append(commands,
					fmt.Sprintf("# Full project access with %s:", role),
					fmt.Sprintf("gcloud projects describe %s --impersonate-service-account=%s", path.TargetProject, email),
				)
			}
		}
	}

	return commands
}

// extractProjectFromMember extracts the project ID from a member string
func extractProjectFromMember(member string) string {
	// serviceAccount:sa-name@project-id.iam.gserviceaccount.com
	if strings.HasPrefix(member, "serviceAccount:") {
		email := strings.TrimPrefix(member, "serviceAccount:")
		// Format: name@project-id.iam.gserviceaccount.com
		// or: project-id@project-id.iam.gserviceaccount.com
		if strings.Contains(email, ".iam.gserviceaccount.com") {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				domain := parts[1]
				projectPart := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
				return projectPart
			}
		}
		// App Engine default service accounts
		if strings.Contains(email, "@appspot.gserviceaccount.com") {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				return strings.TrimSuffix(parts[1], ".appspot.gserviceaccount.com")
			}
		}
		// Compute Engine default service accounts: project-number@project.iam.gserviceaccount.com
		if strings.Contains(email, "-compute@developer.gserviceaccount.com") {
			// Can't extract project ID from project number easily
			return ""
		}
	}
	return ""
}

// extractPrincipalType extracts the type of principal from a member string
func extractPrincipalType(member string) string {
	if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	}
	return "unknown"
}

// categorizePrivilegeLevel categorizes the privilege level of a role
func categorizePrivilegeLevel(role string) string {
	if strings.Contains(role, "owner") || strings.Contains(role, "Owner") {
		return "ADMIN"
	}
	if strings.Contains(role, "admin") || strings.Contains(role, "Admin") {
		return "ADMIN"
	}
	if strings.Contains(role, "editor") || strings.Contains(role, "Editor") {
		return "WRITE"
	}
	if strings.Contains(role, "writer") || strings.Contains(role, "Writer") {
		return "WRITE"
	}
	if strings.Contains(role, "creator") || strings.Contains(role, "Creator") {
		return "WRITE"
	}
	if strings.Contains(role, "viewer") || strings.Contains(role, "Viewer") {
		return "READ"
	}
	if strings.Contains(role, "reader") || strings.Contains(role, "Reader") {
		return "READ"
	}
	return "READ" // Default to READ for unknown
}

// FindCrossProjectLoggingSinks discovers logging sinks that export to other projects
func (s *CrossProjectService) FindCrossProjectLoggingSinks(projectIDs []string) ([]CrossProjectLoggingSink, error) {
	ctx := context.Background()

	loggingService, err := s.getLoggingService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "logging.googleapis.com")
	}

	// Build project lookup map
	projectMap := make(map[string]bool)
	for _, p := range projectIDs {
		projectMap[p] = true
	}

	var crossProjectSinks []CrossProjectLoggingSink

	for _, sourceProject := range projectIDs {
		parent := fmt.Sprintf("projects/%s", sourceProject)
		req := loggingService.Projects.Sinks.List(parent)
		err := req.Pages(ctx, func(page *logging.ListSinksResponse) error {
			for _, sink := range page.Sinks {
				// Parse destination to extract target project
				destType, targetProject := parseLoggingDestination(sink.Destination)

				// Check if this is a cross-project sink
				if targetProject != "" && targetProject != sourceProject {
					riskLevel, riskReasons := analyzeLoggingSinkRisk(sink, targetProject, projectMap)

					crossSink := CrossProjectLoggingSink{
						SourceProject:   sourceProject,
						SinkName:        sink.Name,
						Destination:     sink.Destination,
						DestinationType: destType,
						TargetProject:   targetProject,
						Filter:          sink.Filter,
						RiskLevel:       riskLevel,
						RiskReasons:     riskReasons,
					}
					crossProjectSinks = append(crossProjectSinks, crossSink)
				}
			}
			return nil
		})
		if err != nil {
			// Continue with other projects
			continue
		}
	}

	return crossProjectSinks, nil
}

// parseLoggingDestination parses a logging sink destination to extract type and project
func parseLoggingDestination(destination string) (destType, projectID string) {
	// Destination formats:
	// storage.googleapis.com/BUCKET_NAME
	// bigquery.googleapis.com/projects/PROJECT_ID/datasets/DATASET_ID
	// pubsub.googleapis.com/projects/PROJECT_ID/topics/TOPIC_ID
	// logging.googleapis.com/projects/PROJECT_ID/locations/LOCATION/buckets/BUCKET_ID

	if strings.HasPrefix(destination, "storage.googleapis.com/") {
		// GCS bucket - need to look up bucket to get project (not easily extractable)
		return "storage", ""
	}

	if strings.HasPrefix(destination, "bigquery.googleapis.com/") {
		destType = "bigquery"
		// Format: bigquery.googleapis.com/projects/PROJECT_ID/datasets/DATASET_ID
		parts := strings.Split(destination, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return destType, parts[i+1]
			}
		}
	}

	if strings.HasPrefix(destination, "pubsub.googleapis.com/") {
		destType = "pubsub"
		// Format: pubsub.googleapis.com/projects/PROJECT_ID/topics/TOPIC_ID
		parts := strings.Split(destination, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return destType, parts[i+1]
			}
		}
	}

	if strings.HasPrefix(destination, "logging.googleapis.com/") {
		destType = "logging"
		// Format: logging.googleapis.com/projects/PROJECT_ID/locations/LOCATION/buckets/BUCKET_ID
		parts := strings.Split(destination, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return destType, parts[i+1]
			}
		}
	}

	return "unknown", ""
}

// analyzeLoggingSinkRisk analyzes the risk level of a cross-project logging sink
func analyzeLoggingSinkRisk(sink *logging.LogSink, targetProject string, knownProjects map[string]bool) (string, []string) {
	var reasons []string
	score := 0

	// External project is higher risk
	if !knownProjects[targetProject] {
		reasons = append(reasons, "Logs exported to project outside analyzed scope")
		score += 2
	}

	// Check if filter is broad (empty = all logs)
	if sink.Filter == "" {
		reasons = append(reasons, "No filter - ALL logs exported")
		score += 2
	}

	// Check for sensitive log types in filter
	sensitiveLogTypes := []string{"data_access", "admin_activity", "cloudaudit"}
	for _, lt := range sensitiveLogTypes {
		if strings.Contains(sink.Filter, lt) {
			reasons = append(reasons, fmt.Sprintf("Exports sensitive logs: %s", lt))
			score += 1
		}
	}

	// Check if sink has service account (writerIdentity)
	if sink.WriterIdentity != "" {
		reasons = append(reasons, fmt.Sprintf("Service account: %s", sink.WriterIdentity))
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	}
	return "LOW", reasons
}

// FindCrossProjectPubSubExports discovers Pub/Sub subscriptions that export to other projects
func (s *CrossProjectService) FindCrossProjectPubSubExports(projectIDs []string) ([]CrossProjectPubSubExport, error) {
	ctx := context.Background()

	pubsubService, err := s.getPubSubService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "pubsub.googleapis.com")
	}

	// Build project lookup map
	projectMap := make(map[string]bool)
	for _, p := range projectIDs {
		projectMap[p] = true
	}

	var crossProjectExports []CrossProjectPubSubExport

	for _, sourceProject := range projectIDs {
		// List all subscriptions in project
		parent := fmt.Sprintf("projects/%s", sourceProject)
		req := pubsubService.Projects.Subscriptions.List(parent)
		err := req.Pages(ctx, func(page *pubsub.ListSubscriptionsResponse) error {
			for _, sub := range page.Subscriptions {
				// Extract subscription name and topic project
				subName := extractResourceNameFromPath(sub.Name)
				topicProject := extractProjectFromPath(sub.Topic)

				var exportType, exportDest, targetProject string

				// Check for BigQuery export
				if sub.BigqueryConfig != nil && sub.BigqueryConfig.Table != "" {
					exportType = "bigquery"
					exportDest = sub.BigqueryConfig.Table
					// Extract project from table: PROJECT:DATASET.TABLE
					if parts := strings.Split(sub.BigqueryConfig.Table, ":"); len(parts) > 0 {
						targetProject = parts[0]
					}
				}

				// Check for Cloud Storage export
				if sub.CloudStorageConfig != nil && sub.CloudStorageConfig.Bucket != "" {
					exportType = "cloudstorage"
					exportDest = sub.CloudStorageConfig.Bucket
					// Bucket project not easily extractable without additional API call
					targetProject = ""
				}

				// Check for push endpoint
				if sub.PushConfig != nil && sub.PushConfig.PushEndpoint != "" {
					exportType = "push"
					exportDest = sub.PushConfig.PushEndpoint
					// External push endpoints can't be mapped to a project
					targetProject = "external"
				}

				// Check if subscription is to a topic in another project
				if topicProject != "" && topicProject != sourceProject {
					// This is a cross-project topic subscription
					riskLevel, riskReasons := analyzePubSubExportRisk(sub, targetProject, projectMap, topicProject, sourceProject)
					export := CrossProjectPubSubExport{
						SourceProject:    sourceProject,
						TopicProject:     topicProject,
						TopicName:        extractResourceNameFromPath(sub.Topic),
						SubscriptionName: subName,
						ExportType:       "cross-project-topic",
						ExportDest:       sub.Topic,
						TargetProject:    topicProject,
						RiskLevel:        riskLevel,
						RiskReasons:      riskReasons,
					}
					crossProjectExports = append(crossProjectExports, export)
				}

				// If exporting to another project via BQ/GCS
				if targetProject != "" && targetProject != sourceProject && targetProject != "external" {
					riskLevel, riskReasons := analyzePubSubExportRisk(sub, targetProject, projectMap, topicProject, sourceProject)
					export := CrossProjectPubSubExport{
						SourceProject:    sourceProject,
						TopicProject:     topicProject,
						TopicName:        extractResourceNameFromPath(sub.Topic),
						SubscriptionName: subName,
						ExportType:       exportType,
						ExportDest:       exportDest,
						TargetProject:    targetProject,
						RiskLevel:        riskLevel,
						RiskReasons:      riskReasons,
					}
					crossProjectExports = append(crossProjectExports, export)
				}
			}
			return nil
		})
		if err != nil {
			// Continue with other projects
			continue
		}
	}

	return crossProjectExports, nil
}

// extractResourceNameFromPath extracts the resource name from a full path
func extractResourceNameFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}

// extractProjectFromPath extracts the project ID from a resource path
func extractProjectFromPath(path string) string {
	// Format: projects/PROJECT_ID/...
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// analyzePubSubExportRisk analyzes the risk level of a cross-project Pub/Sub export
func analyzePubSubExportRisk(sub *pubsub.Subscription, targetProject string, knownProjects map[string]bool, topicProject, sourceProject string) (string, []string) {
	var reasons []string
	score := 0

	// External target project is higher risk
	if targetProject != "" && !knownProjects[targetProject] {
		reasons = append(reasons, "Data exported to project outside analyzed scope")
		score += 2
	}

	// Cross-project topic subscription
	if topicProject != "" && topicProject != sourceProject {
		reasons = append(reasons, fmt.Sprintf("Subscription to topic in project %s", topicProject))
		score += 1
	}

	// Push to external endpoint
	if sub.PushConfig != nil && sub.PushConfig.PushEndpoint != "" {
		endpoint := sub.PushConfig.PushEndpoint
		reasons = append(reasons, fmt.Sprintf("Push endpoint: %s", endpoint))
		// External endpoints are high risk
		if !strings.Contains(endpoint, ".run.app") && !strings.Contains(endpoint, ".cloudfunctions.net") {
			reasons = append(reasons, "Push to external (non-GCP) endpoint")
			score += 2
		}
	}

	// BigQuery export
	if sub.BigqueryConfig != nil {
		reasons = append(reasons, fmt.Sprintf("BigQuery export: %s", sub.BigqueryConfig.Table))
		score += 1
	}

	// Cloud Storage export
	if sub.CloudStorageConfig != nil {
		reasons = append(reasons, fmt.Sprintf("Cloud Storage export: %s", sub.CloudStorageConfig.Bucket))
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	}
	return "LOW", reasons
}
