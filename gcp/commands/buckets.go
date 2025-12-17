package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudStorageService "github.com/BishopFox/cloudfox/gcp/services/cloudStorageService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPBucketsCommand = &cobra.Command{
	Use:     globals.GCP_BUCKETS_MODULE_NAME,
	Aliases: []string{"storage", "gcs"},
	Short:   "Enumerate GCP Cloud Storage buckets with security configuration",
	Long: `Enumerate GCP Cloud Storage buckets across projects with security-relevant details.

Features:
- Lists all buckets accessible to the authenticated user
- Shows security configuration (public access prevention, uniform access, versioning)
- Enumerates IAM policies and identifies public buckets
- Shows encryption type (Google-managed vs CMEK)
- Shows retention and soft delete policies
- Generates gcloud commands for further enumeration
- Generates exploitation commands for data access

Security Columns:
- Public: Whether the bucket has allUsers or allAuthenticatedUsers access
- PublicAccessPrevention: "enforced" prevents public access at org/project level
- UniformAccess: true means IAM-only (no ACLs), recommended for security
- Versioning: Object versioning enabled (helps with recovery/compliance)
- Logging: Access logging enabled (audit trail)
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Retention: Data retention policy (compliance/immutability)`,
	Run: runGCPBucketsCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type BucketsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Buckets []CloudStorageService.BucketInfo
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type BucketsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BucketsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BucketsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPBucketsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_BUCKETS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &BucketsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Buckets:       []CloudStorageService.BucketInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *BucketsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_BUCKETS_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Buckets) == 0 {
		logger.InfoM("No buckets found", globals.GCP_BUCKETS_MODULE_NAME)
		return
	}

	// Count public buckets for summary
	publicCount := 0
	for _, bucket := range m.Buckets {
		if bucket.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d bucket(s), %d PUBLIC", len(m.Buckets), publicCount), globals.GCP_BUCKETS_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d bucket(s)", len(m.Buckets)), globals.GCP_BUCKETS_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *BucketsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating buckets in project: %s", projectID), globals.GCP_BUCKETS_MODULE_NAME)
	}

	// Create service and fetch buckets
	cs := CloudStorageService.New()
	buckets, err := cs.Buckets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating buckets in project %s: %v", projectID, err), globals.GCP_BUCKETS_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Buckets = append(m.Buckets, buckets...)

	// Generate loot for each bucket
	for _, bucket := range buckets {
		m.addBucketToLoot(bucket)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d bucket(s) in project %s", len(buckets), projectID), globals.GCP_BUCKETS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *BucketsModule) initializeLootFiles() {
	m.LootMap["buckets-gcloud-commands"] = &internal.LootFile{
		Name:     "buckets-gcloud-commands",
		Contents: "# GCP Cloud Storage Bucket Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-gsutil-commands"] = &internal.LootFile{
		Name:     "buckets-gsutil-commands",
		Contents: "# GCP gsutil Commands for Data Access\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-exploitation"] = &internal.LootFile{
		Name:     "buckets-exploitation",
		Contents: "# GCP Bucket Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["buckets-public"] = &internal.LootFile{
		Name:     "buckets-public",
		Contents: "# PUBLIC GCP Buckets\n# Generated by CloudFox\n# These buckets have allUsers or allAuthenticatedUsers access!\n\n",
	}
	m.LootMap["buckets-iam-bindings"] = &internal.LootFile{
		Name:     "buckets-iam-bindings",
		Contents: "# GCP Bucket IAM Bindings\n# Generated by CloudFox\n\n",
	}
}

func (m *BucketsModule) addBucketToLoot(bucket CloudStorageService.BucketInfo) {
	// gcloud commands for enumeration
	m.LootMap["buckets-gcloud-commands"].Contents += fmt.Sprintf(
		"# Bucket: %s (Project: %s, Location: %s)\n"+
			"gcloud storage buckets describe gs://%s --project=%s\n"+
			"gcloud storage buckets get-iam-policy gs://%s --project=%s\n\n",
		bucket.Name, bucket.ProjectID, bucket.Location,
		bucket.Name, bucket.ProjectID,
		bucket.Name, bucket.ProjectID,
	)

	// gsutil commands for data access
	m.LootMap["buckets-gsutil-commands"].Contents += fmt.Sprintf(
		"# Bucket: %s\n"+
			"gsutil ls gs://%s/\n"+
			"gsutil ls -L gs://%s/\n"+
			"gsutil du -s gs://%s/\n\n",
		bucket.Name,
		bucket.Name,
		bucket.Name,
		bucket.Name,
	)

	// Exploitation commands
	m.LootMap["buckets-exploitation"].Contents += fmt.Sprintf(
		"# Bucket: %s\n"+
			"# List all objects recursively:\n"+
			"gsutil ls -r gs://%s/**\n"+
			"# Download all contents:\n"+
			"gsutil -m cp -r gs://%s/ ./loot/%s/\n"+
			"# Check for public access:\n"+
			"curl -s https://storage.googleapis.com/%s/ | head -20\n\n",
		bucket.Name,
		bucket.Name,
		bucket.Name, bucket.Name,
		bucket.Name,
	)

	// Public buckets
	if bucket.IsPublic {
		m.LootMap["buckets-public"].Contents += fmt.Sprintf(
			"# BUCKET: %s\n"+
				"# Project: %s\n"+
				"# Public Access: %s\n"+
				"# Public Access Prevention: %s\n"+
				"# Direct URL: https://storage.googleapis.com/%s/\n"+
				"# Console URL: https://console.cloud.google.com/storage/browser/%s\n"+
				"curl -s https://storage.googleapis.com/%s/ | head -50\n"+
				"gsutil ls gs://%s/\n\n",
			bucket.Name,
			bucket.ProjectID,
			bucket.PublicAccess,
			bucket.PublicAccessPrevention,
			bucket.Name,
			bucket.Name,
			bucket.Name,
			bucket.Name,
		)
	}

	// IAM bindings
	if len(bucket.IAMBindings) > 0 {
		m.LootMap["buckets-iam-bindings"].Contents += fmt.Sprintf(
			"# Bucket: %s (Project: %s)\n",
			bucket.Name, bucket.ProjectID,
		)
		for _, binding := range bucket.IAMBindings {
			m.LootMap["buckets-iam-bindings"].Contents += fmt.Sprintf(
				"# Role: %s\n#   Members: %s\n",
				binding.Role,
				strings.Join(binding.Members, ", "),
			)
		}
		m.LootMap["buckets-iam-bindings"].Contents += "\n"
	}
}

// ------------------------------
// Helper functions
// ------------------------------
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func boolToCheckMark(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}

// getMemberType extracts the member type from a GCP IAM member string
// Member formats: user:email, serviceAccount:email, group:email, domain:domain, allUsers, allAuthenticatedUsers
func getMemberType(member string) string {
	switch {
	case member == "allUsers":
		return "PUBLIC"
	case member == "allAuthenticatedUsers":
		return "ALL_AUTHENTICATED"
	case strings.HasPrefix(member, "user:"):
		return "User"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "ServiceAccount"
	case strings.HasPrefix(member, "group:"):
		return "Group"
	case strings.HasPrefix(member, "domain:"):
		return "Domain"
	case strings.HasPrefix(member, "projectOwner:"):
		return "ProjectOwner"
	case strings.HasPrefix(member, "projectEditor:"):
		return "ProjectEditor"
	case strings.HasPrefix(member, "projectViewer:"):
		return "ProjectViewer"
	case strings.HasPrefix(member, "deleted:"):
		return "Deleted"
	default:
		return "Unknown"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *BucketsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main table with security-relevant columns
	header := []string{
		"Project ID",
		"Name",
		"Location",
		"Public",
		"PublicAccessPrevention",
		"UniformAccess",
		"Versioning",
		"Logging",
		"Encryption",
		"Retention",
	}

	var body [][]string
	for _, bucket := range m.Buckets {
		// Format retention info
		retentionInfo := "-"
		if bucket.RetentionPolicyEnabled {
			if bucket.RetentionPolicyLocked {
				retentionInfo = fmt.Sprintf("%dd (LOCKED)", bucket.RetentionPeriodDays)
			} else {
				retentionInfo = fmt.Sprintf("%dd", bucket.RetentionPeriodDays)
			}
		}

		// Format public access - highlight if public
		publicDisplay := bucket.PublicAccess
		if bucket.IsPublic {
			publicDisplay = "PUBLIC: " + bucket.PublicAccess
		}

		body = append(body, []string{
			bucket.ProjectID,
			bucket.Name,
			bucket.Location,
			publicDisplay,
			bucket.PublicAccessPrevention,
			boolToCheckMark(bucket.UniformBucketLevelAccess),
			boolToCheckMark(bucket.VersioningEnabled),
			boolToCheckMark(bucket.LoggingEnabled),
			bucket.EncryptionType,
			retentionInfo,
		})
	}

	// Detailed IAM table - one row per member for granular view
	iamHeader := []string{
		"Bucket",
		"Project ID",
		"Role",
		"Member Type",
		"Member",
	}

	var iamBody [][]string
	for _, bucket := range m.Buckets {
		for _, binding := range bucket.IAMBindings {
			for _, member := range binding.Members {
				memberType := getMemberType(member)
				iamBody = append(iamBody, []string{
					bucket.Name,
					bucket.ProjectID,
					binding.Role,
					memberType,
					member,
				})
			}
		}
	}

	// Public buckets table (if any)
	publicHeader := []string{
		"Bucket",
		"Project ID",
		"Public Access",
		"Public Access Prevention",
		"URL",
	}

	var publicBody [][]string
	for _, bucket := range m.Buckets {
		if bucket.IsPublic {
			publicBody = append(publicBody, []string{
				bucket.Name,
				bucket.ProjectID,
				bucket.PublicAccess,
				bucket.PublicAccessPrevention,
				fmt.Sprintf("https://storage.googleapis.com/%s/", bucket.Name),
			})
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{
		{
			Name:   globals.GCP_BUCKETS_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	// Add IAM table if there are bindings
	if len(iamBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "buckets-iam",
			Header: iamHeader,
			Body:   iamBody,
		})
	}

	// Add public buckets table if any
	if len(publicBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "buckets-public",
			Header: publicHeader,
			Body:   publicBody,
		})
	}

	output := BucketsOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",           // scopeType
		m.ProjectIDs,        // scopeIdentifiers
		m.ProjectIDs,        // scopeNames (same as IDs for GCP projects)
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_BUCKETS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
