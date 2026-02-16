package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	bigqueryservice "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
	loggingservice "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	orgpolicyservice "github.com/BishopFox/cloudfox/gcp/services/orgpolicyService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	vpcscservice "github.com/BishopFox/cloudfox/gcp/services/vpcscService"
	"github.com/BishopFox/cloudfox/gcp/shared"
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
	Long: `Identify data exfiltration vectors and paths in GCP environments.

This module identifies both ACTUAL misconfigurations and POTENTIAL exfiltration vectors
using FoxMapper graph data for permission analysis.

Actual Findings (specific resources):
- Public snapshots and images (actual IAM policy check)
- Public buckets (actual IAM policy check)
- Cross-project logging sinks (actual sink enumeration)
- Pub/Sub push subscriptions to external endpoints
- BigQuery datasets with public IAM bindings
- Storage Transfer Service jobs to external destinations

Permission-Based Vectors (from FoxMapper graph):
- Storage objects read/list permissions
- BigQuery data access and export permissions
- Cloud SQL export and connect permissions
- Secret Manager access permissions
- KMS decrypt permissions
- Logging read permissions

Prerequisites:
- Run 'foxmapper gcp graph create' for permission-based analysis

Security Controls Checked:
- VPC Service Controls (VPC-SC) perimeter protection
- Organization policies for data protection

The loot file includes commands to perform each type of exfiltration.`,
	Run: runGCPDataExfiltrationCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

// ExfiltrationPath represents an actual misconfiguration or finding
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
	ProjectID                   string
	PublicAccessPrevention      bool // storage.publicAccessPrevention enforced
	DomainRestriction           bool // iam.allowedPolicyMemberDomains enforced
	SQLPublicIPRestriction      bool // sql.restrictPublicIp enforced
	ResourceLocationRestriction bool // gcp.resourceLocations enforced
	CloudFunctionsVPCConnector  bool // cloudfunctions.requireVPCConnector enforced
	CloudRunIngressRestriction  bool // run.allowedIngress enforced
	CloudRunRequireIAMInvoker   bool // run.allowedIngress = internal or internal-and-cloud-load-balancing
	DisableBQOmniAWS            bool // bigquery.disableBQOmniAWS enforced
	DisableBQOmniAzure          bool // bigquery.disableBQOmniAzure enforced
	MissingProtections          []string
}

// ------------------------------
// Module Struct
// ------------------------------
type DataExfiltrationModule struct {
	gcpinternal.BaseGCPModule

	ProjectExfiltrationPaths map[string][]ExfiltrationPath                // projectID -> paths
	ProjectPublicExports     map[string][]PublicExport                    // projectID -> exports
	FoxMapperFindings        []foxmapperservice.DataExfilFinding          // FoxMapper-based findings
	LootMap                  map[string]map[string]*internal.LootFile     // projectID -> loot files
	mu                       sync.Mutex
	vpcscProtectedProj       map[string]bool                 // Projects protected by VPC-SC
	orgPolicyProtection      map[string]*OrgPolicyProtection // Org policy protections per project
	FoxMapperCache           *gcpinternal.FoxMapperCache     // FoxMapper cache for unified data access
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
		BaseGCPModule:            gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectExfiltrationPaths: make(map[string][]ExfiltrationPath),
		ProjectPublicExports:     make(map[string][]PublicExport),
		FoxMapperFindings:        []foxmapperservice.DataExfilFinding{},
		LootMap:                  make(map[string]map[string]*internal.LootFile),
		vpcscProtectedProj:       make(map[string]bool),
		orgPolicyProtection:      make(map[string]*OrgPolicyProtection),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DataExfiltrationModule) getAllExfiltrationPaths() []ExfiltrationPath {
	var all []ExfiltrationPath
	for _, paths := range m.ProjectExfiltrationPaths {
		all = append(all, paths...)
	}
	return all
}

func (m *DataExfiltrationModule) getAllPublicExports() []PublicExport {
	var all []PublicExport
	for _, exports := range m.ProjectPublicExports {
		all = append(all, exports...)
	}
	return all
}

func (m *DataExfiltrationModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Identifying data exfiltration paths and potential vectors...", GCP_DATAEXFILTRATION_MODULE_NAME)

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

	// First, check VPC-SC protection status for all projects
	m.checkVPCSCProtection(ctx, logger)

	// Check organization policy protections for all projects
	m.checkOrgPolicyProtection(ctx, logger)

	// Process each project for actual misconfigurations
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_DATAEXFILTRATION_MODULE_NAME, m.processProject)

	// Analyze permission-based exfiltration using FoxMapper
	if m.FoxMapperCache != nil && m.FoxMapperCache.IsPopulated() {
		logger.InfoM("Analyzing permission-based exfiltration paths using FoxMapper...", GCP_DATAEXFILTRATION_MODULE_NAME)
		svc := m.FoxMapperCache.GetService()
		m.FoxMapperFindings = svc.AnalyzeDataExfil("")
		if len(m.FoxMapperFindings) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d permission-based exfiltration techniques with access", len(m.FoxMapperFindings)), GCP_DATAEXFILTRATION_MODULE_NAME)
		}
	} else {
		logger.InfoM("No FoxMapper data found - skipping permission-based analysis. Run 'foxmapper gcp graph create' for full analysis.", GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	allPaths := m.getAllExfiltrationPaths()

	// Check results
	hasResults := len(allPaths) > 0 || len(m.FoxMapperFindings) > 0

	if !hasResults {
		logger.InfoM("No data exfiltration paths found", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	if len(allPaths) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d actual misconfiguration(s)", len(allPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
	if len(m.FoxMapperFindings) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d permission-based exfiltration technique(s) with access", len(m.FoxMapperFindings)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// VPC-SC Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkVPCSCProtection(ctx context.Context, logger internal.Logger) {
	vpcsc := vpcscservice.New()

	if len(m.ProjectIDs) == 0 {
		return
	}

	policies, err := vpcsc.ListAccessPolicies("")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM("Could not check VPC-SC policies (may require org-level access)", GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	for _, policy := range policies {
		perimeters, err := vpcsc.ListServicePerimeters(policy.Name)
		if err != nil {
			continue
		}

		for _, perimeter := range perimeters {
			for _, resource := range perimeter.Resources {
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

		policies, err := orgSvc.ListProjectPolicies(projectID)
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not check org policies for %s: %v", projectID, err), GCP_DATAEXFILTRATION_MODULE_NAME)
			}
			m.mu.Lock()
			m.orgPolicyProtection[projectID] = protection
			m.mu.Unlock()
			continue
		}

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
			case "constraints/cloudfunctions.requireVPCConnector":
				if policy.Enforced {
					protection.CloudFunctionsVPCConnector = true
				}
			case "constraints/run.allowedIngress":
				if len(policy.AllowedValues) > 0 {
					for _, val := range policy.AllowedValues {
						if val == "internal" || val == "internal-and-cloud-load-balancing" {
							protection.CloudRunIngressRestriction = true
							break
						}
					}
				}
			case "constraints/bigquery.disableBQOmniAWS":
				if policy.Enforced {
					protection.DisableBQOmniAWS = true
				}
			case "constraints/bigquery.disableBQOmniAzure":
				if policy.Enforced {
					protection.DisableBQOmniAzure = true
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
		if !protection.CloudFunctionsVPCConnector {
			protection.MissingProtections = append(protection.MissingProtections, "cloudfunctions.requireVPCConnector not enforced")
		}
		if !protection.CloudRunIngressRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "run.allowedIngress not restricted")
		}
		if !protection.DisableBQOmniAWS {
			protection.MissingProtections = append(protection.MissingProtections, "bigquery.disableBQOmniAWS not enforced")
		}
		if !protection.DisableBQOmniAzure {
			protection.MissingProtections = append(protection.MissingProtections, "bigquery.disableBQOmniAzure not enforced")
		}

		m.mu.Lock()
		m.orgPolicyProtection[projectID] = protection
		m.mu.Unlock()
	}
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DataExfiltrationModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["data-exfiltration-commands"] = &internal.LootFile{
			Name:     "data-exfiltration-commands",
			Contents: "# Data Exfiltration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
		}
	}
}

func (m *DataExfiltrationModule) generatePlaybook() *internal.LootFile {
	var sb strings.Builder
	sb.WriteString("# GCP Data Exfiltration Playbook\n")
	sb.WriteString("# Generated by CloudFox\n\n")

	// Actual misconfigurations
	allPaths := m.getAllExfiltrationPaths()
	if len(allPaths) > 0 {
		sb.WriteString("## Actual Misconfigurations\n\n")
		for _, path := range allPaths {
			sb.WriteString(fmt.Sprintf("### %s: %s\n", path.PathType, path.ResourceName))
			sb.WriteString(fmt.Sprintf("- Project: %s\n", path.ProjectID))
			sb.WriteString(fmt.Sprintf("- Risk Level: %s\n", path.RiskLevel))
			sb.WriteString(fmt.Sprintf("- Description: %s\n", path.Description))
			sb.WriteString(fmt.Sprintf("- Destination: %s\n\n", path.Destination))
			if path.ExploitCommand != "" {
				sb.WriteString("```bash\n")
				sb.WriteString(path.ExploitCommand)
				sb.WriteString("\n```\n\n")
			}
		}
	}

	// Permission-based findings from FoxMapper
	if len(m.FoxMapperFindings) > 0 {
		sb.WriteString("## Permission-Based Exfiltration Techniques\n\n")
		for _, finding := range m.FoxMapperFindings {
			sb.WriteString(fmt.Sprintf("### %s (%s)\n", finding.Technique, finding.Service))
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
		Name:     "data-exfiltration-playbook",
		Contents: sb.String(),
	}
}

func (m *DataExfiltrationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing exfiltration paths in project: %s", projectID), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	// === ACTUAL MISCONFIGURATIONS ===

	// 1. Find public/shared snapshots
	m.findPublicSnapshots(ctx, projectID, logger)

	// 2. Find public/shared images
	m.findPublicImages(ctx, projectID, logger)

	// 3. Find public buckets
	m.findPublicBuckets(ctx, projectID, logger)

	// 4. Find cross-project logging sinks
	m.findCrossProjectLoggingSinks(ctx, projectID, logger)

	// 5. Find Pub/Sub push subscriptions to external endpoints
	m.findPubSubPushEndpoints(ctx, projectID, logger)

	// 6. Find Pub/Sub subscriptions exporting to external destinations
	m.findPubSubExportSubscriptions(ctx, projectID, logger)

	// 7. Find BigQuery datasets with public access
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
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						if member == "allUsers" {
							accessLevel = "allUsers"
							break
						}
						if accessLevel != "allUsers" {
							accessLevel = "allAuthenticatedUsers"
						}
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
				m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
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
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						if member == "allUsers" {
							accessLevel = "allUsers"
							break
						}
						if accessLevel != "allUsers" {
							accessLevel = "allAuthenticatedUsers"
						}
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
				m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
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
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		accessLevel := ""
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if shared.IsPublicPrincipal(member) {
					if member == "allUsers" {
						accessLevel = "allUsers"
						break
					}
					if accessLevel != "allUsers" {
						accessLevel = "allAuthenticatedUsers"
					}
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
			m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findCrossProjectLoggingSinks finds logging sinks that export to external destinations
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

		if sink.IsCrossProject {
			riskLevel := "HIGH"
			if sink.DestinationType == "pubsub" {
				riskLevel = "MEDIUM"
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
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
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
				Description:  "Subscription pushes messages to external endpoint",
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
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
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
		if sub.BigQueryTable != "" {
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
					m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
					m.addExfiltrationPathToLoot(projectID, path)
					m.mu.Unlock()
				}
			}
		}

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
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
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
			m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
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
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backup := instance.Settings.BackupConfiguration
			if backup.Enabled && backup.BinaryLogEnabled {
				path := ExfiltrationPath{
					PathType:     "Cloud SQL Export",
					ResourceName: instance.Name,
					ProjectID:    projectID,
					Description:  "Cloud SQL instance with binary logging enabled (enables CDC export)",
					Destination:  "External via mysqldump/pg_dump or CDC",
					RiskLevel:    "LOW",
					RiskReasons:  []string{"Binary logging enables change data capture", "Data can be exported if IAM allows"},
					ExploitCommand: fmt.Sprintf(
						"# Check export permissions\n"+
							"gcloud sql instances describe %s --project=%s\n"+
							"# Export if permitted\n"+
							"gcloud sql export sql %s gs://bucket/export.sql --database=mydb",
						instance.Name, projectID, instance.Name),
				}

				m.mu.Lock()
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
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

	filter := fmt.Sprintf(`{"projectId":"%s"}`, projectID)
	req := stsService.TransferJobs.List(filter)
	err = req.Pages(ctx, func(page *storagetransfer.ListTransferJobsResponse) error {
		for _, job := range page.TransferJobs {
			if job.Status != "ENABLED" {
				continue
			}

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
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
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
func (m *DataExfiltrationModule) addExfiltrationPathToLoot(projectID string, path ExfiltrationPath) {
	if path.ExploitCommand == "" {
		return
	}

	lootFile := m.LootMap[projectID]["data-exfiltration-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"#############################################\n"+
			"## [ACTUAL] %s: %s\n"+
			"## Project: %s\n"+
			"## Description: %s\n"+
			"## Destination: %s\n"+
			"#############################################\n",
		path.PathType,
		path.ResourceName,
		path.ProjectID,
		path.Description,
		path.Destination,
	)

	lootFile.Contents += fmt.Sprintf("%s\n\n", path.ExploitCommand)
}

// ------------------------------
// Output Generation
// ------------------------------

func (m *DataExfiltrationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *DataExfiltrationModule) getMisconfigHeader() []string {
	return []string{
		"Project",
		"Resource",
		"Type",
		"Destination",
		"Public",
		"Size",
	}
}

func (m *DataExfiltrationModule) getFoxMapperHeader() []string {
	return []string{
		"Technique",
		"Service",
		"Permission",
		"Description",
		"Principal Count",
	}
}

func (m *DataExfiltrationModule) pathsToTableBody(paths []ExfiltrationPath, exports []PublicExport) [][]string {
	var body [][]string

	publicResources := make(map[string]PublicExport)
	for _, e := range exports {
		key := fmt.Sprintf("%s:%s:%s", e.ProjectID, e.ResourceType, e.ResourceName)
		publicResources[key] = e
	}

	for _, p := range paths {
		key := fmt.Sprintf("%s:%s:%s", p.ProjectID, p.PathType, p.ResourceName)
		export, isPublic := publicResources[key]

		publicStatus := "No"
		size := "-"
		if isPublic {
			publicStatus = "Yes"
			size = export.Size
			delete(publicResources, key)
		}

		body = append(body, []string{
			m.GetProjectName(p.ProjectID),
			p.ResourceName,
			p.PathType,
			p.Destination,
			publicStatus,
			size,
		})
	}

	for _, e := range publicResources {
		body = append(body, []string{
			m.GetProjectName(e.ProjectID),
			e.ResourceName,
			e.ResourceType,
			"Public access: " + e.AccessLevel,
			"Yes",
			e.Size,
		})
	}

	return body
}

func (m *DataExfiltrationModule) foxMapperFindingsToTableBody() [][]string {
	var body [][]string
	for _, f := range m.FoxMapperFindings {
		body = append(body, []string{
			f.Technique,
			f.Service,
			f.Permission,
			f.Description,
			fmt.Sprintf("%d", len(f.Principals)),
		})
	}
	return body
}

func (m *DataExfiltrationModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	paths := m.ProjectExfiltrationPaths[projectID]
	exports := m.ProjectPublicExports[projectID]

	if len(paths) > 0 || len(exports) > 0 {
		body := m.pathsToTableBody(paths, exports)
		if len(body) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "data-exfiltration-misconfigurations",
				Header: m.getMisconfigHeader(),
				Body:   body,
			})
		}
	}

	return tableFiles
}

func (m *DataExfiltrationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectExfiltrationPaths {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectPublicExports {
		projectIDs[projectID] = true
	}

	playbook := m.generatePlaybook()
	playbookAdded := false

	for projectID := range projectIDs {
		m.initializeLootForProject(projectID)

		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization!\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		if playbook != nil && playbook.Contents != "" && !playbookAdded {
			lootFiles = append(lootFiles, *playbook)
			playbookAdded = true
		}

		outputData.ProjectLevelData[projectID] = DataExfiltrationOutput{Table: tableFiles, Loot: lootFiles}
	}

	// Add FoxMapper findings table at first project level if exists
	if len(m.FoxMapperFindings) > 0 && len(m.ProjectIDs) > 0 {
		firstProject := m.ProjectIDs[0]
		if existing, ok := outputData.ProjectLevelData[firstProject]; ok {
			existingOutput := existing.(DataExfiltrationOutput)
			existingOutput.Table = append(existingOutput.Table, internal.TableFile{
				Name:   "data-exfiltration-permissions",
				Header: m.getFoxMapperHeader(),
				Body:   m.foxMapperFindingsToTableBody(),
			})
			outputData.ProjectLevelData[firstProject] = existingOutput
		}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
}

func (m *DataExfiltrationModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allPaths := m.getAllExfiltrationPaths()
	allExports := m.getAllPublicExports()

	for _, projectID := range m.ProjectIDs {
		m.initializeLootForProject(projectID)
	}

	tables := []internal.TableFile{}

	misconfigBody := m.pathsToTableBody(allPaths, allExports)
	if len(misconfigBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-misconfigurations",
			Header: m.getMisconfigHeader(),
			Body:   misconfigBody,
		})
	}

	if len(m.FoxMapperFindings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-permissions",
			Header: m.getFoxMapperHeader(),
			Body:   m.foxMapperFindingsToTableBody(),
		})
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization!\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	playbook := m.generatePlaybook()
	if playbook != nil && playbook.Contents != "" {
		lootFiles = append(lootFiles, *playbook)
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
