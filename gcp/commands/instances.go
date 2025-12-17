package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPInstancesCommand = &cobra.Command{
	Use:     globals.GCP_INSTANCES_MODULE_NAME,
	Aliases: []string{"vms", "compute"},
	Short:   "Enumerate GCP Compute Engine instances with security configuration",
	Long: `Enumerate GCP Compute Engine instances across projects with security-relevant details.

Features:
- Lists all instances with network and security configuration
- Shows attached service accounts and their scopes
- Identifies instances with default service accounts or broad scopes
- Shows Shielded VM, Secure Boot, and Confidential VM status
- Shows OS Login and serial port configuration
- Shows disk encryption type (Google-managed vs CMEK/CSEK)
- Generates gcloud commands for instance access
- Generates exploitation commands (SSH, serial console, metadata)

Security Columns:
- ExternalIP: Instances with external IPs are internet-accessible
- DefaultSA: Uses default compute service account (security risk)
- BroadScopes: Has cloud-platform or other broad OAuth scopes
- CanIPForward: Can forward packets (potential for lateral movement)
- OSLogin: OS Login enabled (recommended for access control)
- SerialPort: Serial port access enabled (security risk if exposed)
- ShieldedVM: Shielded VM features enabled
- SecureBoot: Secure Boot enabled (prevents rootkits)
- Encryption: Boot disk encryption type`,
	Run: runGCPInstancesCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type InstancesModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Instances []ComputeEngineService.ComputeEngineInfo
	LootMap   map[string]*internal.LootFile
	mu        sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type InstancesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o InstancesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o InstancesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPInstancesCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_INSTANCES_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &InstancesModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Instances:     []ComputeEngineService.ComputeEngineInfo{},
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
func (m *InstancesModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_INSTANCES_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Instances) == 0 {
		logger.InfoM("No instances found", globals.GCP_INSTANCES_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d instance(s)", len(m.Instances)), globals.GCP_INSTANCES_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *InstancesModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating instances in project: %s", projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}

	// Create service and fetch instances
	ces := ComputeEngineService.New()
	instances, err := ces.Instances(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating instances in project %s: %v", projectID, err), globals.GCP_INSTANCES_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Instances = append(m.Instances, instances...)

	// Generate loot for each instance
	for _, instance := range instances {
		m.addInstanceToLoot(instance)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s) in project %s", len(instances), projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *InstancesModule) initializeLootFiles() {
	m.LootMap["instances-gcloud-commands"] = &internal.LootFile{
		Name:     "instances-gcloud-commands",
		Contents: "# GCP Compute Engine Instance Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["instances-ssh-commands"] = &internal.LootFile{
		Name:     "instances-ssh-commands",
		Contents: "# GCP Instance SSH Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["instances-exploitation"] = &internal.LootFile{
		Name:     "instances-exploitation",
		Contents: "# GCP Instance Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["instances-metadata"] = &internal.LootFile{
		Name:     "instances-metadata",
		Contents: "# GCP Instance Metadata Access Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *InstancesModule) addInstanceToLoot(instance ComputeEngineService.ComputeEngineInfo) {
	// Build service account string
	var saEmails []string
	for _, sa := range instance.ServiceAccounts {
		saEmails = append(saEmails, sa.Email)
	}
	saString := strings.Join(saEmails, ", ")

	// Build security flags string
	var securityFlags []string
	if instance.HasDefaultSA {
		securityFlags = append(securityFlags, "DEFAULT_SA")
	}
	if instance.HasCloudScopes {
		securityFlags = append(securityFlags, "BROAD_SCOPES")
	}
	if instance.ExternalIP != "" {
		securityFlags = append(securityFlags, "EXTERNAL_IP")
	}
	if instance.SerialPortEnabled {
		securityFlags = append(securityFlags, "SERIAL_PORT")
	}
	if !instance.OSLoginEnabled {
		securityFlags = append(securityFlags, "NO_OSLOGIN")
	}
	securityString := strings.Join(securityFlags, ", ")
	if securityString == "" {
		securityString = "None"
	}

	// gcloud commands for enumeration
	m.LootMap["instances-gcloud-commands"].Contents += fmt.Sprintf(
		"# Instance: %s (Project: %s, Zone: %s)\n"+
			"# Service Accounts: %s\n"+
			"# Security Flags: %s\n"+
			"gcloud compute instances describe %s --zone=%s --project=%s\n"+
			"gcloud compute instances get-serial-port-output %s --zone=%s --project=%s\n"+
			"gcloud compute instances get-iam-policy %s --zone=%s --project=%s\n\n",
		instance.Name, instance.ProjectID, instance.Zone, saString, securityString,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// SSH commands (if external IP exists)
	if instance.ExternalIP != "" {
		m.LootMap["instances-ssh-commands"].Contents += fmt.Sprintf(
			"# Instance: %s (External IP: %s)\n"+
				"# OS Login: %v, Serial Port: %v\n"+
				"gcloud compute ssh %s --zone=%s --project=%s\n"+
				"# Direct SSH (if OS Login disabled):\n"+
				"ssh -i <key> <user>@%s\n\n",
			instance.Name, instance.ExternalIP, instance.OSLoginEnabled, instance.SerialPortEnabled,
			instance.Name, instance.Zone, instance.ProjectID,
			instance.ExternalIP,
		)
	} else {
		m.LootMap["instances-ssh-commands"].Contents += fmt.Sprintf(
			"# Instance: %s (Internal IP: %s, No external IP)\n"+
				"# OS Login: %v\n"+
				"# Use IAP tunnel:\n"+
				"gcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap\n\n",
			instance.Name, instance.InternalIP, instance.OSLoginEnabled,
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}

	// Exploitation commands
	m.LootMap["instances-exploitation"].Contents += fmt.Sprintf(
		"# Instance: %s (State: %s)\n"+
			"# Service Account: %s\n"+
			"# Default SA: %v, Broad Scopes: %v\n"+
			"# Get instance metadata (from inside the instance):\n"+
			"curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/?recursive=true\n"+
			"# Get service account token:\n"+
			"curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\n"+
			"# Run command via startup script:\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata=startup-script='#!/bin/bash\\nwhoami > /tmp/pwned'\n"+
			"# Reset SSH keys:\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata-from-file=ssh-keys=<ssh-keys-file>\n\n",
		instance.Name, instance.State, saString, instance.HasDefaultSA, instance.HasCloudScopes,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// Metadata access commands
	m.LootMap["instances-metadata"].Contents += fmt.Sprintf(
		"# Instance: %s\n"+
			"# Has Startup Script: %v, Has SSH Keys: %v\n"+
			"# Block Project SSH Keys: %v\n"+
			"# Get instance metadata:\n"+
			"gcloud compute instances describe %s --zone=%s --project=%s --format='yaml(metadata)'\n"+
			"# Get custom metadata (startup scripts, SSH keys, etc):\n"+
			"gcloud compute project-info describe --project=%s --format='yaml(commonInstanceMetadata)'\n\n",
		instance.Name, instance.HasStartupScript, instance.HasSSHKeys, instance.BlockProjectSSHKeys,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.ProjectID,
	)
}

// ------------------------------
// Helper Functions
// ------------------------------
func instanceBoolToCheck(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *InstancesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main table with security-relevant columns
	header := []string{
		"Project ID",
		"Name",
		"Zone",
		"State",
		"External IP",
		"Internal IP",
		"Service Account",
		"DefaultSA",
		"BroadScopes",
		"OSLogin",
		"SerialPort",
		"ShieldedVM",
		"SecureBoot",
		"Encryption",
	}

	var body [][]string
	for _, instance := range m.Instances {
		// Get first service account email (most instances have just one)
		saEmail := "-"
		if len(instance.ServiceAccounts) > 0 {
			saEmail = instance.ServiceAccounts[0].Email
			// Shorten default SA for display
			if strings.Contains(saEmail, "-compute@developer.gserviceaccount.com") {
				saEmail = "default-compute-sa"
			}
		}

		// External IP display
		externalIP := instance.ExternalIP
		if externalIP == "" {
			externalIP = "-"
		}

		body = append(body, []string{
			instance.ProjectID,
			instance.Name,
			instance.Zone,
			instance.State,
			externalIP,
			instance.InternalIP,
			saEmail,
			instanceBoolToCheck(instance.HasDefaultSA),
			instanceBoolToCheck(instance.HasCloudScopes),
			instanceBoolToCheck(instance.OSLoginEnabled),
			instanceBoolToCheck(instance.SerialPortEnabled),
			instanceBoolToCheck(instance.ShieldedVM),
			instanceBoolToCheck(instance.SecureBoot),
			instance.BootDiskEncryption,
		})
	}

	// Detailed service account table - shows full SA info with scopes
	saHeader := []string{
		"Instance",
		"Project ID",
		"Zone",
		"Service Account",
		"Default SA",
		"Scopes",
	}

	var saBody [][]string
	for _, instance := range m.Instances {
		for _, sa := range instance.ServiceAccounts {
			isDefault := "-"
			if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
				isDefault = "✓"
			}

			// Format scopes (shorten URLs)
			scopes := ComputeEngineService.FormatScopes(sa.Scopes)

			saBody = append(saBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				sa.Email,
				isDefault,
				scopes,
			})
		}
	}

	// Security findings table - highlight risky configurations
	findingsHeader := []string{
		"Instance",
		"Project ID",
		"Zone",
		"Finding",
		"Severity",
		"Details",
	}

	var findingsBody [][]string
	for _, instance := range m.Instances {
		// Check for security issues
		if instance.HasDefaultSA {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Default Service Account",
				"MEDIUM",
				"Using default compute service account - consider using a custom SA",
			})
		}
		if instance.HasCloudScopes {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Broad OAuth Scopes",
				"HIGH",
				"Has cloud-platform or other broad scopes - potential for privilege escalation",
			})
		}
		if instance.ExternalIP != "" && !instance.OSLoginEnabled {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"External IP without OS Login",
				"MEDIUM",
				fmt.Sprintf("External IP %s exposed without OS Login enabled", instance.ExternalIP),
			})
		}
		if instance.SerialPortEnabled {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Serial Port Enabled",
				"LOW",
				"Serial port access enabled - potential for console access",
			})
		}
		if instance.CanIPForward {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"IP Forwarding Enabled",
				"INFO",
				"Can forward packets - may be intentional for NAT/routing",
			})
		}
		if !instance.ShieldedVM {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Shielded VM Disabled",
				"LOW",
				"Shielded VM not enabled - consider enabling for security",
			})
		}
		if instance.HasStartupScript && instance.HasDefaultSA && instance.HasCloudScopes {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Startup Script with Broad Access",
				"HIGH",
				"Has startup script with default SA and broad scopes - potential for code execution",
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
			Name:   globals.GCP_INSTANCES_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	// Add service accounts table if there are any
	if len(saBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-service-accounts",
			Header: saHeader,
			Body:   saBody,
		})
	}

	// Add findings table if there are any
	if len(findingsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-findings",
			Header: findingsHeader,
			Body:   findingsBody,
		})
	}

	output := InstancesOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_INSTANCES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
