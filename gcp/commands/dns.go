package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	DNSService "github.com/BishopFox/cloudfox/gcp/services/dnsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPDNSCommand = &cobra.Command{
	Use:     globals.GCP_DNS_MODULE_NAME,
	Aliases: []string{"zones", "cloud-dns"},
	Short:   "Enumerate Cloud DNS zones and records with security analysis",
	Long: `Enumerate Cloud DNS managed zones and records across projects.

Features:
- Lists all DNS managed zones (public and private)
- Shows zone configuration (DNSSEC, visibility, peering)
- Enumerates DNS records for each zone
- Identifies interesting records (A, CNAME, TXT, MX)
- Shows private zone VPC bindings
- Generates gcloud commands for DNS management

Security Columns:
- Visibility: public or private
- DNSSEC: Whether DNSSEC is enabled
- Networks: VPC networks for private zones
- Peering: Cross-project DNS peering

Attack Surface:
- Public zones expose domain infrastructure
- TXT records may contain sensitive info (SPF, DKIM, verification)
- Private zones indicate internal network structure
- DNS forwarding may expose internal resolvers`,
	Run: runGCPDNSCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type DNSModule struct {
	gcpinternal.BaseGCPModule

	Zones         []DNSService.ZoneInfo
	Records       []DNSService.RecordInfo
	TakeoverRisks []DNSService.TakeoverRisk
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type DNSOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DNSOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DNSOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDNSCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_DNS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DNSModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Zones:         []DNSService.ZoneInfo{},
		Records:       []DNSService.RecordInfo{},
		TakeoverRisks: []DNSService.TakeoverRisk{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DNSModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_DNS_MODULE_NAME, m.processProject)

	if len(m.Zones) == 0 {
		logger.InfoM("No DNS zones found", globals.GCP_DNS_MODULE_NAME)
		return
	}

	// Count zone types and security issues
	publicCount := 0
	privateCount := 0
	transferModeCount := 0
	dnssecOffCount := 0

	for _, zone := range m.Zones {
		if zone.Visibility == "public" {
			publicCount++
			// Check DNSSEC status for public zones
			if zone.DNSSECState == "" || zone.DNSSECState == "off" {
				dnssecOffCount++
			} else if zone.DNSSECState == "transfer" {
				transferModeCount++
			}
		} else {
			privateCount++
		}
	}

	// Check for subdomain takeover risks
	ds := DNSService.New()
	m.TakeoverRisks = ds.CheckTakeoverRisks(m.Records)

	msg := fmt.Sprintf("Found %d zone(s), %d record(s)", len(m.Zones), len(m.Records))
	if publicCount > 0 {
		msg += fmt.Sprintf(" [%d public]", publicCount)
	}
	if privateCount > 0 {
		msg += fmt.Sprintf(" [%d private]", privateCount)
	}
	logger.SuccessM(msg, globals.GCP_DNS_MODULE_NAME)

	// Log security warnings
	if dnssecOffCount > 0 {
		logger.InfoM(fmt.Sprintf("[SECURITY] %d public zone(s) have DNSSEC disabled", dnssecOffCount), globals.GCP_DNS_MODULE_NAME)
	}
	if transferModeCount > 0 {
		logger.InfoM(fmt.Sprintf("[SECURITY] %d zone(s) in DNSSEC transfer mode (vulnerable during migration)", transferModeCount), globals.GCP_DNS_MODULE_NAME)
	}
	if len(m.TakeoverRisks) > 0 {
		logger.InfoM(fmt.Sprintf("[SECURITY] %d potential subdomain takeover risk(s) detected", len(m.TakeoverRisks)), globals.GCP_DNS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DNSModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating DNS in project: %s", projectID), globals.GCP_DNS_MODULE_NAME)
	}

	ds := DNSService.New()

	// Get zones
	zones, err := ds.Zones(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DNS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate DNS zones in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.Zones = append(m.Zones, zones...)

	for _, zone := range zones {
		m.addZoneToLoot(zone)

		// Get records for each zone
		records, err := ds.Records(projectID, zone.Name)
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_DNS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate DNS records in zone %s", zone.Name))
			continue
		}

		m.Records = append(m.Records, records...)
		for _, record := range records {
			m.addRecordToLoot(record, zone)
		}
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d zone(s) in project %s", len(zones), projectID), globals.GCP_DNS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DNSModule) initializeLootFiles() {
	m.LootMap["dns-commands"] = &internal.LootFile{
		Name:     "dns-commands",
		Contents: "# Cloud DNS Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *DNSModule) addZoneToLoot(zone DNSService.ZoneInfo) {
	m.LootMap["dns-commands"].Contents += fmt.Sprintf(
		"# %s (%s)\n"+
			"# Project: %s | Visibility: %s\n",
		zone.Name, zone.DNSName,
		zone.ProjectID, zone.Visibility,
	)

	// gcloud commands
	m.LootMap["dns-commands"].Contents += fmt.Sprintf(
		"gcloud dns managed-zones describe %s --project=%s\n"+
			"gcloud dns record-sets list --zone=%s --project=%s\n",
		zone.Name, zone.ProjectID,
		zone.Name, zone.ProjectID,
	)

	m.LootMap["dns-commands"].Contents += "\n"
}

func (m *DNSModule) addRecordToLoot(record DNSService.RecordInfo, zone DNSService.ZoneInfo) {
	// Records are displayed in the table, no separate loot needed
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *DNSModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Zones table with IAM bindings (one row per IAM binding)
	zonesHeader := []string{
		"Project Name",
		"Project ID",
		"Zone Name",
		"DNS Name",
		"Visibility",
		"DNSSEC",
		"Security",
		"Networks/Peering",
		"Forwarding",
		"IAM Role",
		"IAM Member",
	}

	var zonesBody [][]string
	for _, zone := range m.Zones {
		// Format DNSSEC
		dnssec := zone.DNSSECState
		if dnssec == "" {
			dnssec = "off"
		}

		// Format security status
		security := "-"
		if zone.Visibility == "public" {
			if zone.DNSSECState == "" || zone.DNSSECState == "off" {
				security = "DNSSEC Disabled"
			} else if zone.DNSSECState == "transfer" {
				security = "Transfer Mode (Vulnerable)"
			} else if zone.DNSSECState == "on" {
				security = "OK"
			}
		}

		// Format networks/peering
		networkInfo := "-"
		if len(zone.PrivateNetworks) > 0 {
			networkInfo = strings.Join(zone.PrivateNetworks, ", ")
		} else if zone.PeeringNetwork != "" {
			networkInfo = fmt.Sprintf("Peering: %s", zone.PeeringNetwork)
			if zone.PeeringTargetProject != "" {
				networkInfo += fmt.Sprintf(" (%s)", zone.PeeringTargetProject)
			}
		}

		// Format forwarding
		forwarding := "-"
		if len(zone.ForwardingTargets) > 0 {
			forwarding = strings.Join(zone.ForwardingTargets, ", ")
		}

		// If zone has IAM bindings, create one row per binding
		if len(zone.IAMBindings) > 0 {
			for _, binding := range zone.IAMBindings {
				zonesBody = append(zonesBody, []string{
					m.GetProjectName(zone.ProjectID),
					zone.ProjectID,
					zone.Name,
					zone.DNSName,
					zone.Visibility,
					dnssec,
					security,
					networkInfo,
					forwarding,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// Zone has no IAM bindings - single row
			zonesBody = append(zonesBody, []string{
				m.GetProjectName(zone.ProjectID),
				zone.ProjectID,
				zone.Name,
				zone.DNSName,
				zone.Visibility,
				dnssec,
				security,
				networkInfo,
				forwarding,
				"-",
				"-",
			})
		}
	}

	// Records table (interesting types only, with takeover risk column)
	recordsHeader := []string{
		"Zone",
		"Name",
		"Type",
		"TTL",
		"Data",
		"Takeover Risk",
	}

	// Build a map of takeover risks by record name for quick lookup
	takeoverRiskMap := make(map[string]DNSService.TakeoverRisk)
	for _, risk := range m.TakeoverRisks {
		takeoverRiskMap[risk.RecordName] = risk

		// Add to loot file
		m.LootMap["dns-commands"].Contents += fmt.Sprintf(
			"# [TAKEOVER RISK] %s -> %s (%s)\n"+
				"# Risk: %s - %s\n"+
				"# Verify with:\n%s\n\n",
			risk.RecordName, risk.Target, risk.Service,
			risk.RiskLevel, risk.Description,
			risk.Verification,
		)
	}

	var recordsBody [][]string
	interestingTypes := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true}
	for _, record := range m.Records {
		if !interestingTypes[record.Type] {
			continue
		}

		// Format data - no truncation
		data := strings.Join(record.RRDatas, ", ")

		// Check for takeover risk
		takeoverRisk := "-"
		if risk, exists := takeoverRiskMap[record.Name]; exists {
			takeoverRisk = fmt.Sprintf("%s (%s)", risk.RiskLevel, risk.Service)
		}

		recordsBody = append(recordsBody, []string{
			record.ZoneName,
			record.Name,
			record.Type,
			fmt.Sprintf("%d", record.TTL),
			data,
			takeoverRisk,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{}

	if len(zonesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_DNS_MODULE_NAME + "-zones",
			Header: zonesHeader,
			Body:   zonesBody,
		})
	}

	if len(recordsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_DNS_MODULE_NAME + "-records",
			Header: recordsHeader,
			Body:   recordsBody,
		})
	}

	output := DNSOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_DNS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
