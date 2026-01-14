package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/compute/v1"
)

// Module name constant
const GCP_NETWORKTOPOLOGY_MODULE_NAME string = "network-topology"

var GCPNetworkTopologyCommand = &cobra.Command{
	Use:     GCP_NETWORKTOPOLOGY_MODULE_NAME,
	Aliases: []string{"topology", "network-map", "vpc-topology"},
	Short:   "Visualize VPC network topology, peering relationships, and trust boundaries",
	Long: `Analyze and visualize VPC network topology, peering relationships, and trust boundaries.

Features:
- Maps all VPC networks and their subnets
- Identifies VPC peering relationships
- Detects Shared VPC configurations
- Analyzes VPC Service Controls perimeters
- Maps Cloud NAT and Private Google Access
- Identifies potential trust boundary issues
- Detects cross-project network access paths

Requires appropriate IAM permissions:
- roles/compute.networkViewer
- roles/compute.viewer`,
	Run: runGCPNetworkTopologyCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type VPCNetwork struct {
	Name               string
	ProjectID          string
	SelfLink           string
	Description        string
	RoutingMode        string
	AutoCreateSubnets  bool
	SubnetCount        int
	PeeringCount       int
	IsSharedVPC        bool
	SharedVPCRole      string // "host" or "service"
	SharedVPCHost      string
	MTU                int64
	CreationTimestamp  string
	FirewallRuleCount  int
	PrivateGoogleAcces bool
}

type Subnet struct {
	Name                  string
	ProjectID             string
	Network               string
	Region                string
	IPCIDRRange           string
	SecondaryRanges       []string
	PrivateIPGoogleAccess bool
	FlowLogsEnabled       bool
	Purpose               string
	Role                  string
	StackType             string
	IAMBindings           []SubnetIAMBinding
}

type SubnetIAMBinding struct {
	Role   string
	Member string
}

type VPCPeering struct {
	Name              string
	Network           string
	PeerNetwork       string
	State             string
	StateDetails      string
	ExportCustomRoute bool
	ImportCustomRoute bool
	ExportSubnetRoute bool
	ImportSubnetRoute bool
	ProjectID         string
	PeerProjectID     string
	AutoCreateRoutes  bool
}

type SharedVPCConfig struct {
	HostProject     string
	ServiceProjects []string
	SharedSubnets   []string
	SharedNetworks  []string
}

type CloudNATConfig struct {
	Name                 string
	ProjectID            string
	Region               string
	Network              string
	Subnets              []string
	NATIPAddresses       []string
	MinPortsPerVM        int64
	SourceSubnetworkType string
	EnableLogging        bool
}


type NetworkRoute struct {
	Name        string
	ProjectID   string
	Network     string
	DestRange   string
	NextHop     string
	NextHopType string
	Priority    int64
	Tags        []string
}

// ------------------------------
// Module Struct
// ------------------------------
type NetworkTopologyModule struct {
	gcpinternal.BaseGCPModule

	ProjectNetworks map[string][]VPCNetwork                  // projectID -> networks
	ProjectSubnets  map[string][]Subnet                      // projectID -> subnets
	ProjectPeerings map[string][]VPCPeering                  // projectID -> peerings
	ProjectNATs     map[string][]CloudNATConfig              // projectID -> NATs
	ProjectRoutes   map[string][]NetworkRoute                // projectID -> routes
	SharedVPCs      map[string]*SharedVPCConfig              // hostProjectID -> config
	LootMap         map[string]map[string]*internal.LootFile // projectID -> loot files
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type NetworkTopologyOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkTopologyOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkTopologyOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPNetworkTopologyCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_NETWORKTOPOLOGY_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &NetworkTopologyModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectNetworks: make(map[string][]VPCNetwork),
		ProjectSubnets:  make(map[string][]Subnet),
		ProjectPeerings: make(map[string][]VPCPeering),
		ProjectNATs:     make(map[string][]CloudNATConfig),
		ProjectRoutes:   make(map[string][]NetworkRoute),
		SharedVPCs:      make(map[string]*SharedVPCConfig),
		LootMap:         make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *NetworkTopologyModule) Execute(ctx context.Context, logger internal.Logger) {
	// Create Compute client
	computeService, err := compute.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Compute service: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, computeService, logger)
		}(projectID)
	}
	wg.Wait()

	// Check results
	allNetworks := m.getAllNetworks()
	if len(allNetworks) == 0 {
		logger.InfoM("No VPC networks found", GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	allSubnets := m.getAllSubnets()
	allPeerings := m.getAllPeerings()
	allNATs := m.getAllNATs()

	logger.SuccessM(fmt.Sprintf("Found %d VPC network(s), %d subnet(s), %d peering(s), %d Cloud NAT(s)",
		len(allNetworks), len(allSubnets), len(allPeerings), len(allNATs)), GCP_NETWORKTOPOLOGY_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *NetworkTopologyModule) getAllNetworks() []VPCNetwork {
	var all []VPCNetwork
	for _, networks := range m.ProjectNetworks {
		all = append(all, networks...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllSubnets() []Subnet {
	var all []Subnet
	for _, subnets := range m.ProjectSubnets {
		all = append(all, subnets...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllPeerings() []VPCPeering {
	var all []VPCPeering
	for _, peerings := range m.ProjectPeerings {
		all = append(all, peerings...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllNATs() []CloudNATConfig {
	var all []CloudNATConfig
	for _, nats := range m.ProjectNATs {
		all = append(all, nats...)
	}
	return all
}

func (m *NetworkTopologyModule) getAllRoutes() []NetworkRoute {
	var all []NetworkRoute
	for _, routes := range m.ProjectRoutes {
		all = append(all, routes...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *NetworkTopologyModule) processProject(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating networks for project: %s", projectID), GCP_NETWORKTOPOLOGY_MODULE_NAME)
	}

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["network-topology-commands"] = &internal.LootFile{
			Name:     "network-topology-commands",
			Contents: "# Network Topology Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}
	m.mu.Unlock()

	// List networks
	m.enumerateNetworks(ctx, projectID, computeService, logger)

	// List subnets
	m.enumerateSubnets(ctx, projectID, computeService, logger)

	// List routes
	m.enumerateRoutes(ctx, projectID, computeService, logger)

	// List Cloud NAT
	m.enumerateCloudNAT(ctx, projectID, computeService, logger)
}

func (m *NetworkTopologyModule) enumerateNetworks(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Networks.List(projectID)
	err := req.Pages(ctx, func(page *compute.NetworkList) error {
		for _, network := range page.Items {
			vpc := VPCNetwork{
				Name:              network.Name,
				ProjectID:         projectID,
				SelfLink:          network.SelfLink,
				Description:       network.Description,
				RoutingMode:       network.RoutingConfig.RoutingMode,
				AutoCreateSubnets: network.AutoCreateSubnetworks,
				MTU:               network.Mtu,
				CreationTimestamp: network.CreationTimestamp,
				SubnetCount:       len(network.Subnetworks),
			}

			// Check for peerings
			for _, peering := range network.Peerings {
				vpc.PeeringCount++

				peeringRecord := VPCPeering{
					Name:              peering.Name,
					Network:           network.SelfLink,
					PeerNetwork:       peering.Network,
					State:             peering.State,
					StateDetails:      peering.StateDetails,
					ExportCustomRoute: peering.ExportCustomRoutes,
					ImportCustomRoute: peering.ImportCustomRoutes,
					ExportSubnetRoute: peering.ExportSubnetRoutesWithPublicIp,
					ImportSubnetRoute: peering.ImportSubnetRoutesWithPublicIp,
					ProjectID:         projectID,
					AutoCreateRoutes:  peering.AutoCreateRoutes,
				}

				// Extract peer project ID from peer network URL
				peeringRecord.PeerProjectID = m.extractProjectFromURL(peering.Network)

				m.mu.Lock()
				m.ProjectPeerings[projectID] = append(m.ProjectPeerings[projectID], peeringRecord)
				m.mu.Unlock()
			}

			m.mu.Lock()
			m.ProjectNetworks[projectID] = append(m.ProjectNetworks[projectID], vpc)
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list networks in project %s", projectID))
	}

	// Check for Shared VPC host project
	m.checkSharedVPCHost(ctx, projectID, computeService, logger)
}

func (m *NetworkTopologyModule) enumerateSubnets(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Subnetworks.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for region, subnetList := range page.Items {
			if subnetList.Subnetworks == nil {
				continue
			}
			regionName := m.extractRegionFromURL(region)
			for _, subnet := range subnetList.Subnetworks {
				subnetRecord := Subnet{
					Name:                  subnet.Name,
					ProjectID:             projectID,
					Network:               subnet.Network,
					Region:                regionName,
					IPCIDRRange:           subnet.IpCidrRange,
					PrivateIPGoogleAccess: subnet.PrivateIpGoogleAccess,
					Purpose:               subnet.Purpose,
					Role:                  subnet.Role,
					StackType:             subnet.StackType,
				}

				// Check for flow logs
				if subnet.LogConfig != nil {
					subnetRecord.FlowLogsEnabled = subnet.LogConfig.Enable
				}

				// Secondary ranges
				for _, sr := range subnet.SecondaryIpRanges {
					subnetRecord.SecondaryRanges = append(subnetRecord.SecondaryRanges,
						fmt.Sprintf("%s:%s", sr.RangeName, sr.IpCidrRange))
				}

				// Get IAM bindings for the subnet
				subnetRecord.IAMBindings = m.getSubnetIAMBindings(ctx, computeService, projectID, regionName, subnet.Name)

				m.mu.Lock()
				m.ProjectSubnets[projectID] = append(m.ProjectSubnets[projectID], subnetRecord)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list subnets in project %s", projectID))
	}
}

// getSubnetIAMBindings retrieves IAM bindings for a subnet
func (m *NetworkTopologyModule) getSubnetIAMBindings(ctx context.Context, computeService *compute.Service, projectID, region, subnetName string) []SubnetIAMBinding {
	policy, err := computeService.Subnetworks.GetIamPolicy(projectID, region, subnetName).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []SubnetIAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, SubnetIAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}
	return bindings
}

func (m *NetworkTopologyModule) enumerateRoutes(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Routes.List(projectID)
	err := req.Pages(ctx, func(page *compute.RouteList) error {
		for _, route := range page.Items {
			routeRecord := NetworkRoute{
				Name:      route.Name,
				ProjectID: projectID,
				Network:   route.Network,
				DestRange: route.DestRange,
				Priority:  route.Priority,
				Tags:      route.Tags,
			}

			// Determine next hop type
			switch {
			case route.NextHopGateway != "":
				routeRecord.NextHopType = "gateway"
				routeRecord.NextHop = route.NextHopGateway
			case route.NextHopInstance != "":
				routeRecord.NextHopType = "instance"
				routeRecord.NextHop = route.NextHopInstance
			case route.NextHopIp != "":
				routeRecord.NextHopType = "ip"
				routeRecord.NextHop = route.NextHopIp
			case route.NextHopNetwork != "":
				routeRecord.NextHopType = "network"
				routeRecord.NextHop = route.NextHopNetwork
			case route.NextHopPeering != "":
				routeRecord.NextHopType = "peering"
				routeRecord.NextHop = route.NextHopPeering
			case route.NextHopIlb != "":
				routeRecord.NextHopType = "ilb"
				routeRecord.NextHop = route.NextHopIlb
			case route.NextHopVpnTunnel != "":
				routeRecord.NextHopType = "vpn"
				routeRecord.NextHop = route.NextHopVpnTunnel
			}

			m.mu.Lock()
			m.ProjectRoutes[projectID] = append(m.ProjectRoutes[projectID], routeRecord)
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list routes in project %s", projectID))
	}
}

func (m *NetworkTopologyModule) enumerateCloudNAT(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// List routers to find NAT configurations
	req := computeService.Routers.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.RouterAggregatedList) error {
		for region, routerList := range page.Items {
			if routerList.Routers == nil {
				continue
			}
			for _, router := range routerList.Routers {
				for _, nat := range router.Nats {
					natRecord := CloudNATConfig{
						Name:                 nat.Name,
						ProjectID:            projectID,
						Region:               m.extractRegionFromURL(region),
						Network:              router.Network,
						MinPortsPerVM:        nat.MinPortsPerVm,
						SourceSubnetworkType: nat.SourceSubnetworkIpRangesToNat,
					}

					// NAT IP addresses
					for _, natIP := range nat.NatIps {
						natRecord.NATIPAddresses = append(natRecord.NATIPAddresses, natIP)
					}

					// Subnets using this NAT
					for _, subnet := range nat.Subnetworks {
						natRecord.Subnets = append(natRecord.Subnets, subnet.Name)
					}

					// Logging
					if nat.LogConfig != nil {
						natRecord.EnableLogging = nat.LogConfig.Enable
					}

					m.mu.Lock()
					m.ProjectNATs[projectID] = append(m.ProjectNATs[projectID], natRecord)
					m.mu.Unlock()
				}
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud NAT in project %s", projectID))
	}
}

func (m *NetworkTopologyModule) checkSharedVPCHost(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// Check if project is a Shared VPC host
	project, err := computeService.Projects.Get(projectID).Do()
	if err != nil {
		return
	}

	if project.XpnProjectStatus == "HOST" {
		m.mu.Lock()
		m.SharedVPCs[projectID] = &SharedVPCConfig{
			HostProject:     projectID,
			ServiceProjects: []string{},
			SharedSubnets:   []string{},
			SharedNetworks:  []string{},
		}
		m.mu.Unlock()

		// List service projects
		xpnReq := computeService.Projects.GetXpnResources(projectID)
		err := xpnReq.Pages(ctx, func(page *compute.ProjectsGetXpnResources) error {
			for _, resource := range page.Resources {
				if resource.Type == "PROJECT" {
					m.mu.Lock()
					m.SharedVPCs[projectID].ServiceProjects = append(
						m.SharedVPCs[projectID].ServiceProjects, resource.Id)
					m.mu.Unlock()
				}
			}
			return nil
		})
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
				fmt.Sprintf("Could not list XPN resources in project %s", projectID))
		}

		// Mark host networks
		m.mu.Lock()
		if networks, ok := m.ProjectNetworks[projectID]; ok {
			for i := range networks {
				networks[i].IsSharedVPC = true
				networks[i].SharedVPCRole = "host"
			}
			m.ProjectNetworks[projectID] = networks
		}
		m.mu.Unlock()
	}
}


// ------------------------------
// Helper Functions
// ------------------------------
func (m *NetworkTopologyModule) extractProjectFromURL(url string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}
	if strings.Contains(url, "projects/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *NetworkTopologyModule) extractNetworkName(url string) string {
	// Extract network name from full URL
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func (m *NetworkTopologyModule) extractRegionFromURL(url string) string {
	// Extract region from URL like regions/us-central1
	if strings.Contains(url, "regions/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "regions" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return url
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *NetworkTopologyModule) addNetworkToLoot(projectID string, n VPCNetwork) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"## VPC Network: %s (Project: %s)\n"+
			"# Describe network:\n"+
			"gcloud compute networks describe %s --project=%s\n\n"+
			"# List subnets in network:\n"+
			"gcloud compute networks subnets list --network=%s --project=%s\n\n"+
			"# List firewall rules for network:\n"+
			"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s\n\n",
		n.Name, n.ProjectID,
		n.Name, n.ProjectID,
		n.Name, n.ProjectID,
		n.Name, n.ProjectID,
	)
}

func (m *NetworkTopologyModule) addSubnetToLoot(projectID string, s Subnet) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"## Subnet: %s (Project: %s, Region: %s)\n"+
			"# Describe subnet:\n"+
			"gcloud compute networks subnets describe %s --region=%s --project=%s\n\n"+
			"# Get subnet IAM policy:\n"+
			"gcloud compute networks subnets get-iam-policy %s --region=%s --project=%s\n\n",
		s.Name, s.ProjectID, s.Region,
		s.Name, s.Region, s.ProjectID,
		s.Name, s.Region, s.ProjectID,
	)
}

func (m *NetworkTopologyModule) addPeeringToLoot(projectID string, p VPCPeering) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"## VPC Peering: %s (Project: %s)\n"+
			"# Local: %s -> Peer: %s (project: %s)\n"+
			"# List peerings:\n"+
			"gcloud compute networks peerings list --project=%s\n\n"+
			"# List peering routes (incoming):\n"+
			"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=INCOMING\n\n"+
			"# List peering routes (outgoing):\n"+
			"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=OUTGOING\n\n",
		p.Name, p.ProjectID,
		m.extractNetworkName(p.Network), m.extractNetworkName(p.PeerNetwork), p.PeerProjectID,
		p.ProjectID,
		p.Name, p.ProjectID, m.extractNetworkName(p.Network),
		p.Name, p.ProjectID, m.extractNetworkName(p.Network),
	)
}

func (m *NetworkTopologyModule) addNATToLoot(projectID string, nat CloudNATConfig) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"## Cloud NAT: %s (Project: %s, Region: %s)\n"+
			"# Describe router with NAT config:\n"+
			"gcloud compute routers describe ROUTER_NAME --region=%s --project=%s\n\n"+
			"# List NAT mappings:\n"+
			"gcloud compute routers get-nat-mapping-info ROUTER_NAME --region=%s --project=%s\n\n",
		nat.Name, nat.ProjectID, nat.Region,
		nat.Region, nat.ProjectID,
		nat.Region, nat.ProjectID,
	)
}

func (m *NetworkTopologyModule) addSharedVPCToLoot(projectID string, config *SharedVPCConfig) {
	lootFile := m.LootMap[projectID]["network-topology-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"## Shared VPC Host: %s\n"+
			"# Service Projects: %v\n"+
			"# List Shared VPC resources:\n"+
			"gcloud compute shared-vpc list-associated-resources %s\n\n"+
			"# Get host project for service project:\n"+
			"gcloud compute shared-vpc get-host-project SERVICE_PROJECT_ID\n\n"+
			"# List usable subnets for service project:\n"+
			"gcloud compute networks subnets list-usable --project=%s\n\n",
		projectID,
		config.ServiceProjects,
		projectID,
		projectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *NetworkTopologyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *NetworkTopologyModule) getNetworksHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Network",
		"Routing Mode",
		"Subnets",
		"Peerings",
		"Shared VPC",
		"MTU",
	}
}

func (m *NetworkTopologyModule) getSubnetsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Subnet",
		"Network",
		"Region",
		"CIDR",
		"Private Google Access",
		"Flow Logs",
		"Purpose",
		"Resource Role",
		"Resource Principal",
	}
}

func (m *NetworkTopologyModule) getPeeringsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Local Network",
		"Peer Network",
		"Peer Project",
		"State",
		"Import Routes",
		"Export Routes",
	}
}

func (m *NetworkTopologyModule) getNATHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"Network",
		"NAT IPs",
		"Logging",
	}
}

func (m *NetworkTopologyModule) networksToTableBody(networks []VPCNetwork) [][]string {
	var body [][]string
	for _, n := range networks {
		sharedVPC := "-"
		if n.IsSharedVPC {
			sharedVPC = n.SharedVPCRole
		}

		body = append(body, []string{
			m.GetProjectName(n.ProjectID),
			n.ProjectID,
			n.Name,
			n.RoutingMode,
			fmt.Sprintf("%d", n.SubnetCount),
			fmt.Sprintf("%d", n.PeeringCount),
			sharedVPC,
			fmt.Sprintf("%d", n.MTU),
		})
	}
	return body
}

func (m *NetworkTopologyModule) subnetsToTableBody(subnets []Subnet) [][]string {
	var body [][]string
	for _, s := range subnets {
		purpose := s.Purpose
		if purpose == "" {
			purpose = "PRIVATE"
		}

		if len(s.IAMBindings) > 0 {
			// One row per IAM binding
			for _, binding := range s.IAMBindings {
				body = append(body, []string{
					m.GetProjectName(s.ProjectID),
					s.ProjectID,
					s.Name,
					m.extractNetworkName(s.Network),
					s.Region,
					s.IPCIDRRange,
					boolToYesNo(s.PrivateIPGoogleAccess),
					boolToYesNo(s.FlowLogsEnabled),
					purpose,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// No IAM bindings - single row
			body = append(body, []string{
				m.GetProjectName(s.ProjectID),
				s.ProjectID,
				s.Name,
				m.extractNetworkName(s.Network),
				s.Region,
				s.IPCIDRRange,
				boolToYesNo(s.PrivateIPGoogleAccess),
				boolToYesNo(s.FlowLogsEnabled),
				purpose,
				"-",
				"-",
			})
		}
	}
	return body
}

func (m *NetworkTopologyModule) peeringsToTableBody(peerings []VPCPeering) [][]string {
	var body [][]string
	for _, p := range peerings {
		body = append(body, []string{
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			p.Name,
			m.extractNetworkName(p.Network),
			m.extractNetworkName(p.PeerNetwork),
			p.PeerProjectID,
			p.State,
			boolToYesNo(p.ImportCustomRoute),
			boolToYesNo(p.ExportCustomRoute),
		})
	}
	return body
}

func (m *NetworkTopologyModule) natsToTableBody(nats []CloudNATConfig) [][]string {
	var body [][]string
	for _, nat := range nats {
		natIPs := strings.Join(nat.NATIPAddresses, ", ")
		if natIPs == "" {
			natIPs = "AUTO"
		}

		body = append(body, []string{
			m.GetProjectName(nat.ProjectID),
			nat.ProjectID,
			nat.Name,
			nat.Region,
			m.extractNetworkName(nat.Network),
			natIPs,
			boolToYesNo(nat.EnableLogging),
		})
	}
	return body
}

func (m *NetworkTopologyModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if networks, ok := m.ProjectNetworks[projectID]; ok && len(networks) > 0 {
		sort.Slice(networks, func(i, j int) bool {
			return networks[i].Name < networks[j].Name
		})
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "vpc-networks",
			Header: m.getNetworksHeader(),
			Body:   m.networksToTableBody(networks),
		})
		for _, n := range networks {
			m.addNetworkToLoot(projectID, n)
		}
	}

	if subnets, ok := m.ProjectSubnets[projectID]; ok && len(subnets) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "subnets",
			Header: m.getSubnetsHeader(),
			Body:   m.subnetsToTableBody(subnets),
		})
		for _, s := range subnets {
			m.addSubnetToLoot(projectID, s)
		}
	}

	if peerings, ok := m.ProjectPeerings[projectID]; ok && len(peerings) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "vpc-peerings",
			Header: m.getPeeringsHeader(),
			Body:   m.peeringsToTableBody(peerings),
		})
		for _, p := range peerings {
			m.addPeeringToLoot(projectID, p)
		}
	}

	if nats, ok := m.ProjectNATs[projectID]; ok && len(nats) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "cloud-nat",
			Header: m.getNATHeader(),
			Body:   m.natsToTableBody(nats),
		})
		for _, nat := range nats {
			m.addNATToLoot(projectID, nat)
		}
	}

	// Add Shared VPC loot if this is a host project
	if config, ok := m.SharedVPCs[projectID]; ok {
		m.addSharedVPCToLoot(projectID, config)
	}

	return tableFiles
}

func (m *NetworkTopologyModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectsWithData := make(map[string]bool)
	for projectID := range m.ProjectNetworks {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectSubnets {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectPeerings {
		projectsWithData[projectID] = true
	}
	for projectID := range m.ProjectNATs {
		projectsWithData[projectID] = true
	}

	for projectID := range projectsWithData {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = NetworkTopologyOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
	}
}

func (m *NetworkTopologyModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allNetworks := m.getAllNetworks()
	allSubnets := m.getAllSubnets()
	allPeerings := m.getAllPeerings()
	allNATs := m.getAllNATs()

	sort.Slice(allNetworks, func(i, j int) bool {
		if allNetworks[i].ProjectID != allNetworks[j].ProjectID {
			return allNetworks[i].ProjectID < allNetworks[j].ProjectID
		}
		return allNetworks[i].Name < allNetworks[j].Name
	})

	var tables []internal.TableFile

	if len(allNetworks) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpc-networks",
			Header: m.getNetworksHeader(),
			Body:   m.networksToTableBody(allNetworks),
		})
	}

	if len(allSubnets) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "subnets",
			Header: m.getSubnetsHeader(),
			Body:   m.subnetsToTableBody(allSubnets),
		})
	}

	if len(allPeerings) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpc-peerings",
			Header: m.getPeeringsHeader(),
			Body:   m.peeringsToTableBody(allPeerings),
		})
	}

	if len(allNATs) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cloud-nat",
			Header: m.getNATHeader(),
			Body:   m.natsToTableBody(allNATs),
		})
	}

	// Populate loot for flat output
	for projectID, networks := range m.ProjectNetworks {
		for _, n := range networks {
			m.addNetworkToLoot(projectID, n)
		}
	}
	for projectID, subnets := range m.ProjectSubnets {
		for _, s := range subnets {
			m.addSubnetToLoot(projectID, s)
		}
	}
	for projectID, peerings := range m.ProjectPeerings {
		for _, p := range peerings {
			m.addPeeringToLoot(projectID, p)
		}
	}
	for projectID, nats := range m.ProjectNATs {
		for _, nat := range nats {
			m.addNATToLoot(projectID, nat)
		}
	}
	for projectID, config := range m.SharedVPCs {
		m.addSharedVPCToLoot(projectID, config)
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := NetworkTopologyOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
