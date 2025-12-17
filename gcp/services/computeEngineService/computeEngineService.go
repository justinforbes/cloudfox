package computeengineservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/compute/v1"
)

type ComputeEngineService struct {
	session *gcpinternal.SafeSession
}

// New creates a new ComputeEngineService (legacy - uses ADC directly)
func New() *ComputeEngineService {
	return &ComputeEngineService{}
}

// NewWithSession creates a ComputeEngineService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *ComputeEngineService {
	return &ComputeEngineService{session: session}
}

// ServiceAccountInfo contains service account details for an instance
type ServiceAccountInfo struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

// ComputeEngineInfo contains instance metadata and security-relevant configuration
type ComputeEngineInfo struct {
	// Basic info
	Name      string `json:"name"`
	ID        string `json:"id"`
	Zone      string `json:"zone"`
	State     string `json:"state"`
	ProjectID string `json:"projectID"`

	// Network configuration
	ExternalIP        string                      `json:"externalIP"`
	InternalIP        string                      `json:"internalIP"`
	NetworkInterfaces []*compute.NetworkInterface `json:"networkInterfaces"`
	CanIPForward      bool                        `json:"canIpForward"` // Can forward packets (router/NAT)

	// Service accounts and scopes
	ServiceAccounts []ServiceAccountInfo `json:"serviceAccounts"`
	HasDefaultSA    bool                 `json:"hasDefaultSA"`   // Uses default compute SA
	HasCloudScopes  bool                 `json:"hasCloudScopes"` // Has cloud-platform or other broad scopes

	// Security configuration
	DeletionProtection  bool `json:"deletionProtection"`  // Protected against deletion
	ShieldedVM          bool `json:"shieldedVM"`          // Shielded VM enabled
	SecureBoot          bool `json:"secureBoot"`          // Secure Boot enabled
	VTPMEnabled         bool `json:"vtpmEnabled"`         // vTPM enabled
	IntegrityMonitoring bool `json:"integrityMonitoring"` // Integrity monitoring enabled
	ConfidentialVM      bool `json:"confidentialVM"`      // Confidential computing enabled

	// Instance metadata
	MachineType string            `json:"machineType"`
	Tags        *compute.Tags     `json:"tags"`
	Labels      map[string]string `json:"labels"`

	// Metadata security
	HasStartupScript    bool `json:"hasStartupScript"`    // Has startup script in metadata
	HasSSHKeys          bool `json:"hasSSHKeys"`          // Has SSH keys in metadata
	BlockProjectSSHKeys bool `json:"blockProjectSSHKeys"` // Blocks project-wide SSH keys
	OSLoginEnabled      bool `json:"osLoginEnabled"`      // OS Login enabled
	OSLogin2FAEnabled   bool `json:"osLogin2FAEnabled"`   // OS Login 2FA enabled
	SerialPortEnabled   bool `json:"serialPortEnabled"`   // Serial port access enabled

	// Disk encryption
	BootDiskEncryption string `json:"bootDiskEncryption"` // "Google-managed", "CMEK", or "CSEK"
	BootDiskKMSKey     string `json:"bootDiskKMSKey"`     // KMS key for CMEK

	// Timestamps
	CreationTimestamp  string `json:"creationTimestamp"`
	LastStartTimestamp string `json:"lastStartTimestamp"`
}

// getService returns a compute service, using session if available
func (ces *ComputeEngineService) getService(ctx context.Context) (*compute.Service, error) {
	if ces.session != nil {
		return compute.NewService(ctx, ces.session.GetClientOption())
	}
	return compute.NewService(ctx)
}

// Retrieves instances from all regions and zones for a project without using concurrency.
func (ces *ComputeEngineService) Instances(projectID string) ([]ComputeEngineInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, err
	}

	regions, err := computeService.Regions.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	var instanceInfos []ComputeEngineInfo
	for _, region := range regions.Items {
		for _, zoneURL := range region.Zones {
			zone := getZoneNameFromURL(zoneURL)
			instanceList, err := computeService.Instances.List(projectID, zone).Do()
			if err != nil {
				return nil, fmt.Errorf("error retrieving instances from zone %s: %v", zone, err)
			}
			for _, instance := range instanceList.Items {
				info := ComputeEngineInfo{
					Name:               instance.Name,
					ID:                 fmt.Sprintf("%v", instance.Id),
					Zone:               zone,
					State:              instance.Status,
					ExternalIP:         getExternalIP(instance),
					InternalIP:         getInternalIP(instance),
					NetworkInterfaces:  instance.NetworkInterfaces,
					CanIPForward:       instance.CanIpForward,
					Tags:               instance.Tags,
					Labels:             instance.Labels,
					ProjectID:          projectID,
					DeletionProtection: instance.DeletionProtection,
					CreationTimestamp:  instance.CreationTimestamp,
					LastStartTimestamp: instance.LastStartTimestamp,
				}

				// Parse machine type (extract just the type name)
				info.MachineType = getMachineTypeName(instance.MachineType)

				// Parse service accounts and scopes
				info.ServiceAccounts, info.HasDefaultSA, info.HasCloudScopes = parseServiceAccounts(instance.ServiceAccounts, projectID)

				// Parse shielded VM config
				if instance.ShieldedInstanceConfig != nil {
					info.ShieldedVM = true
					info.SecureBoot = instance.ShieldedInstanceConfig.EnableSecureBoot
					info.VTPMEnabled = instance.ShieldedInstanceConfig.EnableVtpm
					info.IntegrityMonitoring = instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
				}

				// Parse confidential VM config
				if instance.ConfidentialInstanceConfig != nil {
					info.ConfidentialVM = instance.ConfidentialInstanceConfig.EnableConfidentialCompute
				}

				// Parse metadata for security-relevant items
				if instance.Metadata != nil {
					info.HasStartupScript, info.HasSSHKeys, info.BlockProjectSSHKeys,
						info.OSLoginEnabled, info.OSLogin2FAEnabled, info.SerialPortEnabled = parseMetadata(instance.Metadata)
				}

				// Parse boot disk encryption
				info.BootDiskEncryption, info.BootDiskKMSKey = parseBootDiskEncryption(instance.Disks)

				instanceInfos = append(instanceInfos, info)
			}
		}
	}
	return instanceInfos, nil
}

// Returns the zone from a GCP URL string with the zone in it
func getZoneNameFromURL(zoneURL string) string {
	splits := strings.Split(zoneURL, "/")
	return splits[len(splits)-1]
}

// getExternalIP extracts the external IP address from an instance if available.
func getExternalIP(instance *compute.Instance) string {
	for _, iface := range instance.NetworkInterfaces {
		for _, accessConfig := range iface.AccessConfigs {
			if accessConfig.NatIP != "" {
				return accessConfig.NatIP
			}
		}
	}
	return ""
}

// getInternalIP extracts the internal IP address from an instance.
func getInternalIP(instance *compute.Instance) string {
	if len(instance.NetworkInterfaces) > 0 {
		return instance.NetworkInterfaces[0].NetworkIP
	}
	return ""
}

// getMachineTypeName extracts the machine type name from a full URL
func getMachineTypeName(machineTypeURL string) string {
	parts := strings.Split(machineTypeURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return machineTypeURL
}

// parseServiceAccounts extracts service account info and checks for security concerns
func parseServiceAccounts(sas []*compute.ServiceAccount, projectID string) ([]ServiceAccountInfo, bool, bool) {
	var accounts []ServiceAccountInfo
	hasDefaultSA := false
	hasCloudScopes := false

	defaultSAPattern := fmt.Sprintf("%s-compute@developer.gserviceaccount.com", projectID)

	for _, sa := range sas {
		info := ServiceAccountInfo{
			Email:  sa.Email,
			Scopes: sa.Scopes,
		}
		accounts = append(accounts, info)

		// Check if using default compute service account
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") ||
			strings.HasSuffix(sa.Email, defaultSAPattern) {
			hasDefaultSA = true
		}

		// Check for broad scopes
		for _, scope := range sa.Scopes {
			if scope == "https://www.googleapis.com/auth/cloud-platform" ||
				scope == "https://www.googleapis.com/auth/compute" ||
				scope == "https://www.googleapis.com/auth/devstorage.full_control" ||
				scope == "https://www.googleapis.com/auth/devstorage.read_write" {
				hasCloudScopes = true
			}
		}
	}

	return accounts, hasDefaultSA, hasCloudScopes
}

// parseMetadata checks instance metadata for security-relevant settings
func parseMetadata(metadata *compute.Metadata) (hasStartupScript, hasSSHKeys, blockProjectSSHKeys, osLoginEnabled, osLogin2FA, serialPortEnabled bool) {
	if metadata == nil || metadata.Items == nil {
		return
	}

	for _, item := range metadata.Items {
		if item == nil {
			continue
		}

		switch item.Key {
		case "startup-script", "startup-script-url":
			hasStartupScript = true
		case "ssh-keys", "sshKeys":
			hasSSHKeys = true
		case "block-project-ssh-keys":
			if item.Value != nil && *item.Value == "true" {
				blockProjectSSHKeys = true
			}
		case "enable-oslogin":
			if item.Value != nil && strings.ToLower(*item.Value) == "true" {
				osLoginEnabled = true
			}
		case "enable-oslogin-2fa":
			if item.Value != nil && strings.ToLower(*item.Value) == "true" {
				osLogin2FA = true
			}
		case "serial-port-enable":
			if item.Value != nil && *item.Value == "true" {
				serialPortEnabled = true
			}
		}
	}

	return
}

// parseBootDiskEncryption checks the boot disk encryption type
func parseBootDiskEncryption(disks []*compute.AttachedDisk) (encryptionType, kmsKey string) {
	encryptionType = "Google-managed"

	for _, disk := range disks {
		if disk == nil || !disk.Boot {
			continue
		}

		if disk.DiskEncryptionKey != nil {
			if disk.DiskEncryptionKey.KmsKeyName != "" {
				encryptionType = "CMEK"
				kmsKey = disk.DiskEncryptionKey.KmsKeyName
			} else if disk.DiskEncryptionKey.Sha256 != "" {
				encryptionType = "CSEK"
			}
		}
		break // Only check boot disk
	}

	return
}

// FormatScopes formats service account scopes for display
func FormatScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "-"
	}

	// Shorten scope URLs for display
	var shortScopes []string
	for _, scope := range scopes {
		// Extract the scope name from the URL
		parts := strings.Split(scope, "/")
		if len(parts) > 0 {
			shortScopes = append(shortScopes, parts[len(parts)-1])
		}
	}
	return strings.Join(shortScopes, ", ")
}
