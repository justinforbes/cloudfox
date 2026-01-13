package composerservice

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	composer "google.golang.org/api/composer/v1"
)

// composerRegions contains all Cloud Composer regions
// Note: Cloud Composer API does NOT support the "-" wildcard for locations
// so we need to iterate through regions explicitly
var composerRegions = []string{
	// Americas
	"northamerica-northeast1", "northamerica-northeast2", "northamerica-south1",
	"southamerica-east1", "southamerica-west1",
	"us-central1", "us-east1", "us-east4", "us-east5", "us-east7",
	"us-south1", "us-west1", "us-west2", "us-west3", "us-west4",
	// Europe
	"europe-central2", "europe-north1", "europe-north2",
	"europe-southwest1", "europe-west1", "europe-west2", "europe-west3",
	"europe-west4", "europe-west6", "europe-west8", "europe-west9",
	"europe-west10", "europe-west12",
	// Asia Pacific
	"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
	"asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
	"australia-southeast1", "australia-southeast2",
	// Middle East & Africa
	"africa-south1", "me-central1", "me-central2", "me-west1",
}

type ComposerService struct {
	session *gcpinternal.SafeSession
}

func New() *ComposerService {
	return &ComposerService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *ComposerService {
	return &ComposerService{session: session}
}

// EnvironmentInfo represents a Cloud Composer environment
type EnvironmentInfo struct {
	Name              string   `json:"name"`
	ProjectID         string   `json:"projectId"`
	Location          string   `json:"location"`
	State             string   `json:"state"`
	CreateTime        string   `json:"createTime"`
	UpdateTime        string   `json:"updateTime"`

	// Airflow config
	AirflowURI        string   `json:"airflowUri"`
	DagGcsPrefix      string   `json:"dagGcsPrefix"`
	AirflowVersion    string   `json:"airflowVersion"`
	PythonVersion     string   `json:"pythonVersion"`
	ImageVersion      string   `json:"imageVersion"`

	// Node config
	MachineType       string   `json:"machineType"`
	DiskSizeGb        int64    `json:"diskSizeGb"`
	NodeCount         int64    `json:"nodeCount"`
	Network           string   `json:"network"`
	Subnetwork        string   `json:"subnetwork"`
	ServiceAccount    string   `json:"serviceAccount"`

	// Security config
	PrivateEnvironment    bool     `json:"privateEnvironment"`
	WebServerAllowedIPs   []string `json:"webServerAllowedIps"`
	EnablePrivateEndpoint bool     `json:"enablePrivateEndpoint"`
}

// ListEnvironments retrieves all Composer environments in a project across all regions
// Note: The Cloud Composer API does NOT support the "-" wildcard for locations
// so we must iterate through regions explicitly
func (s *ComposerService) ListEnvironments(projectID string) ([]EnvironmentInfo, error) {
	ctx := context.Background()
	var service *composer.Service
	var err error

	if s.session != nil {
		service, err = composer.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = composer.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "composer.googleapis.com")
	}

	var environments []EnvironmentInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	var lastErr error
	var errMu sync.Mutex

	// Use a semaphore to limit concurrent API calls
	semaphore := make(chan struct{}, 10) // Max 10 concurrent requests

	// Iterate through all Composer regions in parallel
	for _, region := range composerRegions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
			req := service.Projects.Locations.Environments.List(parent)
			err := req.Pages(ctx, func(page *composer.ListEnvironmentsResponse) error {
				for _, env := range page.Environments {
					info := s.parseEnvironment(env, projectID)
					mu.Lock()
					environments = append(environments, info)
					mu.Unlock()
				}
				return nil
			})

			if err != nil {
				// Track the last error but continue - region may not have environments or API may not be enabled
				errMu.Lock()
				lastErr = err
				errMu.Unlock()
			}
		}(region)
	}

	wg.Wait()

	// Only return error if we got no environments AND had errors
	// If we found environments in some regions, that's success
	if len(environments) == 0 && lastErr != nil {
		return nil, gcpinternal.ParseGCPError(lastErr, "composer.googleapis.com")
	}

	return environments, nil
}

// parseEnvironment converts a Composer environment to EnvironmentInfo
func (s *ComposerService) parseEnvironment(env *composer.Environment, projectID string) EnvironmentInfo {
	info := EnvironmentInfo{
		Name:       extractName(env.Name),
		ProjectID:  projectID,
		Location:   extractLocation(env.Name),
		State:      env.State,
		CreateTime: env.CreateTime,
		UpdateTime: env.UpdateTime,
	}

	if env.Config != nil {
		// Airflow config
		if env.Config.AirflowUri != "" {
			info.AirflowURI = env.Config.AirflowUri
		}
		info.DagGcsPrefix = env.Config.DagGcsPrefix

		// Software config
		if env.Config.SoftwareConfig != nil {
			info.AirflowVersion = env.Config.SoftwareConfig.AirflowConfigOverrides["core-dags_are_paused_at_creation"]
			info.PythonVersion = env.Config.SoftwareConfig.PythonVersion
			info.ImageVersion = env.Config.SoftwareConfig.ImageVersion
		}

		// Node config
		if env.Config.NodeConfig != nil {
			info.MachineType = env.Config.NodeConfig.MachineType
			info.DiskSizeGb = env.Config.NodeConfig.DiskSizeGb
			info.Network = env.Config.NodeConfig.Network
			info.Subnetwork = env.Config.NodeConfig.Subnetwork
			info.ServiceAccount = env.Config.NodeConfig.ServiceAccount
		}

		info.NodeCount = env.Config.NodeCount

		// Private environment config
		if env.Config.PrivateEnvironmentConfig != nil {
			info.PrivateEnvironment = env.Config.PrivateEnvironmentConfig.EnablePrivateEnvironment
			// EnablePrivateEndpoint is part of PrivateClusterConfig, not PrivateEnvironmentConfig
			if env.Config.PrivateEnvironmentConfig.PrivateClusterConfig != nil {
				info.EnablePrivateEndpoint = env.Config.PrivateEnvironmentConfig.PrivateClusterConfig.EnablePrivateEndpoint
			}
		}

		// Web server network access control
		if env.Config.WebServerNetworkAccessControl != nil {
			for _, cidr := range env.Config.WebServerNetworkAccessControl.AllowedIpRanges {
				info.WebServerAllowedIPs = append(info.WebServerAllowedIPs, cidr.Value)
			}
		}
	}

	return info
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractLocation(fullName string) string {
	parts := strings.Split(fullName, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
