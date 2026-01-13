package schedulerservice

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	scheduler "google.golang.org/api/cloudscheduler/v1"
)

// schedulerRegions contains all Cloud Scheduler regions
// Note: Cloud Scheduler API does NOT support the "-" wildcard for locations
// so we need to iterate through regions explicitly
var schedulerRegions = []string{
	// Americas
	"northamerica-northeast1", "northamerica-northeast2",
	"southamerica-east1", "southamerica-west1",
	"us-central1", "us-east1", "us-east4", "us-east5",
	"us-south1", "us-west1", "us-west2", "us-west3", "us-west4",
	// Europe
	"europe-central2", "europe-north1",
	"europe-southwest1", "europe-west1", "europe-west2", "europe-west3",
	"europe-west4", "europe-west6", "europe-west8", "europe-west9",
	// Asia Pacific
	"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
	"asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
	"australia-southeast1", "australia-southeast2",
	// Middle East & Africa
	"africa-south1", "me-central1", "me-west1",
}

type SchedulerService struct{}

func New() *SchedulerService {
	return &SchedulerService{}
}

// JobInfo holds Cloud Scheduler job details with security-relevant information
type JobInfo struct {
	Name              string
	ProjectID         string
	Location          string
	Description       string
	State             string  // ENABLED, PAUSED, DISABLED, UPDATE_FAILED
	Schedule          string  // Cron expression
	TimeZone          string

	// Target configuration
	TargetType        string  // http, pubsub, appengine
	TargetURI         string  // For HTTP targets
	TargetHTTPMethod  string  // For HTTP targets
	TargetTopic       string  // For Pub/Sub targets
	TargetService     string  // For App Engine targets
	TargetVersion     string  // For App Engine targets

	// Authentication
	ServiceAccount    string  // OIDC or OAuth service account
	AuthType          string  // OIDC, OAuth, or none

	// Retry configuration
	RetryCount        int64
	MaxRetryDuration  string
	MaxBackoff        string

	// Timing
	LastAttemptTime   string
	ScheduleTime      string
	Status            string  // Last attempt status
}

// Jobs retrieves all Cloud Scheduler jobs in a project across all regions
// Note: The Cloud Scheduler API does NOT support the "-" wildcard for locations
// so we must iterate through regions explicitly
func (ss *SchedulerService) Jobs(projectID string) ([]JobInfo, error) {
	ctx := context.Background()

	service, err := scheduler.NewService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudscheduler.googleapis.com")
	}

	var jobs []JobInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	var lastErr error
	var errMu sync.Mutex

	// Use a semaphore to limit concurrent API calls
	semaphore := make(chan struct{}, 10) // Max 10 concurrent requests

	// Iterate through all Scheduler regions in parallel
	for _, region := range schedulerRegions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)

			call := service.Projects.Locations.Jobs.List(parent)
			err := call.Pages(ctx, func(page *scheduler.ListJobsResponse) error {
				for _, job := range page.Jobs {
					info := parseJobInfo(job, projectID)
					mu.Lock()
					jobs = append(jobs, info)
					mu.Unlock()
				}
				return nil
			})

			if err != nil {
				// Track the last error but continue - region may not have jobs or API may not be enabled
				errMu.Lock()
				lastErr = err
				errMu.Unlock()
			}
		}(region)
	}

	wg.Wait()

	// Only return error if we got no jobs AND had errors
	// If we found jobs in some regions, that's success
	if len(jobs) == 0 && lastErr != nil {
		return nil, gcpinternal.ParseGCPError(lastErr, "cloudscheduler.googleapis.com")
	}

	return jobs, nil
}

// parseJobInfo extracts relevant information from a Cloud Scheduler job
func parseJobInfo(job *scheduler.Job, projectID string) JobInfo {
	info := JobInfo{
		Name:        extractName(job.Name),
		ProjectID:   projectID,
		Description: job.Description,
		State:       job.State,
		Schedule:    job.Schedule,
		TimeZone:    job.TimeZone,
	}

	// Extract location from job name
	// Format: projects/{project}/locations/{location}/jobs/{name}
	parts := strings.Split(job.Name, "/")
	if len(parts) >= 4 {
		info.Location = parts[3]
	}

	// Parse target configuration
	if job.HttpTarget != nil {
		info.TargetType = "http"
		info.TargetURI = job.HttpTarget.Uri
		info.TargetHTTPMethod = job.HttpTarget.HttpMethod

		// Check for OIDC token
		if job.HttpTarget.OidcToken != nil {
			info.AuthType = "OIDC"
			info.ServiceAccount = job.HttpTarget.OidcToken.ServiceAccountEmail
		}

		// Check for OAuth token
		if job.HttpTarget.OauthToken != nil {
			info.AuthType = "OAuth"
			info.ServiceAccount = job.HttpTarget.OauthToken.ServiceAccountEmail
		}
	}

	if job.PubsubTarget != nil {
		info.TargetType = "pubsub"
		info.TargetTopic = extractName(job.PubsubTarget.TopicName)
	}

	if job.AppEngineHttpTarget != nil {
		info.TargetType = "appengine"
		info.TargetURI = job.AppEngineHttpTarget.RelativeUri
		info.TargetHTTPMethod = job.AppEngineHttpTarget.HttpMethod
		if job.AppEngineHttpTarget.AppEngineRouting != nil {
			info.TargetService = job.AppEngineHttpTarget.AppEngineRouting.Service
			info.TargetVersion = job.AppEngineHttpTarget.AppEngineRouting.Version
		}
	}

	// Retry configuration
	if job.RetryConfig != nil {
		info.RetryCount = job.RetryConfig.RetryCount
		info.MaxRetryDuration = job.RetryConfig.MaxRetryDuration
		info.MaxBackoff = job.RetryConfig.MaxBackoffDuration
	}

	// Timing info
	info.LastAttemptTime = job.LastAttemptTime
	info.ScheduleTime = job.ScheduleTime
	if job.Status != nil {
		info.Status = formatJobStatus(job.Status)
	}

	return info
}

// formatJobStatus formats the job status for display
func formatJobStatus(status *scheduler.Status) string {
	if status.Code == 0 {
		return "OK"
	}
	return fmt.Sprintf("Error %d: %s", status.Code, status.Message)
}

// extractName extracts just the resource name from the full resource name
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
