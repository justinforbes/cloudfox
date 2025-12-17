package cloudstorageservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	storageapi "google.golang.org/api/storage/v1"
)

type CloudStorageService struct {
	client  *storage.Client
	session *gcpinternal.SafeSession
}

// New creates a new CloudStorageService (legacy - uses ADC directly)
func New() *CloudStorageService {
	return &CloudStorageService{}
}

// NewWithSession creates a CloudStorageService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *CloudStorageService {
	return &CloudStorageService{session: session}
}

// NewWithClient creates a CloudStorageService with an existing client (for reuse)
func NewWithClient(client *storage.Client) *CloudStorageService {
	return &CloudStorageService{client: client}
}

// IAMBinding represents a single IAM binding on a bucket
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// BucketInfo contains bucket metadata and security-relevant configuration
type BucketInfo struct {
	// Basic info
	Name      string `json:"name"`
	Location  string `json:"location"`
	ProjectID string `json:"projectID"`

	// Security-relevant fields
	PublicAccessPrevention   string `json:"publicAccessPrevention"`   // "enforced", "inherited", or "unspecified"
	UniformBucketLevelAccess bool   `json:"uniformBucketLevelAccess"` // true = IAM only, no ACLs
	VersioningEnabled        bool   `json:"versioningEnabled"`        // Object versioning
	RequesterPays            bool   `json:"requesterPays"`            // Requester pays enabled
	DefaultEventBasedHold    bool   `json:"defaultEventBasedHold"`    // Event-based hold on new objects
	LoggingEnabled           bool   `json:"loggingEnabled"`           // Access logging enabled
	LogBucket                string `json:"logBucket"`                // Destination bucket for logs
	EncryptionType           string `json:"encryptionType"`           // "Google-managed", "CMEK", or "CSEK"
	KMSKeyName               string `json:"kmsKeyName"`               // KMS key for CMEK
	RetentionPolicyEnabled   bool   `json:"retentionPolicyEnabled"`   // Retention policy set
	RetentionPeriodDays      int64  `json:"retentionPeriodDays"`      // Retention period in days
	RetentionPolicyLocked    bool   `json:"retentionPolicyLocked"`    // Retention policy is locked (immutable)
	SoftDeleteEnabled        bool   `json:"softDeleteEnabled"`        // Soft delete policy enabled
	SoftDeleteRetentionDays  int64  `json:"softDeleteRetentionDays"`  // Soft delete retention in days
	StorageClass             string `json:"storageClass"`             // Default storage class
	AutoclassEnabled         bool   `json:"autoclassEnabled"`         // Autoclass feature enabled
	AutoclassTerminalClass   string `json:"autoclassTerminalClass"`   // Terminal storage class for autoclass

	// Public access indicators
	IsPublic     bool   `json:"isPublic"`     // Has allUsers or allAuthenticatedUsers
	PublicAccess string `json:"publicAccess"` // "None", "allUsers", "allAuthenticatedUsers", or "Both"

	// IAM Policy
	IAMBindings []IAMBinding `json:"iamBindings"` // IAM policy bindings on the bucket

	// Timestamps
	Created string `json:"created"`
	Updated string `json:"updated"`
}

func (cs *CloudStorageService) Buckets(projectID string) ([]BucketInfo, error) {
	ctx := context.Background()

	// Get or create client
	client, closeClient, err := cs.getClient(ctx)
	if err != nil {
		return nil, err
	}
	if closeClient {
		defer client.Close()
	}

	var buckets []BucketInfo
	bucketIterator := client.Buckets(ctx, projectID)
	for {
		battrs, err := bucketIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		bucket := BucketInfo{
			Name:      battrs.Name,
			Location:  battrs.Location,
			ProjectID: projectID,
		}

		// Security fields
		bucket.PublicAccessPrevention = publicAccessPreventionToString(battrs.PublicAccessPrevention)
		bucket.UniformBucketLevelAccess = battrs.UniformBucketLevelAccess.Enabled
		bucket.VersioningEnabled = battrs.VersioningEnabled
		bucket.RequesterPays = battrs.RequesterPays
		bucket.DefaultEventBasedHold = battrs.DefaultEventBasedHold
		bucket.StorageClass = battrs.StorageClass

		// Logging
		if battrs.Logging != nil {
			bucket.LoggingEnabled = battrs.Logging.LogBucket != ""
			bucket.LogBucket = battrs.Logging.LogBucket
		}

		// Encryption
		if battrs.Encryption != nil && battrs.Encryption.DefaultKMSKeyName != "" {
			bucket.EncryptionType = "CMEK"
			bucket.KMSKeyName = battrs.Encryption.DefaultKMSKeyName
		} else {
			bucket.EncryptionType = "Google-managed"
		}

		// Retention Policy
		if battrs.RetentionPolicy != nil {
			bucket.RetentionPolicyEnabled = true
			bucket.RetentionPeriodDays = int64(battrs.RetentionPolicy.RetentionPeriod.Hours() / 24)
			bucket.RetentionPolicyLocked = battrs.RetentionPolicy.IsLocked
		}

		// Autoclass
		if battrs.Autoclass != nil && battrs.Autoclass.Enabled {
			bucket.AutoclassEnabled = true
			bucket.AutoclassTerminalClass = battrs.Autoclass.TerminalStorageClass
		}

		// Timestamps
		if !battrs.Created.IsZero() {
			bucket.Created = battrs.Created.Format("2006-01-02")
		}

		// Get additional fields via REST API (SoftDeletePolicy, Updated)
		cs.enrichBucketFromRestAPI(ctx, &bucket)

		// Get IAM policy for the bucket
		iamBindings, isPublic, publicAccess := cs.getBucketIAMPolicy(ctx, client, battrs.Name)
		bucket.IAMBindings = iamBindings
		bucket.IsPublic = isPublic
		bucket.PublicAccess = publicAccess

		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

// getClient returns a storage client, using session if available
// Returns the client, whether to close it, and any error
func (cs *CloudStorageService) getClient(ctx context.Context) (*storage.Client, bool, error) {
	// If we have an existing client, use it
	if cs.client != nil {
		return cs.client, false, nil
	}

	// If we have a session, use its token source
	if cs.session != nil {
		client, err := storage.NewClient(ctx, cs.session.GetClientOption())
		if err != nil {
			return nil, false, fmt.Errorf("failed to create client with session: %v", err)
		}
		return client, true, nil
	}

	// Fall back to ADC
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create client: %v", err)
	}
	return client, true, nil
}

// getClientOption returns the appropriate client option based on session
func (cs *CloudStorageService) getClientOption() option.ClientOption {
	if cs.session != nil {
		return cs.session.GetClientOption()
	}
	return nil
}

// getBucketIAMPolicy retrieves the IAM policy for a bucket and checks for public access
func (cs *CloudStorageService) getBucketIAMPolicy(ctx context.Context, client *storage.Client, bucketName string) ([]IAMBinding, bool, string) {
	var bindings []IAMBinding
	isPublic := false
	hasAllUsers := false
	hasAllAuthenticatedUsers := false

	policy, err := client.Bucket(bucketName).IAM().Policy(ctx)
	if err != nil {
		// Return empty bindings if we can't get the policy (permission denied, etc.)
		return bindings, false, "Unknown"
	}

	// Convert IAM policy to our binding format
	for _, role := range policy.Roles() {
		members := policy.Members(role)
		if len(members) > 0 {
			binding := IAMBinding{
				Role:    string(role),
				Members: make([]string, len(members)),
			}
			for i, member := range members {
				binding.Members[i] = member

				// Check for public access
				if member == string(iam.AllUsers) {
					hasAllUsers = true
					isPublic = true
				}
				if member == string(iam.AllAuthenticatedUsers) {
					hasAllAuthenticatedUsers = true
					isPublic = true
				}
			}
			bindings = append(bindings, binding)
		}
	}

	// Determine public access level
	publicAccess := "None"
	if hasAllUsers && hasAllAuthenticatedUsers {
		publicAccess = "allUsers + allAuthenticatedUsers"
	} else if hasAllUsers {
		publicAccess = "allUsers"
	} else if hasAllAuthenticatedUsers {
		publicAccess = "allAuthenticatedUsers"
	}

	return bindings, isPublic, publicAccess
}

// GetBucketIAMPolicyOnly retrieves just the IAM policy for a specific bucket
func (cs *CloudStorageService) GetBucketIAMPolicyOnly(bucketName string) ([]IAMBinding, error) {
	ctx := context.Background()

	client, closeClient, err := cs.getClient(ctx)
	if err != nil {
		return nil, err
	}
	if closeClient {
		defer client.Close()
	}

	bindings, _, _ := cs.getBucketIAMPolicy(ctx, client, bucketName)
	return bindings, nil
}

// publicAccessPreventionToString converts the PublicAccessPrevention type to a readable string
func publicAccessPreventionToString(pap storage.PublicAccessPrevention) string {
	switch pap {
	case storage.PublicAccessPreventionEnforced:
		return "enforced"
	case storage.PublicAccessPreventionInherited:
		return "inherited"
	default:
		return "unspecified"
	}
}

// FormatIAMBindings formats IAM bindings for display
func FormatIAMBindings(bindings []IAMBinding) string {
	if len(bindings) == 0 {
		return "No IAM bindings"
	}

	var parts []string
	for _, binding := range bindings {
		memberStr := strings.Join(binding.Members, ", ")
		parts = append(parts, fmt.Sprintf("%s: [%s]", binding.Role, memberStr))
	}
	return strings.Join(parts, "; ")
}

// FormatIAMBindingsShort formats IAM bindings in a shorter format for table display
func FormatIAMBindingsShort(bindings []IAMBinding) string {
	if len(bindings) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d binding(s)", len(bindings))
}

// enrichBucketFromRestAPI fetches additional bucket fields via the REST API
// that may not be available in the Go SDK version
func (cs *CloudStorageService) enrichBucketFromRestAPI(ctx context.Context, bucket *BucketInfo) {
	var service *storageapi.Service
	var err error

	// Use session if available
	if cs.session != nil {
		service, err = storageapi.NewService(ctx, cs.session.GetClientOption())
	} else {
		service, err = storageapi.NewService(ctx)
	}

	if err != nil {
		// Silently fail - these are optional enrichments
		return
	}

	// Get bucket details via REST API
	restBucket, err := service.Buckets.Get(bucket.Name).Context(ctx).Do()
	if err != nil {
		// Silently fail - these are optional enrichments
		return
	}

	// Parse SoftDeletePolicy
	if restBucket.SoftDeletePolicy != nil {
		if restBucket.SoftDeletePolicy.RetentionDurationSeconds > 0 {
			bucket.SoftDeleteEnabled = true
			bucket.SoftDeleteRetentionDays = restBucket.SoftDeletePolicy.RetentionDurationSeconds / 86400 // seconds to days
		}
	}

	// Parse Updated timestamp
	if restBucket.Updated != "" {
		// REST API returns RFC3339 format
		if t, err := time.Parse(time.RFC3339, restBucket.Updated); err == nil {
			bucket.Updated = t.Format("2006-01-02")
		}
	}
}
