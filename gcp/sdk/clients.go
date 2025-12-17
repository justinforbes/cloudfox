package sdk

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	artifactregistry "google.golang.org/api/artifactregistry/v1"
	bigquery "google.golang.org/api/bigquery/v2"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	iam "google.golang.org/api/iam/v1"
	run "google.golang.org/api/run/v1"
	secretmanager "google.golang.org/api/secretmanager/v1"
)

// GetStorageClient returns a Cloud Storage client
func GetStorageClient(ctx context.Context, session *gcpinternal.SafeSession) (*storage.Client, error) {
	client, err := storage.NewClient(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	return client, nil
}

// GetComputeService returns a Compute Engine service
func GetComputeService(ctx context.Context, session *gcpinternal.SafeSession) (*compute.Service, error) {
	service, err := compute.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}
	return service, nil
}

// GetIAMService returns an IAM Admin service
func GetIAMService(ctx context.Context, session *gcpinternal.SafeSession) (*iam.Service, error) {
	service, err := iam.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %w", err)
	}
	return service, nil
}

// GetResourceManagerService returns a Cloud Resource Manager service
func GetResourceManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudresourcemanager.Service, error) {
	service, err := cloudresourcemanager.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return service, nil
}

// GetSecretManagerService returns a Secret Manager service
func GetSecretManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*secretmanager.Service, error) {
	service, err := secretmanager.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager service: %w", err)
	}
	return service, nil
}

// GetBigQueryService returns a BigQuery service
func GetBigQueryService(ctx context.Context, session *gcpinternal.SafeSession) (*bigquery.Service, error) {
	service, err := bigquery.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create BigQuery service: %w", err)
	}
	return service, nil
}

// GetArtifactRegistryService returns an Artifact Registry service
func GetArtifactRegistryService(ctx context.Context, session *gcpinternal.SafeSession) (*artifactregistry.Service, error) {
	service, err := artifactregistry.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Artifact Registry service: %w", err)
	}
	return service, nil
}

// GetContainerService returns a GKE Container service
func GetContainerService(ctx context.Context, session *gcpinternal.SafeSession) (*container.Service, error) {
	service, err := container.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create container service: %w", err)
	}
	return service, nil
}

// GetCloudRunService returns a Cloud Run service
func GetCloudRunService(ctx context.Context, session *gcpinternal.SafeSession) (*run.APIService, error) {
	service, err := run.NewService(ctx, session.GetClientOption())
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Run service: %w", err)
	}
	return service, nil
}

// ------------------------- CACHED CLIENT WRAPPERS -------------------------

// CachedGetStorageClient returns a cached Storage client
func CachedGetStorageClient(ctx context.Context, session *gcpinternal.SafeSession) (*storage.Client, error) {
	cacheKey := CacheKey("client", "storage")

	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*storage.Client), nil
	}

	client, err := GetStorageClient(ctx, session)
	if err != nil {
		return nil, err
	}

	GCPSDKCache.Set(cacheKey, client, 0)
	return client, nil
}

// CachedGetComputeService returns a cached Compute Engine service
func CachedGetComputeService(ctx context.Context, session *gcpinternal.SafeSession) (*compute.Service, error) {
	cacheKey := CacheKey("client", "compute")

	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*compute.Service), nil
	}

	service, err := GetComputeService(ctx, session)
	if err != nil {
		return nil, err
	}

	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetIAMService returns a cached IAM service
func CachedGetIAMService(ctx context.Context, session *gcpinternal.SafeSession) (*iam.Service, error) {
	cacheKey := CacheKey("client", "iam")

	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*iam.Service), nil
	}

	service, err := GetIAMService(ctx, session)
	if err != nil {
		return nil, err
	}

	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetResourceManagerService returns a cached Resource Manager service
func CachedGetResourceManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*cloudresourcemanager.Service, error) {
	cacheKey := CacheKey("client", "resourcemanager")

	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*cloudresourcemanager.Service), nil
	}

	service, err := GetResourceManagerService(ctx, session)
	if err != nil {
		return nil, err
	}

	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}

// CachedGetSecretManagerService returns a cached Secret Manager service
func CachedGetSecretManagerService(ctx context.Context, session *gcpinternal.SafeSession) (*secretmanager.Service, error) {
	cacheKey := CacheKey("client", "secretmanager")

	if cached, found := GCPSDKCache.Get(cacheKey); found {
		return cached.(*secretmanager.Service), nil
	}

	service, err := GetSecretManagerService(ctx, session)
	if err != nil {
		return nil, err
	}

	GCPSDKCache.Set(cacheKey, service, 0)
	return service, nil
}
