package gcpinternal

import (
	"context"
	"fmt"
	"strings"

	foxmapperservice "github.com/BishopFox/cloudfox/gcp/services/foxmapperService"
)

// FoxMapperCache wraps FoxMapperService for use by CloudFox modules
// This provides access to FoxMapper's graph-based privilege escalation analysis
type FoxMapperCache struct {
	service    *foxmapperservice.FoxMapperService
	populated  bool
	identifier string
}

// NewFoxMapperCache creates a new FoxMapper cache
func NewFoxMapperCache() *FoxMapperCache {
	return &FoxMapperCache{
		service: foxmapperservice.New(),
	}
}

// LoadFromOrg loads FoxMapper data for an organization
func (c *FoxMapperCache) LoadFromOrg(orgID string) error {
	err := c.service.LoadGraph(orgID, true)
	if err != nil {
		return err
	}
	c.populated = true
	c.identifier = orgID
	return nil
}

// LoadFromProject loads FoxMapper data for a project
func (c *FoxMapperCache) LoadFromProject(projectID string) error {
	err := c.service.LoadGraph(projectID, false)
	if err != nil {
		return err
	}
	c.populated = true
	c.identifier = projectID
	return nil
}

// LoadFromPath loads FoxMapper data from a custom path
func (c *FoxMapperCache) LoadFromPath(path string) error {
	err := c.service.LoadGraphFromPath(path)
	if err != nil {
		return err
	}
	c.populated = true
	c.identifier = path
	return nil
}

// TryLoad attempts to load FoxMapper data, trying org first then each project
func (c *FoxMapperCache) TryLoad(orgID string, projectIDs []string) error {
	// Try org first
	if orgID != "" {
		if err := c.LoadFromOrg(orgID); err == nil {
			return nil
		}
	}
	// Try each project
	for _, projectID := range projectIDs {
		if err := c.LoadFromProject(projectID); err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not load FoxMapper data for org %s or any of %d projects", orgID, len(projectIDs))
}

// IsPopulated returns whether the cache has data
func (c *FoxMapperCache) IsPopulated() bool {
	return c.populated
}

// GetAttackSummary returns attack path summary for a principal
func (c *FoxMapperCache) GetAttackSummary(principal string) string {
	if !c.populated {
		return "run foxmapper"
	}
	return c.service.GetAttackSummary(principal)
}

// DoesPrincipalHavePathToAdmin checks if principal can escalate to admin
func (c *FoxMapperCache) DoesPrincipalHavePathToAdmin(principal string) bool {
	if !c.populated {
		return false
	}
	return c.service.DoesPrincipalHavePathToAdmin(principal)
}

// IsPrincipalAdmin checks if principal is admin
func (c *FoxMapperCache) IsPrincipalAdmin(principal string) bool {
	if !c.populated {
		return false
	}
	return c.service.IsPrincipalAdmin(principal)
}

// GetPrivescPaths returns privesc paths for a principal
func (c *FoxMapperCache) GetPrivescPaths(principal string) []foxmapperservice.PrivescPath {
	if !c.populated {
		return nil
	}
	return c.service.GetPrivescPaths(principal)
}

// GetService returns the underlying FoxMapper service
func (c *FoxMapperCache) GetService() *foxmapperservice.FoxMapperService {
	return c.service
}

// GetStats returns statistics about the FoxMapper graph
func (c *FoxMapperCache) GetStats() (totalNodes, adminNodes, nodesWithPrivesc int) {
	if !c.populated || c.service == nil {
		return 0, 0, 0
	}
	summary := c.service.GetPrivescSummary()
	totalNodes = summary["total_nodes"].(int)
	adminNodes = summary["admin_nodes"].(int)
	nodesWithPrivesc = summary["nodes_with_privesc"].(int)
	return
}

// GetIdentifier returns the org/project ID this cache was loaded for
func (c *FoxMapperCache) GetIdentifier() string {
	return c.identifier
}

// HasPrivesc checks if a service account has privilege escalation potential
func (c *FoxMapperCache) HasPrivesc(serviceAccount string) (bool, string) {
	if !c.populated {
		return false, ""
	}

	node := c.service.GetNode(serviceAccount)
	if node == nil {
		return false, ""
	}

	if node.IsAdmin {
		return true, fmt.Sprintf("Admin (%s)", node.AdminLevel)
	}

	if node.PathToAdmin {
		paths := c.service.GetPrivescPaths(serviceAccount)
		if len(paths) > 0 {
			return true, fmt.Sprintf("Privesc (%d hops)", paths[0].HopCount)
		}
		return true, "Privesc"
	}

	return false, ""
}

// Context key for FoxMapper cache
type foxMapperCacheKey struct{}

// GetFoxMapperCacheFromContext retrieves the FoxMapper cache from context
func GetFoxMapperCacheFromContext(ctx context.Context) *FoxMapperCache {
	if cache, ok := ctx.Value(foxMapperCacheKey{}).(*FoxMapperCache); ok {
		return cache
	}
	return nil
}

// SetFoxMapperCacheInContext returns a new context with the FoxMapper cache
func SetFoxMapperCacheInContext(ctx context.Context, cache *FoxMapperCache) context.Context {
	return context.WithValue(ctx, foxMapperCacheKey{}, cache)
}

// TryLoadFoxMapper attempts to find and load FoxMapper data
// Returns the loaded cache or nil if not found
// If org-level graph exists, uses that. Otherwise, loads and merges all project graphs.
func TryLoadFoxMapper(orgID string, projectIDs []string) *FoxMapperCache {
	cache := NewFoxMapperCache()

	// Try org first - if it exists, it should contain all projects
	if orgID != "" {
		if err := cache.LoadFromOrg(orgID); err == nil {
			return cache
		}
	}

	// No org-level graph - try to load and merge all project graphs
	loadedCount := 0
	for _, projectID := range projectIDs {
		if loadedCount == 0 {
			// First project - load normally
			if err := cache.LoadFromProject(projectID); err == nil {
				loadedCount++
			}
		} else {
			// Subsequent projects - merge into existing graph
			path, err := foxmapperservice.FindFoxMapperData(projectID, false)
			if err == nil {
				if err := cache.service.MergeGraphFromPath(path); err == nil {
					loadedCount++
				}
			}
		}
	}

	// If we loaded multiple projects, rebuild the graph
	if loadedCount > 1 {
		cache.service.RebuildAfterMerge()
		cache.identifier = fmt.Sprintf("%d projects", loadedCount)
	}

	if loadedCount > 0 {
		return cache
	}

	return nil
}

// FindFoxMapperData searches for FoxMapper data and returns the path if found
func FindFoxMapperData(identifier string, isOrg bool) (string, error) {
	return foxmapperservice.FindFoxMapperData(identifier, isOrg)
}

// AttackSummaryProvider is an interface that FoxMapperCache implements
// This allows modules to use the cache interchangeably
type AttackSummaryProvider interface {
	IsPopulated() bool
	GetAttackSummary(principal string) string
}

// GetBestAttackSummary returns attack summary from FoxMapper
func GetBestAttackSummary(ctx context.Context, principal string) string {
	if fmCache := GetFoxMapperCacheFromContext(ctx); fmCache != nil && fmCache.IsPopulated() {
		return fmCache.GetAttackSummary(principal)
	}
	return "run foxmapper"
}

// All-checks mode context helper
type allChecksModeKey struct{}

// SetAllChecksMode sets a flag in context indicating all-checks mode is active
func SetAllChecksMode(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, allChecksModeKey{}, enabled)
}

// GetAllChecksMode checks if all-checks mode is active in context
func GetAllChecksMode(ctx context.Context) bool {
	if enabled, ok := ctx.Value(allChecksModeKey{}).(bool); ok {
		return enabled
	}
	return false
}

// GetAttackSummaryFromCaches returns attack summary using FoxMapper cache
// The second parameter is kept for backward compatibility but is ignored
func GetAttackSummaryFromCaches(foxMapperCache *FoxMapperCache, _ interface{}, principal string) string {
	// Clean the principal - remove prefixes if present
	cleanPrincipal := principal
	if strings.HasPrefix(principal, "serviceAccount:") {
		cleanPrincipal = strings.TrimPrefix(principal, "serviceAccount:")
	} else if strings.HasPrefix(principal, "user:") {
		cleanPrincipal = strings.TrimPrefix(principal, "user:")
	}

	// Use FoxMapper for graph-based analysis
	if foxMapperCache != nil && foxMapperCache.IsPopulated() {
		return foxMapperCache.GetAttackSummary(cleanPrincipal)
	}

	return "run foxmapper"
}
