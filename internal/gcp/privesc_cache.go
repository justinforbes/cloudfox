package gcpinternal

import (
	"context"
	"strings"
	"sync"
)

// PrivescCache holds cached privilege escalation analysis results
// This allows modules to quickly check if a service account or principal has privesc potential
// without re-running the full analysis
type PrivescCache struct {
	// ServiceAccountPrivesc maps service account email -> list of privesc methods
	// Example: "sa@project.iam.gserviceaccount.com" -> ["CreateServiceAccountKey", "GetServiceAccountAccessToken"]
	ServiceAccountPrivesc map[string][]PrivescMethod

	// PrincipalPrivesc maps any principal (user, group, SA) -> list of privesc methods
	// This includes the full principal string like "serviceAccount:sa@project.iam.gserviceaccount.com"
	PrincipalPrivesc map[string][]PrivescMethod

	// Populated indicates whether the cache has been populated with privesc data
	Populated bool

	mu sync.RWMutex
}

// PrivescMethod represents a single privilege escalation method
type PrivescMethod struct {
	Method      string   // e.g., "CreateServiceAccountKey", "GetServiceAccountAccessToken"
	RiskLevel   string   // "CRITICAL", "HIGH", "MEDIUM"
	Target      string   // What the method targets
	Permissions []string // Permissions that enable this method
}

// NewPrivescCache creates a new empty privesc cache
func NewPrivescCache() *PrivescCache {
	return &PrivescCache{
		ServiceAccountPrivesc: make(map[string][]PrivescMethod),
		PrincipalPrivesc:      make(map[string][]PrivescMethod),
		Populated:             false,
	}
}

// AddPrivescPath adds a privilege escalation path to the cache
// principal should be the full member string (e.g., "serviceAccount:sa@project.iam.gserviceaccount.com")
func (c *PrivescCache) AddPrivescPath(principal string, method PrivescMethod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Add to principal map
	c.PrincipalPrivesc[principal] = append(c.PrincipalPrivesc[principal], method)

	// If it's a service account, also add to the SA-specific map
	if strings.HasPrefix(principal, "serviceAccount:") {
		email := strings.TrimPrefix(principal, "serviceAccount:")
		c.ServiceAccountPrivesc[email] = append(c.ServiceAccountPrivesc[email], method)
	}

	// Also check if the principal itself looks like an email (for cleaned member names)
	if strings.Contains(principal, "@") && strings.Contains(principal, ".iam.gserviceaccount.com") {
		c.ServiceAccountPrivesc[principal] = append(c.ServiceAccountPrivesc[principal], method)
	}
}

// MarkPopulated marks the cache as populated
func (c *PrivescCache) MarkPopulated() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Populated = true
}

// IsPopulated returns whether the cache has been populated
func (c *PrivescCache) IsPopulated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Populated
}

// HasPrivesc checks if a service account has any privilege escalation potential
// Returns (hasPrivesc bool, methods []PrivescMethod)
func (c *PrivescCache) HasPrivesc(serviceAccount string) (bool, []PrivescMethod) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check direct match
	if methods, ok := c.ServiceAccountPrivesc[serviceAccount]; ok && len(methods) > 0 {
		return true, methods
	}

	// Check with serviceAccount: prefix
	prefixed := "serviceAccount:" + serviceAccount
	if methods, ok := c.PrincipalPrivesc[prefixed]; ok && len(methods) > 0 {
		return true, methods
	}

	return false, nil
}

// HasPrivescForPrincipal checks if any principal (user, group, SA) has privesc potential
func (c *PrivescCache) HasPrivescForPrincipal(principal string) (bool, []PrivescMethod) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if methods, ok := c.PrincipalPrivesc[principal]; ok && len(methods) > 0 {
		return true, methods
	}

	return false, nil
}

// GetPrivescSummary returns a summary string for a service account's privesc potential
// Returns: "Yes (3)" for 3 methods, "No" if none, "-" if cache not populated
func (c *PrivescCache) GetPrivescSummary(serviceAccount string) string {
	if !c.IsPopulated() {
		return "-"
	}

	hasPrivesc, methods := c.HasPrivesc(serviceAccount)
	if !hasPrivesc || len(methods) == 0 {
		return "No"
	}

	return "Yes"
}

// GetPrivescSummaryWithCount returns a summary string with count
// Returns: "Yes (3)" for 3 methods, "No" if none, "-" if cache not populated
func (c *PrivescCache) GetPrivescSummaryWithCount(serviceAccount string) string {
	if !c.IsPopulated() {
		return "-"
	}

	hasPrivesc, methods := c.HasPrivesc(serviceAccount)
	if !hasPrivesc || len(methods) == 0 {
		return "No"
	}

	// Count unique methods
	uniqueMethods := make(map[string]bool)
	for _, m := range methods {
		uniqueMethods[m.Method] = true
	}

	if len(uniqueMethods) == 1 {
		return "Yes (1)"
	}
	return "Yes (" + string(rune('0'+len(uniqueMethods))) + ")"
}

// GetHighestRiskLevel returns the highest risk level for a service account
// Returns: "CRITICAL", "HIGH", "MEDIUM", or "" if no privesc
func (c *PrivescCache) GetHighestRiskLevel(serviceAccount string) string {
	hasPrivesc, methods := c.HasPrivesc(serviceAccount)
	if !hasPrivesc {
		return ""
	}

	riskOrder := map[string]int{"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
	highestRisk := ""
	highestOrder := -1

	for _, m := range methods {
		if order, ok := riskOrder[m.RiskLevel]; ok && order > highestOrder {
			highestOrder = order
			highestRisk = m.RiskLevel
		}
	}

	return highestRisk
}

// GetMethodNames returns a list of unique method names for a service account
func (c *PrivescCache) GetMethodNames(serviceAccount string) []string {
	hasPrivesc, methods := c.HasPrivesc(serviceAccount)
	if !hasPrivesc {
		return nil
	}

	uniqueMethods := make(map[string]bool)
	var result []string
	for _, m := range methods {
		if !uniqueMethods[m.Method] {
			uniqueMethods[m.Method] = true
			result = append(result, m.Method)
		}
	}

	return result
}

// PrivescPathInfo is a minimal representation of a privesc path for cache population
// This allows the cache to be populated without importing the privescService package
type PrivescPathInfo struct {
	Principal     string
	PrincipalType string
	Method        string
	RiskLevel     string
	Target        string
	Permissions   []string
}

// PopulateFromPaths populates the cache from a list of privesc path info
func (c *PrivescCache) PopulateFromPaths(paths []PrivescPathInfo) {
	for _, path := range paths {
		method := PrivescMethod{
			Method:      path.Method,
			RiskLevel:   path.RiskLevel,
			Target:      path.Target,
			Permissions: path.Permissions,
		}

		// Build the full principal string
		principal := path.Principal
		if path.PrincipalType == "serviceAccount" && !strings.HasPrefix(principal, "serviceAccount:") {
			principal = "serviceAccount:" + principal
		} else if path.PrincipalType == "user" && !strings.HasPrefix(principal, "user:") {
			principal = "user:" + principal
		} else if path.PrincipalType == "group" && !strings.HasPrefix(principal, "group:") {
			principal = "group:" + principal
		}

		c.AddPrivescPath(principal, method)
	}
	c.MarkPopulated()
}

// Context key for privesc cache
type privescCacheKey struct{}

// GetPrivescCacheFromContext retrieves the privesc cache from context
func GetPrivescCacheFromContext(ctx context.Context) *PrivescCache {
	if cache, ok := ctx.Value(privescCacheKey{}).(*PrivescCache); ok {
		return cache
	}
	return nil
}

// SetPrivescCacheInContext returns a new context with the privesc cache
func SetPrivescCacheInContext(ctx context.Context, cache *PrivescCache) context.Context {
	return context.WithValue(ctx, privescCacheKey{}, cache)
}
