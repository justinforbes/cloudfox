package gcpinternal

// This file provides backward compatibility aliases for the unified AttackPathCache.
// All new code should use AttackPathCache and related types directly.

// PrivescMethod is kept for backward compatibility
// DEPRECATED: Use AttackMethod instead
type PrivescMethod = AttackMethod

// PrivescCache is an alias to AttackPathCache for backward compatibility
// DEPRECATED: Use AttackPathCache instead
type PrivescCache = AttackPathCache

// NewPrivescCache creates a new attack path cache (backward compatible)
// DEPRECATED: Use NewAttackPathCache instead
func NewPrivescCache() *AttackPathCache {
	return NewAttackPathCache()
}
