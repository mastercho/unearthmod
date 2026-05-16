package cache_test

import (
	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

// Compile-time assertion that *cache.Cache satisfies the
// techniques.CacheStore contract. Living here (external test package)
// instead of pkg/cache/cache.go keeps pkg/cache free of an import of
// pkg/techniques, which would form a real import cycle now that
// techniques.Run uses cache.Key.
var _ techniques.CacheStore = (*cache.Cache)(nil)
