package techniques

import "sort"

// registry holds every technique registered at init time, keyed by Name.
var registry = map[string]Technique{}

// Register adds a technique to the global registry. It panics if a technique
// with the same Name is already registered, since that indicates a
// programming error that should be caught at process start.
func Register(t Technique) {
	name := t.Name()
	if _, exists := registry[name]; exists {
		panic("techniques: duplicate registration for " + name)
	}
	registry[name] = t
}

// All returns every registered technique, sorted by Name for deterministic
// ordering.
func All() []Technique {
	out := make([]Technique, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name() < out[j].Name()
	})
	return out
}

// Get returns the technique registered under name.
func Get(name string) (Technique, bool) {
	t, ok := registry[name]
	return t, ok
}

// ByTier returns every registered technique whose Tier is at or below maxTier,
// sorted by Name. ByTier(TierPassive) yields passive techniques only;
// ByTier(TierAggressive) yields all techniques.
func ByTier(maxTier Tier) []Technique {
	var out []Technique
	for _, t := range All() {
		if t.Tier() <= maxTier {
			out = append(out, t)
		}
	}
	return out
}
