package techniques

import "errors"

// Sentinel errors techniques return so the orchestration engine can map
// failures to stable, machine-readable reason codes on TechniqueErr without
// matching on error strings.
var (
	// ErrMissingAPIKey is returned by a technique whose required credentials
	// are absent from RunOptions.APIKeys. The engine ordinarily skips such
	// techniques before calling Run; this error covers the case where Run is
	// called directly (in tests, or by a future caller that bypasses the
	// engine's filtering).
	ErrMissingAPIKey = errors.New("missing API key")

	// ErrBudgetExhausted is returned by a technique whose Budget.Charge
	// reports false during a run. The engine maps it to reason
	// "budget_exhausted" on TechniqueErr.
	ErrBudgetExhausted = errors.New("budget exhausted")
)
