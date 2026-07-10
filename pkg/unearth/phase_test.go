package unearth

import (
	"context"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/techniques"
)

// consumerFake is a fakeTech that also satisfies the CandidateConsumer
// optional interface, so the engine sends it to phase 2 with seeded IPs.
type consumerFake struct {
	fakeTech
	consumes bool
	// seen captures the SeedIPs the engine populated, so the test can
	// assert phase 2 actually received pooled phase-1 IPs.
	seen []netip.Addr
	// emits is the candidate IP this technique itself produces. Set so
	// the test can also verify the consumer's own output is folded into
	// the result.
	emits string
}

func (c *consumerFake) ConsumesCandidates() bool { return c.consumes }

func (c *consumerFake) Run(ctx context.Context, target string, opts techniques.RunOptions) ([]techniques.Candidate, error) {
	c.seen = append([]netip.Addr(nil), opts.SeedIPs...)
	// Delegate to the embedded fakeTech so timing/error semantics match.
	out, err := c.fakeTech.Run(ctx, target, opts)
	if err != nil {
		return out, err
	}
	if c.emits != "" {
		out = append(out, techniques.Candidate{IP: c.emits, Evidence: "consumer-evidence"})
	}
	return out, nil
}

// confirmedConsumerFake runs after normal candidate consumers and should see
// only IPs that phase 2 marked as confirmed.
type confirmedConsumerFake struct {
	fakeTech
	consumes bool
	seen     []netip.Addr
	emits    string
}

func (c *confirmedConsumerFake) ConsumesConfirmedCandidates() bool { return c.consumes }

func (c *confirmedConsumerFake) Run(ctx context.Context, target string, opts techniques.RunOptions) ([]techniques.Candidate, error) {
	c.seen = append([]netip.Addr(nil), opts.SeedIPs...)
	out, err := c.fakeTech.Run(ctx, target, opts)
	if err != nil {
		return out, err
	}
	if c.emits != "" {
		out = append(out, techniques.Candidate{IP: c.emits, Evidence: "confirmed-consumer-evidence"})
	}
	return out, nil
}

func TestDiscover_TwoPhaseConsumerSeesProducerIPs(t *testing.T) {
	producer := &fakeTech{
		name: "producer", weight: 0.5, tier: techniques.TierPassive,
		candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "p1"},
			{IP: "203.0.113.2", Evidence: "p2"},
		},
	}
	consumer := &consumerFake{
		fakeTech: fakeTech{name: "consumer", weight: 0.85, tier: techniques.TierActive},
		consumes: true,
		emits:    "203.0.113.99",
	}
	withSelector(t, producer, consumer)

	opts := testOpts()
	opts.Tier = techniques.TierActive // include the active-tier consumer
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Consumer must have observed both producer IPs as seeds.
	if len(consumer.seen) != 2 {
		t.Fatalf("consumer SeedIPs len = %d, want 2 (%v)", len(consumer.seen), consumer.seen)
	}
	wantSeeds := []netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("203.0.113.2"),
	}
	sort.Slice(consumer.seen, func(i, j int) bool { return consumer.seen[i].Less(consumer.seen[j]) })
	for i, want := range wantSeeds {
		if consumer.seen[i] != want {
			t.Errorf("seed[%d]: want %s, got %s", i, want, consumer.seen[i])
		}
	}
	// Final result should fold the consumer's own emission too.
	var gotConsumerIP bool
	for _, c := range res.Candidates {
		if c.IP == "203.0.113.99" {
			gotConsumerIP = true
		}
	}
	if !gotConsumerIP {
		t.Errorf("consumer's own candidate missing from result: %+v", res.Candidates)
	}
}

func TestDiscover_ConfirmedConsumerSeesOnlyValidatedIPs(t *testing.T) {
	producer := &fakeTech{
		name: "producer", weight: 0.5, tier: techniques.TierPassive,
		candidates: []techniques.Candidate{
			{IP: "203.0.113.10", Evidence: "candidate"},
			{IP: "203.0.113.11", Evidence: "will-confirm"},
		},
	}
	validator := &consumerFake{
		fakeTech: fakeTech{
			name: "host_header", weight: 0.85, tier: techniques.TierActive,
			candidates: []techniques.Candidate{{
				IP:       "203.0.113.11",
				Evidence: "confirmed",
				Metadata: map[string]any{"validation": map[string]any{
					"status":    "confirmed",
					"technique": "host_header",
					"score":     0.82,
				}},
			}},
		},
		consumes: true,
	}
	confirmed := &confirmedConsumerFake{
		fakeTech: fakeTech{name: "neighbor_scan", weight: 0.78, tier: techniques.TierActive},
		consumes: true,
		emits:    "203.0.113.12",
	}
	withSelector(t, producer, validator, confirmed)

	opts := testOpts()
	opts.Tier = techniques.TierActive
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(confirmed.seen) != 1 || confirmed.seen[0] != netip.MustParseAddr("203.0.113.11") {
		t.Fatalf("confirmed consumer seeds = %v, want only 203.0.113.11", confirmed.seen)
	}
	found := false
	for _, c := range res.Candidates {
		if c.IP == "203.0.113.12" {
			found = true
		}
	}
	if !found {
		t.Fatalf("confirmed consumer output missing: %+v", res.Candidates)
	}
}

func TestDiscover_DisableNeighborScanSkipsTechnique(t *testing.T) {
	neighbor := &confirmedConsumerFake{
		fakeTech: fakeTech{name: "neighbor_scan", weight: 0.78, tier: techniques.TierActive},
		consumes: true,
		emits:    "203.0.113.12",
	}
	withSelector(t,
		&fakeTech{name: "p", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.11"}}},
		neighbor,
	)
	opts := testOpts()
	opts.Tier = techniques.TierActive
	opts.DisableNeighborScan = true
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if neighbor.ranOnce.Load() != 0 {
		t.Fatal("neighbor_scan should not run when disabled")
	}
	foundSkip := false
	for _, r := range res.TechniqueRuns {
		if r.Technique == "neighbor_scan" && r.Status == "skipped" && r.Reason == "disabled" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("disabled neighbor_scan run not recorded: %+v", res.TechniqueRuns)
	}
}

func TestDiscover_ConfirmedConsumerSkipsWithoutConfirmedSeeds(t *testing.T) {
	neighbor := &confirmedConsumerFake{
		fakeTech: fakeTech{name: "neighbor_scan", weight: 0.78, tier: techniques.TierActive},
		consumes: true,
	}
	withSelector(t,
		&fakeTech{name: "p", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.11"}}},
		neighbor,
	)
	opts := testOpts()
	opts.Tier = techniques.TierActive
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if neighbor.ranOnce.Load() != 0 {
		t.Fatal("confirmed consumer must not run without confirmed seeds")
	}
	foundSkip := false
	for _, r := range res.TechniqueRuns {
		if r.Technique == "neighbor_scan" && r.Status == "skipped" && r.Reason == "no_confirmed_candidates" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("missing no-confirmed-candidates skip: %+v", res.TechniqueRuns)
	}
}

func TestDiscover_PassiveOnlyHasEmptyPhase2(t *testing.T) {
	// A passive-only run must behave exactly like Packet 3: no consumer
	// gets selected, so phase 2 is empty and the run is fully parallel.
	p := &fakeTech{name: "p", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.10"}}}
	consumerNotInTier := &consumerFake{
		fakeTech: fakeTech{name: "c", weight: 0.5, tier: techniques.TierActive},
		consumes: true,
	}
	withSelector(t, p, consumerNotInTier)
	opts := testOpts() // Tier defaults to passive via DefaultOptions in withDefaults
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatal(err)
	}
	if consumerNotInTier.ranOnce.Load() != 0 {
		t.Errorf("active-tier consumer must NOT run under passive Tier")
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.10" {
		t.Errorf("passive result: %+v", res.Candidates)
	}
}

func TestDiscover_ConsumerWithoutOptInRunsInPhase1(t *testing.T) {
	// A technique that satisfies the CandidateConsumer interface but
	// returns false from ConsumesCandidates() must run in phase 1 — no
	// seeded IPs, parallel with the rest.
	optingOut := &consumerFake{
		fakeTech: fakeTech{name: "c", weight: 0.5, tier: techniques.TierActive},
		consumes: false,
		emits:    "203.0.113.20",
	}
	withSelector(t, optingOut)
	opts := testOpts()
	opts.Tier = techniques.TierActive
	res, _ := Discover(context.Background(), "x", opts)
	if len(optingOut.seen) != 0 {
		t.Errorf("opted-out consumer should not have received SeedIPs, got %v", optingOut.seen)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.20" {
		t.Errorf("candidate: %+v", res.Candidates)
	}
}

func TestDiscover_ConsumerStillBoundByPerTechniqueTimeout(t *testing.T) {
	// Phase 2 honors the same per-technique timeout as phase 1.
	slow := &consumerFake{
		fakeTech: fakeTech{
			name: "slow-consumer", weight: 0.5, tier: techniques.TierActive,
			delay: 5 * time.Second,
		},
		consumes: true,
	}
	withSelector(t,
		&fakeTech{name: "p", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.5"}}},
		slow,
	)
	opts := testOpts()
	opts.Tier = techniques.TierActive
	opts.PerTechniqueTimeout = 50 * time.Millisecond
	res, _ := Discover(context.Background(), "x", opts)
	foundTimeout := false
	for _, e := range res.Errors {
		if e.Technique == "slow-consumer" && e.Reason == "timeout" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Errorf("phase-2 timeout not surfaced: %+v", res.Errors)
	}
}

// timeoutOverrider satisfies techniques.TimeoutOverrider.
type timeoutOverrider struct {
	fakeTech
	override time.Duration
}

func (o *timeoutOverrider) TimeoutOverride() time.Duration { return o.override }

func TestDiscover_TimeoutOverride_LongerWins(t *testing.T) {
	// Technique sleeps 60ms; default per-technique is 20ms (would kill it);
	// override is 300ms (enough). Override must win.
	tech := &timeoutOverrider{
		fakeTech: fakeTech{
			name: "slow-with-override", weight: 0.5,
			delay:      60 * time.Millisecond,
			candidates: []techniques.Candidate{{IP: "203.0.113.42"}},
		},
		override: 300 * time.Millisecond,
	}
	withSelector(t, tech)
	opts := testOpts()
	opts.PerTechniqueTimeout = 20 * time.Millisecond
	opts.OverallTimeout = 5 * time.Second
	res, _ := Discover(context.Background(), "x", opts)
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.42" {
		t.Errorf("override should have kept the technique alive, got %+v / errors=%+v",
			res.Candidates, res.Errors)
	}
}

func TestDiscover_TimeoutOverride_NeverShortensBudget(t *testing.T) {
	// Override (10ms) is SHORTER than the configured PerTechniqueTimeout
	// (500ms). The engine must keep the longer 500ms — overrides only widen.
	tech := &timeoutOverrider{
		fakeTech: fakeTech{
			name: "fast-with-tiny-override", weight: 0.5,
			delay:      100 * time.Millisecond,
			candidates: []techniques.Candidate{{IP: "203.0.113.43"}},
		},
		override: 10 * time.Millisecond,
	}
	withSelector(t, tech)
	opts := testOpts()
	opts.PerTechniqueTimeout = 500 * time.Millisecond
	res, _ := Discover(context.Background(), "x", opts)
	if len(res.Candidates) != 1 {
		t.Errorf("tiny override must not shorten budget, got %+v / %+v", res.Candidates, res.Errors)
	}
}

func TestDiscover_TimeoutOverride_StillBoundedByOverall(t *testing.T) {
	// OverallTimeout is small enough that even the technique's override
	// can't save it. The technique must still time out.
	tech := &timeoutOverrider{
		fakeTech: fakeTech{
			name: "slow", weight: 0.5,
			delay: 2 * time.Second,
		},
		override: 10 * time.Second, // would normally allow this
	}
	withSelector(t, tech)
	opts := testOpts()
	opts.PerTechniqueTimeout = 1 * time.Second
	opts.OverallTimeout = 100 * time.Millisecond
	res, _ := Discover(context.Background(), "x", opts)
	foundTimeout := false
	for _, e := range res.Errors {
		if e.Reason == "timeout" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Errorf("overall timeout should bound an override; got errors=%+v", res.Errors)
	}
}

func TestDiscover_ExistingTechniquesUnaffectedByTimeoutSupport(t *testing.T) {
	// A plain fakeTech that does NOT implement TimeoutOverrider must
	// behave identically to Packet 5A: gets the configured default.
	tech := &fakeTech{
		name: "plain", weight: 0.5,
		delay:      30 * time.Millisecond,
		candidates: []techniques.Candidate{{IP: "203.0.113.44"}},
	}
	withSelector(t, tech)
	opts := testOpts()
	opts.PerTechniqueTimeout = 100 * time.Millisecond
	res, _ := Discover(context.Background(), "x", opts)
	if len(res.Candidates) != 1 {
		t.Errorf("non-overrider should still produce its candidate, got %+v / %+v",
			res.Candidates, res.Errors)
	}
}

func TestDiscover_TierInsufficientReason(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "t", weight: 0.5, err: techniques.ErrTierInsufficient},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if len(res.Errors) != 1 || res.Errors[0].Reason != "tier_insufficient" {
		t.Errorf("expected tier_insufficient reason, got %+v", res.Errors)
	}
}
