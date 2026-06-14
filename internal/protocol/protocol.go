package protocol

import (
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/router"
)

type AgentAssignment struct {
	ServerTime                   time.Time              `json:"server_time"`
	TraceHost                    string                 `json:"trace_host"`
	TracePath                    string                 `json:"trace_path"`
	ProbePort                    int                    `json:"probe_port"`
	ProbeAttempts                int                    `json:"probe_attempts"`
	ProbeTimeoutSeconds          int                    `json:"probe_timeout_seconds"`
	SpikeThresholdMs             float64                `json:"spike_threshold_ms"`
	SpikeMultiplier              float64                `json:"spike_multiplier"`
	RouteTraceCommand            string                 `json:"route_trace_command"`
	RouteTraceArgs               []string               `json:"route_trace_args"`
	MaxRouteTracesPerCycle       int                    `json:"max_route_traces_per_cycle"`
	CheckIntervalSeconds         int                    `json:"check_interval_seconds"`
	SampleStep                   int                    `json:"sample_step"`
	SeedCIDRStep                 int                    `json:"seed_cidr_step"`
	SeedPreflightMaxPerCycle     int                    `json:"seed_preflight_max_per_cycle"`
	MaxSeedSegmentsPerCycle      int                    `json:"max_seed_segments_per_cycle"`
	MaxLearnedSegmentsPerCycle   int                    `json:"max_learned_segments_per_cycle"`
	MaxSamplesPerSegmentPerCycle int                    `json:"max_samples_per_segment_per_cycle"`
	PromoteMinSamples            int                    `json:"promote_min_samples"`
	PromotePOPProbability        float64                `json:"promote_pop_probability"`
	HotMaxPerSegment             int                    `json:"hot_max_per_segment"`
	HotMaxScore                  float64                `json:"hot_max_score"`
	PreferredPOPs                []string               `json:"preferred_pops"`
	SeedIPs                      []string               `json:"seed_ips"`
	SeedCIDRs                    []string               `json:"seed_cidrs"`
	SpeedTest                    config.SpeedTestConfig `json:"speed_test"`
}

type AgentReport struct {
	AgentID     string              `json:"agent_id"`
	Hostname    string              `json:"hostname"`
	ProbeSource string              `json:"probe_source"`
	Carrier     string              `json:"carrier"`
	Time        time.Time           `json:"time"`
	Result      *router.CycleResult `json:"result"`
}

type AgentSnapshot struct {
	AgentID        string              `json:"agent_id"`
	Hostname       string              `json:"hostname"`
	ProbeSource    string              `json:"probe_source"`
	Carrier        string              `json:"carrier"`
	LastSeen       time.Time           `json:"last_seen"`
	CandidateCount int                 `json:"candidate_count"`
	Best           *router.Candidate   `json:"best,omitempty"`
	Result         *router.CycleResult `json:"result,omitempty"`
}
