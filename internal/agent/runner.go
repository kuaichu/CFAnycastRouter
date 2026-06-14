package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/history"
	"cf-anycast-router/internal/protocol"
	"cf-anycast-router/internal/router"
)

type Runner struct {
	cfg    *config.Config
	state  *history.State
	router *router.Router
	client *http.Client
}

func New(cfg *config.Config, st *history.State, rt *router.Router) *Runner {
	return &Runner{
		cfg:    cfg,
		state:  st,
		router: rt,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *Runner) Run(ctx context.Context) error {
	if r.cfg.ServerURL == "" {
		return fmt.Errorf("server_url is required in agent mode")
	}
	agentID := r.agentID()
	log.Printf("[agent] id=%s server=%s", agentID, r.cfg.ServerURL)
	for {
		if err := r.runOnce(ctx, agentID); err != nil {
			log.Printf("[agent] cycle failed: %v", err)
		}
		interval := r.cfg.CheckInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		log.Printf("[agent] next report in %s", interval)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (r *Runner) runOnce(ctx context.Context, agentID string) error {
	assignment, err := r.fetchAssignment(ctx, agentID)
	if err != nil {
		return err
	}
	r.applyAssignment(assignment)
	if len(r.cfg.SeedIPs) == 0 && len(r.cfg.SeedCIDRs) == 0 {
		return fmt.Errorf("server returned no seed targets")
	}
	candidates := r.router.Evaluate()
	if err := r.state.Save(r.cfg.StatePath); err != nil {
		return err
	}
	result := &router.CycleResult{
		Time:       time.Now(),
		Carrier:    r.cfg.Carrier,
		CurrentIP:  r.state.CurrentIP,
		Best:       bestCandidate(candidates),
		Decision:   "agent measurement report",
		Candidates: candidates,
	}
	return r.postReport(ctx, protocol.AgentReport{
		AgentID:     agentID,
		Hostname:    hostname(),
		ProbeSource: r.cfg.ProbeSource,
		Carrier:     r.cfg.Carrier,
		Time:        result.Time,
		Result:      result,
	})
}

func (r *Runner) fetchAssignment(ctx context.Context, agentID string) (protocol.AgentAssignment, error) {
	u, err := url.Parse(r.cfg.ServerURL + "/api/agent/config")
	if err != nil {
		return protocol.AgentAssignment{}, err
	}
	q := u.Query()
	q.Set("agent_id", agentID)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return protocol.AgentAssignment{}, err
	}
	r.authorize(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return protocol.AgentAssignment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return protocol.AgentAssignment{}, fmt.Errorf("assignment request failed: %s", resp.Status)
	}
	var assignment protocol.AgentAssignment
	if err := json.NewDecoder(resp.Body).Decode(&assignment); err != nil {
		return protocol.AgentAssignment{}, err
	}
	return assignment, nil
}

func (r *Runner) postReport(ctx context.Context, report protocol.AgentReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.ServerURL+"/api/agent/report", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.authorize(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report failed: %s", resp.Status)
	}
	log.Printf("[agent] reported %d candidates", len(report.Result.Candidates))
	return nil
}

func (r *Runner) authorize(req *http.Request) {
	if token := strings.TrimSpace(os.Getenv(r.cfg.AgentTokenEnv)); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func (r *Runner) applyAssignment(a protocol.AgentAssignment) {
	if a.TraceHost != "" {
		r.cfg.TraceHost = a.TraceHost
	}
	if a.TracePath != "" {
		r.cfg.TracePath = a.TracePath
	}
	if a.ProbePort > 0 {
		r.cfg.ProbePort = a.ProbePort
	}
	if a.ProbeAttempts > 0 {
		r.cfg.ProbeAttempts = a.ProbeAttempts
	}
	if a.ProbeTimeoutSeconds > 0 {
		r.cfg.ProbeTimeoutSec = a.ProbeTimeoutSeconds
		r.cfg.ProbeTimeout = time.Duration(a.ProbeTimeoutSeconds) * time.Second
	}
	if a.SpikeThresholdMs > 0 {
		r.cfg.SpikeThreshold = a.SpikeThresholdMs
	}
	if a.SpikeMultiplier > 0 {
		r.cfg.SpikeMultiplier = a.SpikeMultiplier
	}
	r.cfg.RouteTraceCommand = a.RouteTraceCommand
	r.cfg.RouteTraceArgs = a.RouteTraceArgs
	if a.MaxRouteTracesPerCycle > 0 {
		r.cfg.MaxRouteTracesPerCycle = a.MaxRouteTracesPerCycle
	}
	if a.CheckIntervalSeconds > 0 {
		r.cfg.CheckIntervalSec = a.CheckIntervalSeconds
		r.cfg.CheckInterval = time.Duration(a.CheckIntervalSeconds) * time.Second
	}
	if a.SampleStep > 0 {
		r.cfg.SampleStep = a.SampleStep
	}
	if a.SeedCIDRStep > 0 {
		r.cfg.SeedCIDRStep = a.SeedCIDRStep
	}
	if a.SeedPreflightMaxPerCycle > 0 {
		r.cfg.SeedPreflightMaxPerCycle = a.SeedPreflightMaxPerCycle
	}
	if a.MaxSeedSegmentsPerCycle > 0 {
		r.cfg.MaxSeedSegmentsPerCycle = a.MaxSeedSegmentsPerCycle
	}
	if a.MaxLearnedSegmentsPerCycle >= 0 {
		r.cfg.MaxLearnedSegmentsPerCycle = a.MaxLearnedSegmentsPerCycle
	}
	if a.MaxSamplesPerSegmentPerCycle > 0 {
		r.cfg.MaxSamplesPerSegmentPerCycle = a.MaxSamplesPerSegmentPerCycle
	}
	if a.PromoteMinSamples > 0 {
		r.cfg.PromoteMinSamples = a.PromoteMinSamples
	}
	if a.PromotePOPProbability > 0 {
		r.cfg.PromotePOPProbability = a.PromotePOPProbability
	}
	if a.HotMaxPerSegment > 0 {
		r.cfg.HotMaxPerSegment = a.HotMaxPerSegment
	}
	if a.HotMaxScore > 0 {
		r.cfg.HotMaxScore = a.HotMaxScore
	}
	if len(a.PreferredPOPs) > 0 {
		r.cfg.PreferredPOPs = make([]string, len(a.PreferredPOPs))
		for i, pop := range a.PreferredPOPs {
			r.cfg.PreferredPOPs[i] = config.NormalizePOP(pop)
		}
	}
	r.cfg.SeedIPs = append([]string(nil), a.SeedIPs...)
	r.cfg.SeedCIDRs = append([]string(nil), a.SeedCIDRs...)
	r.cfg.SpeedTest = a.SpeedTest
}

func (r *Runner) agentID() string {
	if r.cfg.AgentID != "" {
		return r.cfg.AgentID
	}
	if h := hostname(); h != "" {
		return h
	}
	return "agent"
}

func hostname() string {
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}

func bestCandidate(candidates []router.Candidate) *router.Candidate {
	for i := range candidates {
		c := candidates[i]
		if c.Error == "" && !c.Quarantined && c.Region != "" && c.Region != "unknown" && !math.IsInf(c.Score, 0) {
			return &c
		}
	}
	return nil
}
