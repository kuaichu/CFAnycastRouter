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
	"sort"
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
	paused bool
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
			errorCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if reportErr := r.postReport(errorCtx, r.newReport(agentID, "error", err.Error(), nil)); reportErr != nil {
				log.Printf("[agent] error status report failed: %v", reportErr)
			}
			cancel()
		}
		interval := r.cfg.CheckInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		if r.paused {
			interval = 15 * time.Second
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
	r.paused = assignment.Paused
	if assignment.Paused {
		log.Printf("[agent] paused by server")
		return r.postReport(ctx, r.newReport(agentID, "paused", "", nil))
	}
	if err := r.postReport(ctx, r.newReport(agentID, "scanning", "", nil)); err != nil {
		return fmt.Errorf("register agent: %w", err)
	}
	if len(r.cfg.SeedIPs) == 0 && len(r.cfg.SeedCIDRs) == 0 {
		return fmt.Errorf("server returned no seed targets")
	}
	progress := make(chan router.Candidate, 128)
	progressDone := make(chan struct{})
	r.router.SetProgress(func(candidate router.Candidate) {
		select {
		case progress <- candidate:
		default:
		}
	})
	go r.reportProgress(ctx, agentID, progress, progressDone)
	candidates := r.router.Evaluate()
	r.router.SetProgress(nil)
	close(progress)
	<-progressDone
	if err := r.state.Save(r.cfg.StatePath); err != nil {
		log.Printf("[agent] save local state failed; reporting measurement anyway: %v", err)
	}
	result := &router.CycleResult{
		Time:       time.Now(),
		Carrier:    r.cfg.Carrier,
		CurrentIP:  r.state.CurrentIP,
		Best:       bestCandidate(candidates),
		Decision:   "agent measurement report",
		Candidates: candidates,
	}
	return r.postReport(ctx, r.newReport(agentID, "idle", "", result))
}

func (r *Runner) newReport(agentID, status, errorText string, result *router.CycleResult) protocol.AgentReport {
	return protocol.AgentReport{
		AgentID:     agentID,
		Hostname:    hostname(),
		ProbeSource: r.cfg.ProbeSource,
		Carrier:     r.cfg.Carrier,
		Status:      status,
		Error:       errorText,
		Time:        time.Now(),
		Result:      result,
	}
}

func (r *Runner) reportProgress(ctx context.Context, agentID string, input <-chan router.Candidate, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	candidates := map[string]router.Candidate{}
	dirty := false
	for {
		select {
		case candidate, ok := <-input:
			if !ok {
				return
			}
			candidates[candidate.IP] = candidate
			dirty = true
		case <-ticker.C:
			if !dirty || len(candidates) == 0 {
				continue
			}
			partial := make([]router.Candidate, 0, len(candidates))
			for _, candidate := range candidates {
				partial = append(partial, candidate)
			}
			sort.Slice(partial, func(i, j int) bool { return partial[i].IP < partial[j].IP })
			reportCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := r.postReport(reportCtx, r.newReport(agentID, "scanning", "", &router.CycleResult{
				Time:       time.Now(),
				Carrier:    r.cfg.Carrier,
				CurrentIP:  r.state.CurrentIP,
				Decision:   fmt.Sprintf("agent scanning: %d candidates completed", len(partial)),
				Candidates: partial,
			}))
			cancel()
			if err != nil {
				log.Printf("[agent] progress report failed: %v", err)
			} else {
				dirty = false
			}
		case <-ctx.Done():
			return
		}
	}
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
	report.Result = router.JSONSafeCycleResult(report.Result)
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
	if report.Result == nil {
		log.Printf("[agent] registered")
	} else {
		log.Printf("[agent] reported %d candidates", len(report.Result.Candidates))
	}
	return nil
}

func (r *Runner) authorize(req *http.Request) {
	if token := strings.TrimSpace(os.Getenv(r.cfg.AgentTokenEnv)); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func (r *Runner) applyAssignment(a protocol.AgentAssignment) {
	if a.ProbeSource != "" {
		r.cfg.ProbeSource = a.ProbeSource
	}
	if a.Carrier != "" {
		r.cfg.Carrier = config.NormalizeCarrier(a.Carrier)
	}
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
	r.cfg.SampleAllSeedSegments = a.SampleAllSeedSegments
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
		if c.Error == "" && !c.Quarantined && selectableStage(c.Stage) && c.Region != "" && c.Region != "unknown" && c.Region != "preflight" && !math.IsInf(c.Score, 0) {
			return &c
		}
	}
	return nil
}

func selectableStage(stage string) bool {
	switch stage {
	case "seed", "seed-sample", "learned", "hot", "lookup-reference", "lookup-sample":
		return true
	default:
		return false
	}
}
