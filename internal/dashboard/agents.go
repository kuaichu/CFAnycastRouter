package dashboard

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/protocol"
)

type agentRegistry struct {
	mu     sync.RWMutex
	agents map[string]protocol.AgentSnapshot
}

func newAgentRegistry() *agentRegistry {
	return &agentRegistry{agents: map[string]protocol.AgentSnapshot{}}
}

func (r *agentRegistry) upsert(report protocol.AgentReport) protocol.AgentSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := report.Result
	snapshot := protocol.AgentSnapshot{
		AgentID:     report.AgentID,
		Hostname:    report.Hostname,
		ProbeSource: report.ProbeSource,
		Carrier:     report.Carrier,
		LastSeen:    time.Now(),
		Result:      result,
	}
	if result != nil {
		snapshot.CandidateCount = len(result.Candidates)
		snapshot.Best = result.Best
	}
	r.agents[report.AgentID] = snapshot
	return snapshot
}

func (r *agentRegistry) list() []protocol.AgentSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]protocol.AgentSnapshot, 0, len(r.agents))
	for _, snapshot := range r.agents {
		out = append(out, snapshot)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].AgentID < out[j].AgentID
	})
	return out
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"agents": s.agents.list()})
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAgent(w, r) {
		return
	}
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, assignmentFromConfig(cfg))
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorizeAgent(w, r) {
		return
	}
	var report protocol.AgentReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeJSON(w, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	report.AgentID = strings.TrimSpace(report.AgentID)
	if report.AgentID == "" {
		writeJSON(w, map[string]string{"error": "agent_id is required"})
		return
	}
	snapshot := s.agents.upsert(report)
	if report.Result != nil {
		s.SetLast(report.Result)
	}
	writeJSON(w, map[string]any{"ok": true, "agent": snapshot})
}

func (s *Server) authorizeAgent(w http.ResponseWriter, r *http.Request) bool {
	if s.agentTokenEnv == "" {
		return true
	}
	token := strings.TrimSpace(os.Getenv(s.agentTokenEnv))
	if token == "" {
		return true
	}
	if r.Header.Get("Authorization") == "Bearer "+token {
		return true
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func assignmentFromConfig(cfg *config.Config) protocol.AgentAssignment {
	return protocol.AgentAssignment{
		ServerTime:                   time.Now(),
		TraceHost:                    cfg.TraceHost,
		TracePath:                    cfg.TracePath,
		ProbePort:                    cfg.ProbePort,
		ProbeAttempts:                cfg.ProbeAttempts,
		ProbeTimeoutSeconds:          cfg.ProbeTimeoutSec,
		SpikeThresholdMs:             cfg.SpikeThreshold,
		SpikeMultiplier:              cfg.SpikeMultiplier,
		RouteTraceCommand:            cfg.RouteTraceCommand,
		RouteTraceArgs:               append([]string(nil), cfg.RouteTraceArgs...),
		MaxRouteTracesPerCycle:       cfg.MaxRouteTracesPerCycle,
		CheckIntervalSeconds:         cfg.CheckIntervalSec,
		SampleStep:                   cfg.SampleStep,
		SeedCIDRStep:                 cfg.SeedCIDRStep,
		SeedPreflightMaxPerCycle:     cfg.SeedPreflightMaxPerCycle,
		MaxSeedSegmentsPerCycle:      cfg.MaxSeedSegmentsPerCycle,
		MaxLearnedSegmentsPerCycle:   cfg.MaxLearnedSegmentsPerCycle,
		MaxSamplesPerSegmentPerCycle: cfg.MaxSamplesPerSegmentPerCycle,
		PromoteMinSamples:            cfg.PromoteMinSamples,
		PromotePOPProbability:        cfg.PromotePOPProbability,
		HotMaxPerSegment:             cfg.HotMaxPerSegment,
		HotMaxScore:                  cfg.HotMaxScore,
		PreferredPOPs:                append([]string(nil), cfg.PreferredPOPs...),
		SeedIPs:                      append([]string(nil), cfg.SeedIPs...),
		SeedCIDRs:                    append([]string(nil), cfg.SeedCIDRs...),
		SpeedTest:                    cfg.SpeedTest,
	}
}
