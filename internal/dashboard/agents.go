package dashboard

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/protocol"
	"cf-anycast-router/internal/router"
)

type agentRegistry struct {
	mu     sync.RWMutex
	agents map[string]protocol.AgentSnapshot
	path   string
}

func newAgentRegistry(paths ...string) *agentRegistry {
	r := &agentRegistry{agents: map[string]protocol.AgentSnapshot{}}
	if len(paths) > 0 {
		r.path = strings.TrimSpace(paths[0])
	}
	r.load()
	return r
}

func (r *agentRegistry) upsert(report protocol.AgentReport) protocol.AgentSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := report.Result
	now := time.Now()
	firstSeen := now
	existing, exists := r.agents[report.AgentID]
	if exists && !existing.FirstSeen.IsZero() {
		firstSeen = existing.FirstSeen
	}
	if result == nil && exists {
		result = existing.Result
	}
	probeSource := strings.TrimSpace(report.ProbeSource)
	carrier := config.NormalizeCarrier(report.Carrier)
	displayName := ""
	managed := false
	status := strings.TrimSpace(report.Status)
	lastError := strings.TrimSpace(report.Error)
	if exists {
		displayName = existing.DisplayName
		managed = existing.Managed
		if managed {
			probeSource = existing.ProbeSource
			carrier = existing.Carrier
		}
		if status == "" {
			status = existing.Status
		}
		if report.Status == "" && report.Error == "" {
			lastError = existing.LastError
		}
	}
	snapshot := protocol.AgentSnapshot{
		AgentID:     report.AgentID,
		DisplayName: displayName,
		Hostname:    report.Hostname,
		ProbeSource: probeSource,
		Carrier:     carrier,
		Managed:     managed,
		Status:      status,
		LastError:   lastError,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		Result:      result,
	}
	if result != nil {
		snapshot.CandidateCount = len(result.Candidates)
		snapshot.Best = result.Best
	} else if exists {
		snapshot.CandidateCount = existing.CandidateCount
		snapshot.Best = existing.Best
	}
	r.agents[report.AgentID] = snapshot
	r.saveLocked()
	return snapshot
}

func (r *agentRegistry) configure(input protocol.AgentConfig) (protocol.AgentSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	input.AgentID = strings.TrimSpace(input.AgentID)
	if input.AgentID == "" {
		return protocol.AgentSnapshot{}, fmt.Errorf("agent_id is required")
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.ProbeSource = strings.TrimSpace(input.ProbeSource)
	input.Carrier = config.NormalizeCarrier(input.Carrier)
	if input.Carrier == "auto" {
		input.Carrier = config.InferCarrier(input.ProbeSource)
	}
	snapshot := r.agents[input.AgentID]
	snapshot.AgentID = input.AgentID
	snapshot.DisplayName = input.DisplayName
	snapshot.ProbeSource = input.ProbeSource
	snapshot.Carrier = input.Carrier
	snapshot.Managed = true
	r.agents[input.AgentID] = snapshot
	r.saveLocked()
	return snapshot, nil
}

func (r *agentRegistry) get(agentID string) (protocol.AgentSnapshot, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot, ok := r.agents[strings.TrimSpace(agentID)]
	return snapshot, ok
}

func (r *agentRegistry) remove(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	agentID = strings.TrimSpace(agentID)
	if _, ok := r.agents[agentID]; !ok {
		return false
	}
	delete(r.agents, agentID)
	r.saveLocked()
	return true
}

func (r *agentRegistry) load() {
	if r.path == "" {
		return
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var snapshots []protocol.AgentSnapshot
	if json.Unmarshal(data, &snapshots) != nil {
		return
	}
	for _, snapshot := range snapshots {
		if snapshot.AgentID != "" {
			r.agents[snapshot.AgentID] = snapshot
		}
	}
}

func (r *agentRegistry) saveLocked() {
	if r.path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		log.Printf("[agents] create registry directory: %v", err)
		return
	}
	snapshots := make([]protocol.AgentSnapshot, 0, len(r.agents))
	for _, snapshot := range r.agents {
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].AgentID < snapshots[j].AgentID })
	data, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		log.Printf("[agents] encode registry: %v", err)
		return
	}
	if err := os.WriteFile(r.path, append(data, '\n'), 0644); err != nil {
		log.Printf("[agents] save registry: %v", err)
	}
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

func (r *agentRegistry) candidatesByCarrier(carrier string, maxAge time.Duration) []router.Candidate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	carrier = config.NormalizeCarrier(carrier)
	cutoff := time.Now().Add(-maxAge)
	var out []router.Candidate
	for _, snapshot := range r.agents {
		if config.NormalizeCarrier(snapshot.Carrier) != carrier || snapshot.LastSeen.Before(cutoff) || snapshot.Result == nil {
			continue
		}
		out = append(out, snapshot.Result.Candidates...)
	}
	return out
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var input protocol.AgentConfig
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeJSON(w, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		snapshot, err := s.agents.configure(input)
		if err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "agent": snapshot})
		return
	}
	if r.Method == http.MethodDelete {
		agentID := strings.TrimSpace(r.URL.Query().Get("id"))
		if agentID == "" {
			writeJSON(w, map[string]string{"error": "agent id is required"})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "removed": s.agents.remove(agentID)})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	assignment := assignmentFromConfig(cfg)
	if snapshot, ok := s.agents.get(r.URL.Query().Get("agent_id")); ok && snapshot.Managed {
		assignment.ProbeSource = snapshot.ProbeSource
		assignment.Carrier = snapshot.Carrier
	}
	writeJSON(w, assignment)
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
		go s.updateAgentDNS(snapshot.Carrier)
	}
	writeJSON(w, map[string]any{"ok": true, "agent": snapshot})
}

func (s *Server) updateAgentDNS(carrier string) {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		log.Printf("[dns] load config after agent report: %v", err)
		return
	}
	maxAge := time.Duration(cfg.CheckIntervalSec*3) * time.Second
	if maxAge < 15*time.Minute {
		maxAge = 15 * time.Minute
	}
	for _, output := range router.UpdateRegionalDNS(cfg, carrier, s.agents.candidatesByCarrier(carrier, maxAge)) {
		log.Printf("[dns] %s", output)
	}
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
