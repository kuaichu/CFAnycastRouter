package dashboard

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/router"
)

const resultHistoryRetention = 35 * 24 * time.Hour

type resultHistoryPoint struct {
	Time       time.Time `json:"time"`
	Carrier    string    `json:"carrier"`
	Region     string    `json:"region"`
	RouteIP    string    `json:"route_ip,omitempty"`
	PingRTTMs  float64   `json:"ping_rtt_ms,omitempty"`
	SpeedIP    string    `json:"speed_ip,omitempty"`
	SpeedRTTMs float64   `json:"speed_rtt_ms,omitempty"`
	SpeedMbps  float64   `json:"speed_mbps,omitempty"`
	Score      float64   `json:"score,omitempty"`
	Agent      string    `json:"agent,omitempty"`
	Status     string    `json:"status,omitempty"`
}

type resultHistoryStore struct {
	mu   sync.Mutex
	path string
}

func newResultHistoryStore(path string) *resultHistoryStore {
	return &resultHistoryStore{path: strings.TrimSpace(path)}
}

func (s *resultHistoryStore) append(points []resultHistoryPoint, now time.Time) error {
	if s == nil || s.path == "" || len(points) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.loadLocked()
	if err != nil {
		return err
	}
	cutoff := now.Add(-resultHistoryRetention)
	kept := make([]resultHistoryPoint, 0, len(existing)+len(points))
	for _, point := range existing {
		if !point.Time.Before(cutoff) {
			kept = append(kept, point)
		}
	}
	kept = append(kept, points...)
	sort.Slice(kept, func(i, j int) bool { return kept[i].Time.Before(kept[j].Time) })
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(data, '\n'), 0644)
}

func (s *resultHistoryStore) query(since time.Time, carrier string) ([]resultHistoryPoint, error) {
	if s == nil || s.path == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	points, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	carrier = config.NormalizeCarrier(carrier)
	out := make([]resultHistoryPoint, 0, len(points))
	for _, point := range points {
		if point.Time.Before(since) {
			continue
		}
		if carrier != "" && carrier != "auto" && config.NormalizeCarrier(point.Carrier) != carrier {
			continue
		}
		out = append(out, point)
	}
	return out, nil
}

func (s *resultHistoryStore) loadLocked() ([]resultHistoryPoint, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var points []resultHistoryPoint
	if err := json.Unmarshal(data, &points); err != nil {
		return nil, err
	}
	return points, nil
}

func (s *Server) recordResultHistory(carrier string) {
	if s.history == nil {
		return
	}
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		log.Printf("[history] load config after agent report: %v", err)
		return
	}
	maxAge := time.Duration(cfg.CheckIntervalSec*3) * time.Second
	if maxAge < 15*time.Minute {
		maxAge = 15 * time.Minute
	}
	now := time.Now()
	points := buildResultHistoryPoints(now, cfg, carrier, s.agents.sourcedCandidatesByCarrier(carrier, maxAge))
	if err := s.history.append(points, now); err != nil {
		log.Printf("[history] append result history: %v", err)
	}
}

func (s *Server) handleResultHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, duration := parseHistoryRange(r.URL.Query().Get("range"))
	since := time.Now().Add(-duration)
	points, err := s.history.query(since, r.URL.Query().Get("carrier"))
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"range": name, "since": since, "points": points})
}

func parseHistoryRange(value string) (string, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1h":
		return "1h", time.Hour
	case "7d":
		return "7d", 7 * 24 * time.Hour
	case "30d":
		return "30d", 30 * 24 * time.Hour
	default:
		return "24h", 24 * time.Hour
	}
}

func buildResultHistoryPoints(now time.Time, cfg *config.Config, carrier string, candidates []sourcedCandidate) []resultHistoryPoint {
	carrier = config.NormalizeCarrier(carrier)
	regions := finalHistoryRegions(cfg, carrier, candidates)
	points := make([]resultHistoryPoint, 0, len(regions))
	for _, region := range regions {
		route := bestHistoryRoute(candidates, region)
		if route == nil {
			continue
		}
		speed := bestHistorySpeed(candidates, region)
		ping := route.PingRTTMs
		if ping <= 0 {
			ping = route.AvgRTTMs
		}
		point := resultHistoryPoint{
			Time:      now,
			Carrier:   carrier,
			Region:    region,
			RouteIP:   route.IP,
			PingRTTMs: ping,
			Score:     route.Score,
			Agent:     route.Agent,
			Status:    "推荐",
		}
		if speed != nil {
			point.SpeedIP = speed.IP
			point.SpeedRTTMs = speed.CFSpeedRTTMs
			point.SpeedMbps = speed.CFSpeedMbps
			if speed.Agent != "" && speed.Agent != point.Agent {
				if point.Agent == "" {
					point.Agent = speed.Agent
				} else {
					point.Agent += " / " + speed.Agent
				}
			}
			if speed.CFSpeedTested && (speed.CFSpeedRTTMs <= 0 || speed.CFSpeedError != "") {
				point.Status = "测速失败"
			}
		}
		points = append(points, point)
	}
	return points
}

func finalHistoryRegions(cfg *config.Config, carrier string, candidates []sourcedCandidate) []string {
	set := map[string]struct{}{"HK": {}, "US": {}, "JP": {}, "SG": {}}
	if cfg != nil {
		for _, record := range cfg.CloudflareDNS.CarrierRegionRecords(carrier) {
			if record.Enabled == false || strings.ToUpper(strings.TrimSpace(record.Type)) != "A" {
				continue
			}
			if region := historyKnownRegion(record.Region); region != "" {
				set[region] = struct{}{}
			}
		}
	}
	for _, candidate := range candidates {
		if region := historyCandidateRegion(candidate.Candidate); region != "" && region != "unknown" {
			set[region] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for region := range set {
		out = append(out, region)
	}
	sort.Slice(out, func(i, j int) bool {
		return historyRegionRank(out[i]) < historyRegionRank(out[j]) ||
			(historyRegionRank(out[i]) == historyRegionRank(out[j]) && out[i] < out[j])
	})
	return out
}

func bestHistoryRoute(candidates []sourcedCandidate, region string) *sourcedCandidate {
	var best *sourcedCandidate
	bestScore := math.Inf(1)
	for i := range candidates {
		candidate := &candidates[i]
		if !historySelectable(candidate.Candidate) || historyCandidateRegion(candidate.Candidate) != region {
			continue
		}
		score := historyRouteScore(candidate.Candidate)
		if score < bestScore {
			best = candidate
			bestScore = score
		}
	}
	return best
}

func bestHistorySpeed(candidates []sourcedCandidate, region string) *sourcedCandidate {
	var best *sourcedCandidate
	bestScore := math.Inf(1)
	var failed *sourcedCandidate
	failedScore := math.Inf(1)
	for i := range candidates {
		candidate := &candidates[i]
		if !historySelectable(candidate.Candidate) || historyCandidateRegion(candidate.Candidate) != region {
			continue
		}
		if candidate.CFSpeedRTTMs <= 0 {
			if candidate.CFSpeedTested {
				score := historyRouteScore(candidate.Candidate)
				if score < failedScore {
					failed = candidate
					failedScore = score
				}
			}
			continue
		}
		score := candidate.CFSpeedRTTMs + candidate.CFSpeedJitterMs*0.5 + candidate.CFSpeedLossRate*800
		if score < bestScore {
			best = candidate
			bestScore = score
		}
	}
	if best != nil {
		return best
	}
	return failed
}

func historyCandidateRegion(c router.Candidate) string {
	routeRegion := historyKnownRegion(c.RouteRegion)
	cfRegion := historyKnownRegion(c.CFRegion)
	if strings.TrimSpace(c.RouteError) != "" && routeRegion != "" && cfRegion != "" && routeRegion != cfRegion {
		return cfRegion
	}
	if region := historyKnownRegion(c.Region); region != "" {
		return region
	}
	if routeRegion != "" {
		return routeRegion
	}
	if cfRegion != "" {
		return cfRegion
	}
	return "unknown"
}

func historySelectable(c router.Candidate) bool {
	if c.Error != "" || c.Quarantined || math.IsInf(c.Score, 0) {
		return false
	}
	switch c.Stage {
	case "seed", "seed-sample", "learned", "hot", "lookup-reference", "lookup-sample":
	default:
		return false
	}
	return historyKnownRegion(historyCandidateRegion(c)) != ""
}

func historyRouteScore(c router.Candidate) float64 {
	rtt := c.PingRTTMs
	if rtt <= 0 {
		rtt = c.AvgRTTMs
	}
	if rtt <= 0 {
		rtt = 9999
	}
	return rtt + c.PingLossRate*800 + c.LossRate*300 + c.SpikeRate*80
}

func historyKnownRegion(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || value == "-" || value == "UNKNOWN" || value == "PREFLIGHT" {
		return ""
	}
	return value
}

func historyRegionRank(region string) int {
	switch region {
	case "HK":
		return 1
	case "US":
		return 2
	case "JP":
		return 3
	case "SG":
		return 4
	case "EU":
		return 5
	default:
		return 99
	}
}
