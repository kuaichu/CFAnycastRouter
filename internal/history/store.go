package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"cf-anycast-router/internal/config"
)

type State struct {
	RouteModelVersion int                        `json:"route_model_version"`
	CurrentIP         string                     `json:"current_ip"`
	CurrentScore      float64                    `json:"current_score"`
	CurrentBaseline   float64                    `json:"current_baseline_rtt_ms"`
	CandidateIP       string                     `json:"candidate_ip"`
	CandidateRounds   int                        `json:"candidate_rounds"`
	Profiles          map[string]*IPProfile      `json:"profiles"`
	Segments          map[string]*SegmentProfile `json:"segments"`
	LastDecision      string                     `json:"last_decision"`
	LastDecisionTime  time.Time                  `json:"last_decision_time"`
	LastOutputSummary string                     `json:"last_output_summary"`
}

type IPProfile struct {
	IP               string                  `json:"ip"`
	LastPOPByCarrier map[string]string       `json:"last_pop_by_carrier"`
	POPTimeline      []POPEvent              `json:"pop_timeline"`
	TimeBuckets      map[string]*BucketStats `json:"time_buckets"`
	QuarantineUntil  time.Time               `json:"quarantine_until"`
	LastSeen         time.Time               `json:"last_seen"`
}

type POPEvent struct {
	Time    time.Time `json:"time"`
	Carrier string    `json:"carrier"`
	POP     string    `json:"pop"`
}

type BucketStats struct {
	Count     int     `json:"count"`
	AvgRTTMs  float64 `json:"avg_rtt_ms"`
	JitterMs  float64 `json:"jitter_ms"`
	LossRate  float64 `json:"loss_rate"`
	SpikeRate float64 `json:"spike_rate"`
	Score     float64 `json:"score"`
}

type SegmentProfile struct {
	CIDR           string            `json:"cidr"`
	Carrier        string            `json:"carrier"`
	Samples        int               `json:"samples"`
	POPCounts      map[string]int    `json:"pop_counts"`
	AvgRTTMs       float64           `json:"avg_rtt_ms"`
	AvgScore       float64           `json:"avg_score"`
	LossRate       float64           `json:"loss_rate"`
	SpikeRate      float64           `json:"spike_rate"`
	PreferredHits  int               `json:"preferred_hits"`
	PreferredRate  float64           `json:"preferred_rate"`
	Promoted       bool              `json:"promoted"`
	Weight         float64           `json:"weight"`
	ScanCursor     int               `json:"scan_cursor"`
	PreflightIP    string            `json:"preflight_ip,omitempty"`
	PreflightOK    bool              `json:"preflight_ok"`
	PreflightError string            `json:"preflight_error,omitempty"`
	PreflightAt    time.Time         `json:"preflight_at,omitempty"`
	LastScanned    time.Time         `json:"last_scanned"`
	LastPromotedAt time.Time         `json:"last_promoted_at"`
	HotIPs         map[string]*HotIP `json:"hot_ips"`
}

type HotIP struct {
	IP           string    `json:"ip"`
	POP          string    `json:"pop"`
	Score        float64   `json:"score"`
	PingRTTMs    float64   `json:"ping_rtt_ms"`
	PingLossRate float64   `json:"ping_loss_rate"`
	AvgRTTMs     float64   `json:"avg_rtt_ms"`
	JitterMs     float64   `json:"jitter_ms"`
	LossRate     float64   `json:"loss_rate"`
	SpikeRate    float64   `json:"spike_rate"`
	LastSeen     time.Time `json:"last_seen"`
}

func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	st := &State{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if !bytes.Contains(data, []byte(`"route_model_version"`)) {
		st.RouteModelVersion = 0
	}
	if st.Profiles == nil {
		st.Profiles = map[string]*IPProfile{}
	}
	if st.Segments == nil {
		st.Segments = map[string]*SegmentProfile{}
	}
	if st.RouteModelVersion < CurrentRouteModelVersion {
		log.Printf("[history] route model changed from %d to %d; dropping stale learned segments and hot IP cache", st.RouteModelVersion, CurrentRouteModelVersion)
		st.RouteModelVersion = CurrentRouteModelVersion
		st.Profiles = map[string]*IPProfile{}
		st.Segments = map[string]*SegmentProfile{}
		st.CandidateIP = ""
		st.CandidateRounds = 0
		st.CurrentScore = 0
		st.CurrentBaseline = 0
		st.LastDecision = ""
		st.LastDecisionTime = time.Time{}
		st.LastOutputSummary = ""
	}
	return st, nil
}

const CurrentRouteModelVersion = 2

func New() *State {
	return &State{
		RouteModelVersion: CurrentRouteModelVersion,
		Profiles:          map[string]*IPProfile{},
		Segments:          map[string]*SegmentProfile{},
	}
}

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (s *State) Segment(cidr, carrier string) *SegmentProfile {
	if s.Segments == nil {
		s.Segments = map[string]*SegmentProfile{}
	}
	key := carrier + "|" + cidr
	seg := s.Segments[key]
	if seg == nil {
		seg = &SegmentProfile{
			CIDR:      cidr,
			Carrier:   carrier,
			POPCounts: map[string]int{},
			HotIPs:    map[string]*HotIP{},
		}
		s.Segments[key] = seg
	}
	if seg.POPCounts == nil {
		seg.POPCounts = map[string]int{}
	}
	if seg.HotIPs == nil {
		seg.HotIPs = map[string]*HotIP{}
	}
	return seg
}

func (s *State) RecordSegment(cidr, carrier, pop string, preferred bool, now time.Time, avgRTT, loss, spike, score float64) *SegmentProfile {
	seg := s.Segment(cidr, carrier)
	seg.Samples++
	n := float64(seg.Samples)
	if pop != "" {
		seg.POPCounts[pop]++
	}
	if preferred {
		seg.PreferredHits++
	}
	seg.PreferredRate = float64(seg.PreferredHits) / float64(seg.Samples)
	seg.AvgRTTMs += (avgRTT - seg.AvgRTTMs) / n
	seg.AvgScore += (score - seg.AvgScore) / n
	seg.LossRate += (loss - seg.LossRate) / n
	seg.SpikeRate += (spike - seg.SpikeRate) / n
	seg.LastScanned = now
	return seg
}

func (s *State) RecordSegmentPreflight(cidr, carrier, ip string, ok bool, errText string, now time.Time) *SegmentProfile {
	seg := s.Segment(cidr, carrier)
	seg.PreflightIP = ip
	seg.PreflightOK = ok
	seg.PreflightError = errText
	seg.PreflightAt = now
	seg.LastScanned = now
	return seg
}

func (s *State) PromoteSegment(cidr, carrier string, now time.Time) {
	seg := s.Segment(cidr, carrier)
	seg.Promoted = true
	seg.LastPromotedAt = now
	seg.Weight = 1 + seg.PreferredRate*2
}

func (s *State) AddHotIP(cidr, carrier string, hot HotIP, maxPerSegment int) {
	seg := s.Segment(cidr, carrier)
	seg.HotIPs[hot.IP] = &hot
	if maxPerSegment <= 0 || len(seg.HotIPs) <= maxPerSegment {
		return
	}
	var worstIP string
	worstScore := -1.0
	for ip, item := range seg.HotIPs {
		if item.Score > worstScore {
			worstScore = item.Score
			worstIP = ip
		}
	}
	if worstIP != "" {
		delete(seg.HotIPs, worstIP)
	}
}

func (s *State) Profile(ip string) *IPProfile {
	if s.Profiles == nil {
		s.Profiles = map[string]*IPProfile{}
	}
	p := s.Profiles[ip]
	if p == nil {
		p = &IPProfile{
			IP:               ip,
			LastPOPByCarrier: map[string]string{},
			TimeBuckets:      map[string]*BucketStats{},
		}
		s.Profiles[ip] = p
	}
	if p.LastPOPByCarrier == nil {
		p.LastPOPByCarrier = map[string]string{}
	}
	if p.TimeBuckets == nil {
		p.TimeBuckets = map[string]*BucketStats{}
	}
	return p
}

func (s *State) Record(ip, carrier, pop string, now time.Time, avgRTT, jitter, loss, spike, score float64) (oldPOP string, changed bool) {
	p := s.Profile(ip)
	p.LastSeen = now
	if pop != "" && pop != "unknown" {
		oldPOP = p.LastPOPByCarrier[carrier]
		if oldPOP != pop {
			p.LastPOPByCarrier[carrier] = pop
			p.POPTimeline = append(p.POPTimeline, POPEvent{Time: now, Carrier: carrier, POP: pop})
			if len(p.POPTimeline) > 200 {
				p.POPTimeline = p.POPTimeline[len(p.POPTimeline)-200:]
			}
			changed = oldPOP != ""
		}
	}
	bucketName := config.TimeBucket(now)
	bucket := p.TimeBuckets[bucketName]
	if bucket == nil {
		bucket = &BucketStats{}
		p.TimeBuckets[bucketName] = bucket
	}
	bucket.Count++
	n := float64(bucket.Count)
	bucket.AvgRTTMs += (avgRTT - bucket.AvgRTTMs) / n
	bucket.JitterMs += (jitter - bucket.JitterMs) / n
	bucket.LossRate += (loss - bucket.LossRate) / n
	bucket.SpikeRate += (spike - bucket.SpikeRate) / n
	bucket.Score += (score - bucket.Score) / n
	return oldPOP, changed
}
