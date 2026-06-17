package router

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cf-anycast-router/internal/cloudflaredns"
	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/discover"
	"cf-anycast-router/internal/history"
	"cf-anycast-router/internal/netinfo"
	"cf-anycast-router/internal/output"
	"cf-anycast-router/internal/probe"
	"cf-anycast-router/internal/routegeo"
	cftrace "cf-anycast-router/internal/trace"
)

type Router struct {
	cfg      *config.Config
	state    *history.State
	stateMu  sync.Mutex
	pingSem  chan struct{}
	routeSem chan struct{}
	speedSem chan struct{}
	progress func(Candidate)
}

type Candidate struct {
	IP              string  `json:"ip"`
	Stage           string  `json:"stage"`
	Segment         string  `json:"segment"`
	Pool            string  `json:"pool"`
	Carrier         string  `json:"carrier"`
	ExpectedPOP     string  `json:"expected_pop"`
	ObservedPOP     string  `json:"observed_pop"`
	ObservedColo    string  `json:"observed_colo"`
	CFRegion        string  `json:"cf_region"`
	RouteRegion     string  `json:"route_region"`
	RouteHintIP     string  `json:"route_hint_ip"`
	RouteCountry    string  `json:"route_country"`
	RouteCity       string  `json:"route_city"`
	RouteISP        string  `json:"route_isp"`
	RouteConfidence float64 `json:"route_confidence"`
	RouteError      string  `json:"route_error,omitempty"`
	Region          string  `json:"region"`
	RegionSource    string  `json:"region_source"`
	CFSpeedRTTMs    float64 `json:"cf_speed_rtt_ms,omitempty"`
	CFSpeedJitterMs float64 `json:"cf_speed_jitter_ms,omitempty"`
	CFSpeedLossRate float64 `json:"cf_speed_loss_rate,omitempty"`
	CFSpeedMbps     float64 `json:"cf_speed_mbps,omitempty"`
	CFSpeedTested   bool    `json:"cf_speed_tested,omitempty"`
	CFSpeedError    string  `json:"cf_speed_error,omitempty"`
	PingRTTMs       float64 `json:"ping_rtt_ms"`
	PingLossRate    float64 `json:"ping_loss_rate"`
	PingError       string  `json:"ping_error,omitempty"`
	AvgRTTMs        float64 `json:"avg_rtt_ms"`
	JitterMs        float64 `json:"jitter_ms"`
	LossRate        float64 `json:"loss_rate"`
	SpikeRate       float64 `json:"spike_rate"`
	Score           float64 `json:"score"`
	PopPenalty      float64 `json:"pop_penalty"`
	DriftPenalty    float64 `json:"drift_penalty"`
	HijackPenalty   float64 `json:"hijack_penalty"`
	LearnedBonus    float64 `json:"learned_bonus"`
	Error           string  `json:"error,omitempty"`
	Quarantined     bool    `json:"quarantined"`
}

type CycleResult struct {
	Time       time.Time   `json:"time"`
	Carrier    string      `json:"carrier"`
	Best       *Candidate  `json:"best,omitempty"`
	CurrentIP  string      `json:"current_ip"`
	Switched   bool        `json:"switched"`
	Decision   string      `json:"decision"`
	Candidates []Candidate `json:"candidates"`
	Outputs    []string    `json:"outputs"`
}

type RangeValidation struct {
	InputIP         string           `json:"input_ip"`
	ASN             string           `json:"asn"`
	ASNName         string           `json:"asn_name"`
	LookupPrefix    string           `json:"lookup_prefix"`
	TestedPrefix    string           `json:"tested_prefix"`
	AcceptedCIDR    string           `json:"accepted_cidr,omitempty"`
	ReferencePOP    string           `json:"reference_pop"`
	ReferenceRegion string           `json:"reference_region"`
	ReferenceRTT    float64          `json:"reference_rtt_ms"`
	MatchRate       float64          `json:"match_rate"`
	Samples         []Candidate      `json:"samples"`
	Accepted        bool             `json:"accepted"`
	Reason          string           `json:"reason"`
	Fallback        *RangeValidation `json:"fallback,omitempty"`
}

func New(cfg *config.Config, st *history.State) *Router {
	return &Router{cfg: cfg, state: st, pingSem: make(chan struct{}, 16), routeSem: make(chan struct{}, 8), speedSem: make(chan struct{}, 12)}
}

func (r *Router) SetProgress(fn func(Candidate)) {
	r.progress = fn
}

func (r *Router) Evaluate() []Candidate {
	now := time.Now()
	candidates := r.probeTargets(discover.Targets(r.cfg, r.state), now)
	sortCandidates(candidates)
	r.applySpeedShortlist(candidates)
	sortCandidates(candidates)
	return candidates
}

func (r *Router) Cycle() (*CycleResult, error) {
	now := time.Now()
	targets := discover.Targets(r.cfg, r.state)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no scan targets available")
	}
	candidates := r.probeTargets(targets, now)
	sortCandidates(candidates)
	r.applySpeedShortlist(candidates)
	sortCandidates(candidates)
	result := &CycleResult{
		Time:       now,
		Carrier:    r.cfg.Carrier,
		CurrentIP:  r.state.CurrentIP,
		Candidates: candidates,
	}
	if outputs := r.updateRegionalDNS(candidates); len(outputs) > 0 {
		result.Outputs = append(result.Outputs, outputs...)
	}
	best := firstHealthy(candidates)
	if best == nil {
		r.state.CandidateIP = ""
		r.state.CandidateRounds = 0
		result.Decision = "no healthy candidate"
		r.state.LastDecision = result.Decision
		r.state.LastDecisionTime = now
		return result, nil
	}
	result.Best = best
	shouldSwitch, reason := r.shouldSwitch(best, candidates)
	result.Decision = reason
	if shouldSwitch {
		r.state.CurrentIP = best.IP
		r.state.CurrentScore = best.Score
		r.state.CurrentBaseline = best.AvgRTTMs
		r.state.CandidateIP = ""
		r.state.CandidateRounds = 0
		result.CurrentIP = best.IP
		result.Switched = true
		result.Decision = "switched: " + reason
		written, err := output.RenderAll(r.cfg.Outputs, output.ActiveRoute{
			IP:        best.IP,
			Domain:    r.cfg.TraceHost,
			Name:      "cf-anycast-active",
			Port:      r.cfg.ProbePort,
			SNI:       r.cfg.TraceHost,
			Score:     best.Score,
			Carrier:   best.Carrier,
			POP:       best.Region,
			Decision:  result.Decision,
			TraceHost: r.cfg.TraceHost,
		})
		if err != nil {
			return result, err
		}
		result.Outputs = append(result.Outputs, written...)
	} else if r.state.CurrentIP == "" {
		result.Decision = "no active route yet; " + reason
	}
	r.state.LastDecision = result.Decision
	r.state.LastDecisionTime = now
	if len(result.Outputs) > 0 {
		r.state.LastOutputSummary = strings.Join(result.Outputs, ", ")
	}
	return result, nil
}

func (r *Router) updateRegionalDNS(candidates []Candidate) []string {
	return UpdateRegionalDNS(r.cfg, r.cfg.Carrier, candidates)
}

func UpdateRegionalDNS(cfg *config.Config, carrier string, candidates []Candidate) []string {
	if cfg == nil || !cfg.CloudflareDNS.Enabled {
		return nil
	}
	carrier = config.NormalizeCarrier(carrier)
	client, err := cloudflaredns.New(cfg.CloudflareDNS)
	if err != nil {
		return []string{"cloudflare_dns error: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	records := cfg.CloudflareDNS.CarrierRegionRecords(carrier)
	out := make([]string, 0, len(records))
	for _, record := range records {
		best := firstHealthyInRouteRegionForType(candidates, record.Region, record.Type)
		if best == nil {
			out = append(out, fmt.Sprintf("cloudflare_dns %s %s %s %s skipped: no healthy candidate", carrier, record.Region, record.Type, record.Domain))
			continue
		}
		update, err := client.UpsertRecord(ctx, record.Region, record.Type, record.Domain, best.IP)
		if err != nil {
			out = append(out, fmt.Sprintf("cloudflare_dns %s %s %s %s error: %v", carrier, record.Region, record.Type, record.Domain, err))
			continue
		}
		out = append(out, fmt.Sprintf("cloudflare_dns %s %s %s %s -> %s %s", carrier, update.Region, update.Type, update.Domain, update.IP, update.Action))
	}
	return out
}

func (r *Router) ValidateIPRange(ip string, sampleCount int, minMatchRate float64) (*RangeValidation, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	info, err := netinfo.LookupPrefix(parsed.String())
	if err != nil {
		return nil, err
	}
	if sampleCount < 4 {
		sampleCount = 8
	}
	if minMatchRate <= 0 || minMatchRate > 1 {
		minMatchRate = 0.70
	}
	primary := r.validateCIDRAgainstIP(parsed.String(), info.Prefix, info, sampleCount, minMatchRate)
	if primary.Accepted {
		return primary, nil
	}
	local24, ok := discover.IPv4Slash24(parsed.String())
	if ok && local24 != info.Prefix {
		fallback := r.validateCIDRAgainstIP(parsed.String(), local24, info, sampleCount, minMatchRate)
		primary.Fallback = fallback
		if fallback.Accepted {
			primary.AcceptedCIDR = fallback.AcceptedCIDR
			primary.Accepted = true
			primary.Reason = "BGP prefix was mixed; accepted local /24 instead"
		}
	}
	return primary, nil
}

func (r *Router) validateCIDRAgainstIP(ip, cidr string, info *netinfo.PrefixInfo, sampleCount int, minMatchRate float64) *RangeValidation {
	now := time.Now()
	ref := r.probeOne(Candidate{
		IP:          ip,
		Stage:       "lookup-reference",
		Segment:     cidr,
		Pool:        "lookup",
		Carrier:     r.cfg.Carrier,
		ExpectedPOP: strings.Join(r.cfg.PreferredPOPs, "/"),
	}, now, nil, 0)
	result := &RangeValidation{
		InputIP:         ip,
		ASN:             info.ASN,
		ASNName:         info.Name,
		LookupPrefix:    info.Prefix,
		TestedPrefix:    cidr,
		ReferencePOP:    ref.ObservedPOP,
		ReferenceRegion: ref.Region,
		ReferenceRTT:    ref.AvgRTTMs,
	}
	if ref.Error != "" || ref.Region == "" || ref.Region == "unknown" {
		result.Reason = "reference IP could not be classified"
		return result
	}
	ips := discover.RandomSamples(cidr, sampleCount)
	if len(ips) == 0 {
		result.Reason = "no sample IPs generated"
		return result
	}
	targets := make([]discover.Target, 0, len(ips)+1)
	targets = append(targets, discover.Target{IP: ip, Stage: "lookup-reference", Segment: cidr, Carrier: r.cfg.Carrier, Weight: 1})
	for _, sampleIP := range ips {
		if sampleIP == ip {
			continue
		}
		targets = append(targets, discover.Target{IP: sampleIP, Stage: "lookup-sample", Segment: cidr, Carrier: r.cfg.Carrier, Weight: 1})
	}
	samples := r.probeTargets(targets, now)
	sortCandidates(samples)
	result.Samples = samples
	usable := 0
	matches := 0
	for _, sample := range samples {
		if sample.Error != "" || sample.Region == "" || sample.Region == "unknown" {
			continue
		}
		usable++
		if sample.Region == ref.Region {
			matches++
		}
	}
	if usable == 0 {
		result.Reason = "no usable samples"
		return result
	}
	result.MatchRate = float64(matches) / float64(usable)
	if result.MatchRate < minMatchRate {
		result.Reason = fmt.Sprintf("discarded: only %.0f%% samples matched reference route region %s", result.MatchRate*100, ref.Region)
		return result
	}
	result.Accepted = true
	result.AcceptedCIDR = cidr
	result.Reason = fmt.Sprintf("accepted: %.0f%% samples matched reference route region %s", result.MatchRate*100, ref.Region)
	return result
}

func (r *Router) probeTargets(targets []discover.Target, now time.Time) []Candidate {
	var jobs []Candidate
	for _, target := range targets {
		ip := strings.TrimSpace(target.IP)
		if ip == "" {
			continue
		}
		profile := r.state.Profile(ip)
		jobs = append(jobs, Candidate{
			IP:           ip,
			Stage:        target.Stage,
			Segment:      target.Segment,
			Pool:         target.Stage,
			Carrier:      target.Carrier,
			ExpectedPOP:  strings.Join(r.cfg.PreferredPOPs, "/"),
			LearnedBonus: stageBonus(target),
			Quarantined:  !profile.QuarantineUntil.IsZero() && now.Before(profile.QuarantineUntil),
		})
	}
	out := make([]Candidate, len(jobs))
	var wg sync.WaitGroup
	wg.Add(len(jobs))
	maxRoutes := r.cfg.MaxRouteTracesPerCycle
	if maxRoutes < 1 {
		maxRoutes = 1
	}
	routeBudget := int64(maxRoutes)
	if len(jobs) < maxRoutes {
		routeBudget = int64(len(jobs))
	}
	var routeUsed int64
	for i, job := range jobs {
		go func(idx int, c Candidate) {
			defer wg.Done()
			probed := r.probeOne(c, now, &routeUsed, routeBudget)
			out[idx] = probed
			if r.progress != nil {
				r.progress(probed)
			}
		}(i, job)
	}
	wg.Wait()
	return out
}

func (r *Router) probeOne(c Candidate, now time.Time, routeUsed *int64, routeBudget int64) Candidate {
	if c.Quarantined {
		c.Score = math.Inf(1)
		c.Error = "temporarily quarantined after POP drift"
		return c
	}
	ping := r.ping(c.IP)
	c.PingRTTMs = ping.AvgRTTMs
	c.PingLossRate = ping.LossRate
	if ping.Successes == 0 {
		c.PingError = ping.LastError
	}
	pr := probe.TLS(c.IP, r.cfg.TraceHost, r.cfg.ProbePort, r.cfg.ProbeAttempts, r.cfg.ProbeTimeout, r.cfg.SpikeThreshold, r.cfg.SpikeMultiplier)
	c.AvgRTTMs = pr.AvgRTTMs
	c.JitterMs = pr.JitterMs
	c.LossRate = pr.LossRate
	c.SpikeRate = pr.SpikeRate
	if pr.Successes == 0 {
		c.Score = math.Inf(1)
		c.Error = pr.LastError
		if c.Stage == "segment-probe" && c.Segment != "" {
			r.stateMu.Lock()
			r.state.RecordSegmentPreflight(c.Segment, c.Carrier, c.IP, false, c.Error, now)
			r.stateMu.Unlock()
		}
		return c
	}
	if c.Stage == "segment-probe" {
		c.Region = "preflight"
		c.RegionSource = "segment-probe"
		c.Score = c.PingRTTMs + c.PingLossRate*800 + c.AvgRTTMs + c.LossRate*300
		r.stateMu.Lock()
		r.state.RecordSegmentPreflight(c.Segment, c.Carrier, c.IP, true, "", now)
		r.stateMu.Unlock()
		return c
	}
	tr := cftrace.CloudflareTrace(c.IP, r.cfg.TraceHost, r.cfg.TracePath, r.cfg.ProbePort, r.cfg.ProbeTimeout)
	c.ObservedPOP = tr.POP
	c.ObservedColo = strings.ToUpper(strings.TrimSpace(tr.Raw["colo"]))
	if c.ObservedPOP == "" {
		c.ObservedPOP = "unknown"
	}
	if c.ObservedColo == "" && c.ObservedPOP != "unknown" {
		c.ObservedColo = c.ObservedPOP
	}
	c.CFRegion = cftrace.POPRegion(c.ObservedPOP)
	var route routegeo.Result
	if c.LossRate <= 0.5 || c.Stage == "lookup-reference" {
		if routeUsed == nil || atomic.AddInt64(routeUsed, 1) <= routeBudget || c.Stage == "lookup-reference" {
			route = r.traceRoute(c.IP)
		} else {
			route.Error = "route trace skipped by per-cycle budget"
		}
	}
	c.RouteRegion = route.Region
	c.RouteHintIP = route.HintIP
	c.RouteCountry = route.Country
	c.RouteCity = route.City
	c.RouteISP = route.ISP
	c.RouteConfidence = route.Confidence
	c.RouteError = route.Error
	c.Region, c.RegionSource = effectiveRegion(c.RouteRegion, c.CFRegion, c.RouteError, c.RouteConfidence, c.RouteHintIP)
	if c.Region == "" {
		c.Region = "unknown"
	}
	c.PopPenalty = popPenalty(c.Region, c.AvgRTTMs)
	if !tr.OK {
		c.HijackPenalty = r.cfg.HijackPenalty
	}
	preferred := r.cfg.PreferredPOPSet()
	isPreferred := preferred[c.Region]
	if (c.Stage == "hot" || c.Stage == "learned" || c.Stage == "seed" || c.Stage == "seed-sample") && (c.Region == "US" || c.Region == "EU") {
		c.DriftPenalty = r.cfg.DriftPenalty
		if r.cfg.QuarantineMinutes > 0 {
			r.stateMu.Lock()
			r.state.Profile(c.IP).QuarantineUntil = now.Add(time.Duration(r.cfg.QuarantineMinutes) * time.Minute)
			r.stateMu.Unlock()
		}
	}
	c.Score = c.AvgRTTMs + c.JitterMs*0.5 + c.LossRate*500 + c.SpikeRate*80 + c.PopPenalty + c.DriftPenalty + c.HijackPenalty - c.LearnedBonus
	r.stateMu.Lock()
	oldPOP, changed := r.state.Record(c.IP, c.Carrier, c.Region, now, c.AvgRTTMs, c.JitterMs, c.LossRate, c.SpikeRate, c.Score)
	if changed {
		log.Printf("[drift] %s %s route region changed: %s -> %s (cf_colo=%s/%s)", c.IP, c.Carrier, oldPOP, c.Region, c.ObservedColo, c.ObservedPOP)
	}
	if c.Segment != "" {
		seg := r.state.RecordSegment(c.Segment, c.Carrier, c.Region, isPreferred, now, c.AvgRTTMs, c.LossRate, c.SpikeRate, c.Score)
		if !seg.Promoted && seg.Samples >= r.cfg.PromoteMinSamples && seg.PreferredRate >= r.cfg.PromotePOPProbability {
			r.state.PromoteSegment(c.Segment, c.Carrier, now)
			log.Printf("[learn] promoted %s carrier=%s preferred_rate=%.0f%% samples=%d", c.Segment, c.Carrier, seg.PreferredRate*100, seg.Samples)
		}
		if isPreferred && c.Score <= r.cfg.HotMaxScore && c.LossRate <= r.cfg.FastSwitchLossRate && c.SpikeRate <= r.cfg.FastSwitchSpikeRate {
			r.state.AddHotIP(c.Segment, c.Carrier, history.HotIP{
				IP:           c.IP,
				POP:          c.Region,
				Score:        c.Score,
				PingRTTMs:    c.PingRTTMs,
				PingLossRate: c.PingLossRate,
				AvgRTTMs:     c.AvgRTTMs,
				JitterMs:     c.JitterMs,
				LossRate:     c.LossRate,
				SpikeRate:    c.SpikeRate,
				LastSeen:     now,
			}, r.cfg.HotMaxPerSegment)
		}
	}
	r.stateMu.Unlock()
	return c
}

func (r *Router) traceRoute(ip string) routegeo.Result {
	if r.routeSem != nil {
		r.routeSem <- struct{}{}
		defer func() { <-r.routeSem }()
	}
	return routegeo.TraceWithOptions(ip, 22*time.Second, routegeo.TraceOptions{
		Command: r.cfg.RouteTraceCommand,
		Args:    r.cfg.RouteTraceArgs,
	})
}

func (r *Router) ping(ip string) probe.Result {
	if r.pingSem != nil {
		r.pingSem <- struct{}{}
		defer func() { <-r.pingSem }()
	}
	return probe.ICMP(ip, r.cfg.ProbeAttempts, r.cfg.ProbeTimeout)
}

func (r *Router) applySpeedShortlist(candidates []Candidate) {
	if !r.cfg.SpeedTest.Enabled || r.cfg.SpeedTest.TopN <= 0 {
		return
	}
	selected := speedShortlistIndexes(candidates, r.cfg.SpeedTest.TopN)
	var wg sync.WaitGroup
	wg.Add(len(selected))
	for _, idx := range selected {
		go func(i int) {
			defer wg.Done()
			speed := r.cfSpeed(candidates[i].IP)
			applySpeedResult(&candidates[i], speed, r.cfg.SpeedTest.Bytes)
			if r.progress != nil {
				r.progress(candidates[i])
			}
		}(idx)
	}
	wg.Wait()
}

func speedShortlistIndexes(candidates []Candidate, topN int) []int {
	if topN <= 0 {
		return nil
	}
	selected := make([]int, 0, topN)
	seen := make(map[int]bool)
	add := func(i int) {
		if seen[i] {
			return
		}
		seen[i] = true
		selected = append(selected, i)
	}
	for i := range candidates {
		if len(selected) >= topN {
			break
		}
		if isSelectableCandidate(candidates[i]) {
			add(i)
		}
	}
	perRegionLimit := topN * 4
	if perRegionLimit > 20 {
		perRegionLimit = 20
	}
	regionCounts := make(map[string]int)
	for i := range candidates {
		if !isSelectableCandidate(candidates[i]) {
			continue
		}
		region := candidateRecordRegion(candidates[i])
		if !isKnownRegion(region) || regionCounts[region] >= perRegionLimit {
			continue
		}
		regionCounts[region]++
		add(i)
	}
	return selected
}

func applySpeedResult(c *Candidate, speed probe.Result, bytes int64) {
	c.CFSpeedTested = true
	c.CFSpeedRTTMs = speed.AvgRTTMs
	c.CFSpeedJitterMs = speed.JitterMs
	c.CFSpeedLossRate = speed.LossRate
	if speed.Successes > 0 && speed.AvgRTTMs > 0 && bytes > 0 {
		c.CFSpeedMbps = float64(bytes*8) / (c.CFSpeedRTTMs / 1000.0) / 1000000.0
		c.CFSpeedError = ""
		c.PopPenalty = popPenalty(c.Region, c.CFSpeedRTTMs)
		c.Score = c.CFSpeedRTTMs + c.CFSpeedJitterMs*0.5 + c.CFSpeedLossRate*500 + c.SpikeRate*80 + c.PopPenalty + c.DriftPenalty + c.HijackPenalty - c.LearnedBonus
		return
	}
	c.CFSpeedError = speed.LastError
	if c.CFSpeedError == "" {
		c.CFSpeedError = "cloudflare speed test failed"
	}
	c.Score = math.Inf(1)
}

func (r *Router) cfSpeed(ip string) probe.Result {
	if !r.cfg.SpeedTest.Enabled {
		return probe.Result{IP: ip}
	}
	if r.speedSem != nil {
		r.speedSem <- struct{}{}
		defer func() { <-r.speedSem }()
	}
	attempts := r.cfg.ProbeAttempts
	if attempts > 3 {
		attempts = 3
	}
	timeout := r.cfg.ProbeTimeout
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	return probe.CloudflareDownload(ip, r.cfg.SpeedTest.Host, r.cfg.SpeedTest.Path, r.cfg.SpeedTest.Bytes, attempts, timeout, r.cfg.SpikeThreshold, r.cfg.SpikeMultiplier)
}

func (r *Router) shouldSwitch(best *Candidate, candidates []Candidate) (bool, string) {
	if best == nil || best.Score <= 0 || math.IsInf(best.Score, 0) {
		return false, "best candidate is not usable"
	}
	if r.state.CurrentIP == "" {
		return true, "no active route"
	}
	if r.state.CurrentIP == best.IP {
		r.state.CandidateIP = ""
		r.state.CandidateRounds = 0
		r.state.CurrentScore = best.Score
		r.state.CurrentBaseline = best.AvgRTTMs
		return false, "current route remains best"
	}
	if r.state.CurrentScore <= 0 {
		return true, "active route has no baseline score"
	}
	current := findByIP(r.state.CurrentIP, candidates)
	if current != nil && current.Error == "" {
		if current.LossRate > r.cfg.FastSwitchLossRate {
			return true, fmt.Sprintf("active route loss %.1f%% exceeds %.1f%%", current.LossRate*100, r.cfg.FastSwitchLossRate*100)
		}
		if r.state.CurrentBaseline > 0 && current.AvgRTTMs > r.state.CurrentBaseline*r.cfg.FastSwitchRTTMultiplier {
			return true, fmt.Sprintf("active route RTT %.1fms exceeds %.1fx baseline %.1fms", current.AvgRTTMs, r.cfg.FastSwitchRTTMultiplier, r.state.CurrentBaseline)
		}
		if current.SpikeRate > r.cfg.FastSwitchSpikeRate {
			return true, fmt.Sprintf("active route spike rate %.1f%% exceeds %.1f%%", current.SpikeRate*100, r.cfg.FastSwitchSpikeRate*100)
		}
	}
	improvement := (r.state.CurrentScore - best.Score) / r.state.CurrentScore * 100
	if improvement < r.cfg.SwitchImprovementPct {
		r.state.CandidateIP = ""
		r.state.CandidateRounds = 0
		return false, fmt.Sprintf("kept current; %.1f%% improvement is below %.1f%%", improvement, r.cfg.SwitchImprovementPct)
	}
	if r.state.CandidateIP != best.IP {
		r.state.CandidateIP = best.IP
		r.state.CandidateRounds = 1
		return false, fmt.Sprintf("candidate %s is better by %.1f%%; observing 1/%d rounds", best.IP, improvement, r.cfg.SwitchStableRounds)
	}
	r.state.CandidateRounds++
	if r.state.CandidateRounds < r.cfg.SwitchStableRounds {
		return false, fmt.Sprintf("candidate %s is better by %.1f%%; observing %d/%d rounds", best.IP, improvement, r.state.CandidateRounds, r.cfg.SwitchStableRounds)
	}
	return true, fmt.Sprintf("candidate %s held advantage for %d rounds (%.1f%% better)", best.IP, r.state.CandidateRounds, improvement)
}

func firstHealthy(candidates []Candidate) *Candidate {
	for i := range candidates {
		if isSelectableCandidate(candidates[i]) {
			return &candidates[i]
		}
	}
	return nil
}

func firstHealthyInRegion(candidates []Candidate, region string) *Candidate {
	return firstHealthyInRegionForType(candidates, region, "A")
}

func firstHealthyInRegionForType(candidates []Candidate, region, recordType string) *Candidate {
	region = strings.ToUpper(strings.TrimSpace(region))
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	for i := range candidates {
		if candidates[i].Region != region {
			continue
		}
		ip := net.ParseIP(candidates[i].IP)
		if recordType == "A" && (ip == nil || ip.To4() == nil) {
			continue
		}
		if recordType == "AAAA" && (ip == nil || ip.To4() != nil) {
			continue
		}
		if isSelectableCandidate(candidates[i]) {
			return &candidates[i]
		}
	}
	return nil
}

func firstHealthyInRouteRegionForType(candidates []Candidate, region, recordType string) *Candidate {
	region = strings.ToUpper(strings.TrimSpace(region))
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	var best *Candidate
	bestScore := math.Inf(1)
	for i := range candidates {
		if candidateRecordRegion(candidates[i]) != region {
			continue
		}
		ip := net.ParseIP(candidates[i].IP)
		if recordType == "A" && (ip == nil || ip.To4() == nil) {
			continue
		}
		if recordType == "AAAA" && (ip == nil || ip.To4() != nil) {
			continue
		}
		if isSelectableCandidate(candidates[i]) {
			score := dnsRouteScore(candidates[i])
			if score < bestScore {
				best = &candidates[i]
				bestScore = score
			}
		}
	}
	return best
}

func candidateRecordRegion(c Candidate) string {
	routeRegion := normalizeRegion(c.RouteRegion)
	cfRegion := normalizeRegion(c.CFRegion)
	if strings.TrimSpace(c.RouteError) != "" &&
		isKnownRegion(routeRegion) &&
		isKnownRegion(cfRegion) &&
		routeRegion != cfRegion {
		if hasReliableRouteHint(c.RouteConfidence, c.RouteHintIP) {
			return routeRegion
		}
		return cfRegion
	}
	if region := normalizeRegion(c.Region); isKnownRegion(region) {
		return region
	}
	if isKnownRegion(routeRegion) {
		return routeRegion
	}
	if isKnownRegion(cfRegion) {
		return cfRegion
	}
	return "unknown"
}

func isSelectableCandidate(c Candidate) bool {
	if c.Error != "" || c.Quarantined || math.IsInf(c.Score, 0) {
		return false
	}
	switch c.Stage {
	case "seed", "seed-sample", "learned", "hot", "lookup-reference", "lookup-sample":
	default:
		return false
	}
	return isKnownRegion(candidateRecordRegion(c))
}

func dnsRouteScore(c Candidate) float64 {
	if c.CFSpeedRTTMs > 0 {
		return c.CFSpeedRTTMs + c.CFSpeedLossRate*800 + c.SpikeRate*80
	}
	rtt := c.PingRTTMs
	if rtt <= 0 {
		rtt = c.AvgRTTMs
	}
	if rtt <= 0 {
		rtt = 9999
	}
	return rtt + c.PingLossRate*800 + c.LossRate*300 + c.SpikeRate*80
}

func sortCandidates(candidates []Candidate) {
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		aSpeedOK := a.CFSpeedTested && a.CFSpeedRTTMs > 0 && a.CFSpeedError == ""
		bSpeedOK := b.CFSpeedTested && b.CFSpeedRTTMs > 0 && b.CFSpeedError == ""
		if aSpeedOK != bSpeedOK {
			return aSpeedOK
		}
		if math.IsInf(a.Score, 0) && math.IsInf(b.Score, 0) {
			return a.IP < b.IP
		}
		if math.IsInf(a.Score, 0) {
			return false
		}
		if math.IsInf(b.Score, 0) {
			return true
		}
		if a.Score != b.Score {
			return a.Score < b.Score
		}
		return a.AvgRTTMs < b.AvgRTTMs
	})
}

func popPenalty(region string, rtt float64) float64 {
	switch region {
	case "HK", "JP", "SG":
		return 0
	case "US":
		return 100
	case "EU":
		return 150
	case "unknown":
		return 120
	}
	return 30
}

func isPreferredAsia(region string) bool {
	return region == "HK" || region == "JP" || region == "SG"
}

func stageBonus(target discover.Target) float64 {
	switch target.Stage {
	case "hot":
		return 24
	case "learned":
		if target.Weight > 0 {
			return math.Min(20, target.Weight*6)
		}
		return 10
	default:
		return 0
	}
}

func effectiveRegion(routeRegion, cfRegion, routeError string, routeConfidence float64, routeHintIP string) (string, string) {
	routeRegion = normalizeRegion(routeRegion)
	cfRegion = normalizeRegion(cfRegion)
	if strings.TrimSpace(routeError) != "" &&
		isKnownRegion(routeRegion) &&
		isKnownRegion(cfRegion) &&
		routeRegion != cfRegion {
		if hasReliableRouteHint(routeConfidence, routeHintIP) {
			return routeRegion, "route"
		}
		return cfRegion, "cf"
	}
	if isKnownRegion(routeRegion) {
		return routeRegion, "route"
	}
	if isKnownRegion(cfRegion) {
		return cfRegion, "cf"
	}
	return "unknown", "unknown"
}

func hasReliableRouteHint(confidence float64, hintIP string) bool {
	return strings.TrimSpace(hintIP) != "" && confidence >= 0.75
}

func normalizeRegion(region string) string {
	region = strings.ToUpper(strings.TrimSpace(region))
	if region == "" || region == "-" {
		return "unknown"
	}
	return region
}

func isKnownRegion(region string) bool {
	return region != "" && region != "UNKNOWN" && region != "unknown" && region != "-"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findByIP(ip string, candidates []Candidate) *Candidate {
	for i := range candidates {
		if candidates[i].IP == ip {
			return &candidates[i]
		}
	}
	return nil
}
