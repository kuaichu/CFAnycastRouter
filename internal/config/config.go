package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ProbeSource   string `yaml:"probe_source"`
	Carrier       string `yaml:"carrier"`
	AgentID       string `yaml:"agent_id"`
	ServerURL     string `yaml:"server_url"`
	AgentTokenEnv string `yaml:"agent_token_env"`

	TraceHost string `yaml:"trace_host"`
	TracePath string `yaml:"trace_path"`

	ProbePort       int     `yaml:"probe_port"`
	ProbeAttempts   int     `yaml:"probe_attempts"`
	ProbeTimeoutSec int     `yaml:"probe_timeout_seconds"`
	SpikeThreshold  float64 `yaml:"spike_threshold_ms"`
	SpikeMultiplier float64 `yaml:"spike_multiplier"`

	RouteTraceCommand      string   `yaml:"route_trace_command"`
	RouteTraceArgs         []string `yaml:"route_trace_args"`
	MaxRouteTracesPerCycle int      `yaml:"max_route_traces_per_cycle"`

	CheckIntervalSec        int     `yaml:"check_interval_seconds"`
	SwitchStableRounds      int     `yaml:"switch_stable_rounds"`
	SwitchImprovementPct    float64 `yaml:"switch_improvement_percent"`
	FastSwitchLossRate      float64 `yaml:"fast_switch_loss_rate"`
	FastSwitchRTTMultiplier float64 `yaml:"fast_switch_rtt_multiplier"`
	FastSwitchSpikeRate     float64 `yaml:"fast_switch_spike_rate"`

	DriftPenalty      float64 `yaml:"drift_penalty"`
	HijackPenalty     float64 `yaml:"hijack_penalty"`
	QuarantineMinutes int     `yaml:"quarantine_minutes"`

	StatePath string `yaml:"state_path"`
	WebPort   int    `yaml:"web_port"`

	SeedIPs   []string `yaml:"seed_ips"`
	SeedCIDRs []string `yaml:"seed_cidrs"`

	SampleStep                   int      `yaml:"sample_step"`
	SeedCIDRStep                 int      `yaml:"seed_cidr_step"`
	SeedPreflightMaxPerCycle     int      `yaml:"seed_preflight_max_per_cycle"`
	MaxSeedSegmentsPerCycle      int      `yaml:"max_seed_segments_per_cycle"`
	MaxLearnedSegmentsPerCycle   int      `yaml:"max_learned_segments_per_cycle"`
	MaxSamplesPerSegmentPerCycle int      `yaml:"max_samples_per_segment_per_cycle"`
	PromoteMinSamples            int      `yaml:"promote_min_samples"`
	PromotePOPProbability        float64  `yaml:"promote_pop_probability"`
	HotMaxPerSegment             int      `yaml:"hot_max_per_segment"`
	HotMaxScore                  float64  `yaml:"hot_max_score"`
	PreferredPOPs                []string `yaml:"preferred_pops"`

	Pools   []PoolConfig   `yaml:"pools"`
	Outputs []OutputConfig `yaml:"outputs"`

	CloudflareDNS CloudflareDNSConfig `yaml:"cloudflare_dns"`
	SpeedTest     SpeedTestConfig     `yaml:"speed_test" json:"speed_test"`

	ProbeTimeout  time.Duration `yaml:"-"`
	CheckInterval time.Duration `yaml:"-"`
}

type PoolConfig struct {
	Name    string   `yaml:"name"`
	Carrier string   `yaml:"carrier"`
	POP     string   `yaml:"pop"`
	IPs     []string `yaml:"ips"`
}

type OutputConfig struct {
	Type   string            `yaml:"type"`
	Path   string            `yaml:"path"`
	Domain string            `yaml:"domain"`
	Name   string            `yaml:"name"`
	Port   int               `yaml:"port"`
	SNI    string            `yaml:"sni"`
	Extra  map[string]string `yaml:"extra"`
}

type CloudflareDNSConfig struct {
	Enabled    bool              `yaml:"enabled" json:"enabled"`
	ZoneID     string            `yaml:"zone_id" json:"zone_id"`
	ZoneName   string            `yaml:"zone_name" json:"zone_name"`
	TokenEnv   string            `yaml:"token_env" json:"token_env"`
	TTL        int               `yaml:"ttl" json:"ttl"`
	Proxied    bool              `yaml:"proxied" json:"proxied"`
	Records    map[string]string `yaml:"records,omitempty" json:"records,omitempty"`
	RecordSets []DNSRecordConfig `yaml:"record_sets,omitempty" json:"record_sets"`
}

type DNSRecordConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Carrier string `yaml:"carrier" json:"carrier"`
	Region  string `yaml:"region" json:"region"`
	Type    string `yaml:"type" json:"type"`
	Domain  string `yaml:"domain" json:"domain"`
}

type SpeedTestConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Host    string `yaml:"host" json:"host"`
	Path    string `yaml:"path" json:"path"`
	Bytes   int64  `yaml:"bytes" json:"bytes"`
	TopN    int    `yaml:"top_n" json:"top_n"`
}

type ManageSettings struct {
	ProbeSource                  string              `json:"probe_source"`
	Carrier                      string              `json:"carrier"`
	CheckIntervalSec             int                 `json:"check_interval_seconds"`
	ProbeAttempts                int                 `json:"probe_attempts"`
	ProbeTimeoutSec              int                 `json:"probe_timeout_seconds"`
	SpikeThreshold               float64             `json:"spike_threshold_ms"`
	SpikeMultiplier              float64             `json:"spike_multiplier"`
	MaxRouteTracesPerCycle       int                 `json:"max_route_traces_per_cycle"`
	SampleStep                   int                 `json:"sample_step"`
	SeedCIDRStep                 int                 `json:"seed_cidr_step"`
	SeedPreflightMaxPerCycle     int                 `json:"seed_preflight_max_per_cycle"`
	MaxSeedSegmentsPerCycle      int                 `json:"max_seed_segments_per_cycle"`
	MaxLearnedSegmentsPerCycle   int                 `json:"max_learned_segments_per_cycle"`
	MaxSamplesPerSegmentPerCycle int                 `json:"max_samples_per_segment_per_cycle"`
	PromoteMinSamples            int                 `json:"promote_min_samples"`
	PromotePOPProbability        float64             `json:"promote_pop_probability"`
	HotMaxPerSegment             int                 `json:"hot_max_per_segment"`
	HotMaxScore                  float64             `json:"hot_max_score"`
	CloudflareDNS                CloudflareDNSConfig `json:"cloudflare_dns"`
	SpeedTest                    SpeedTestConfig     `json:"speed_test"`
}

func Load(path string) (*Config, error) {
	cfg := defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		ProbeSource:                  "local-agent",
		Carrier:                      "auto",
		AgentTokenEnv:                "CFAR_AGENT_TOKEN",
		TraceHost:                    "cloudflare.com",
		TracePath:                    "/cdn-cgi/trace",
		ProbePort:                    443,
		ProbeAttempts:                5,
		ProbeTimeoutSec:              3,
		SpikeThreshold:               120,
		SpikeMultiplier:              2.0,
		MaxRouteTracesPerCycle:       24,
		CheckIntervalSec:             300,
		SwitchStableRounds:           3,
		SwitchImprovementPct:         15,
		FastSwitchLossRate:           0.03,
		FastSwitchRTTMultiplier:      2.5,
		FastSwitchSpikeRate:          0.50,
		DriftPenalty:                 220,
		HijackPenalty:                500,
		QuarantineMinutes:            60,
		StatePath:                    "data/state.json",
		WebPort:                      19199,
		SampleStep:                   4,
		SeedCIDRStep:                 16,
		SeedPreflightMaxPerCycle:     256,
		MaxSeedSegmentsPerCycle:      8,
		MaxLearnedSegmentsPerCycle:   16,
		MaxSamplesPerSegmentPerCycle: 8,
		PromoteMinSamples:            6,
		PromotePOPProbability:        0.70,
		HotMaxPerSegment:             8,
		HotMaxScore:                  95,
		PreferredPOPs:                []string{"HK", "JP", "SG"},
		SpeedTest: SpeedTestConfig{
			Enabled: true,
			Host:    "speed.cloudflare.com",
			Path:    "/__down",
			Bytes:   262144,
			TopN:    5,
		},
	}
}

func (c *Config) normalize() error {
	c.Carrier = NormalizeCarrier(c.Carrier)
	if c.Carrier == "auto" {
		c.Carrier = InferCarrier(c.ProbeSource)
	}
	c.AgentID = strings.TrimSpace(c.AgentID)
	c.ServerURL = strings.TrimRight(strings.TrimSpace(c.ServerURL), "/")
	c.AgentTokenEnv = strings.TrimSpace(c.AgentTokenEnv)
	if c.AgentTokenEnv == "" {
		c.AgentTokenEnv = "CFAR_AGENT_TOKEN"
	}
	c.TraceHost = strings.TrimSpace(c.TraceHost)
	if c.TraceHost == "" {
		return fmt.Errorf("trace_host is required")
	}
	if c.TracePath == "" {
		c.TracePath = "/cdn-cgi/trace"
	}
	if !strings.HasPrefix(c.TracePath, "/") {
		c.TracePath = "/" + c.TracePath
	}
	if c.ProbePort <= 0 || c.ProbePort > 65535 {
		return fmt.Errorf("probe_port must be 1-65535")
	}
	if c.ProbeAttempts < 1 {
		c.ProbeAttempts = 1
	}
	if c.ProbeTimeoutSec < 1 {
		c.ProbeTimeoutSec = 1
	}
	if c.SpikeThreshold <= 0 {
		c.SpikeThreshold = 120
	}
	if c.SpikeMultiplier <= 0 {
		c.SpikeMultiplier = 2
	}
	c.RouteTraceCommand = strings.TrimSpace(c.RouteTraceCommand)
	for i, arg := range c.RouteTraceArgs {
		c.RouteTraceArgs[i] = strings.TrimSpace(arg)
	}
	if c.MaxRouteTracesPerCycle < 0 {
		c.MaxRouteTracesPerCycle = 0
	}
	if c.MaxRouteTracesPerCycle == 0 {
		c.MaxRouteTracesPerCycle = 24
	}
	if c.CheckIntervalSec < 1 {
		c.CheckIntervalSec = 300
	}
	if c.SwitchStableRounds < 1 {
		c.SwitchStableRounds = 1
	}
	if c.SwitchImprovementPct < 0 {
		c.SwitchImprovementPct = 0
	}
	if c.FastSwitchLossRate <= 0 {
		c.FastSwitchLossRate = 0.03
	}
	if c.FastSwitchRTTMultiplier <= 0 {
		c.FastSwitchRTTMultiplier = 2.5
	}
	if c.FastSwitchSpikeRate <= 0 {
		c.FastSwitchSpikeRate = 0.50
	}
	if c.DriftPenalty <= 0 {
		c.DriftPenalty = 220
	}
	if c.HijackPenalty <= 0 {
		c.HijackPenalty = 500
	}
	if c.QuarantineMinutes < 0 {
		c.QuarantineMinutes = 0
	}
	if c.StatePath == "" {
		c.StatePath = "data/state.json"
	}
	if len(c.SeedIPs) == 0 && len(c.SeedCIDRs) == 0 && len(c.Pools) == 0 && c.ServerURL == "" {
		return fmt.Errorf("at least one seed_ips or seed_cidrs entry is required")
	}
	for i, ip := range c.SeedIPs {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("seed_ips[%d] must be a valid IP address", i)
		}
		c.SeedIPs[i] = ip
	}
	for i, cidr := range c.SeedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("seed_cidrs[%d] must be a valid CIDR: %w", i, err)
		}
		c.SeedCIDRs[i] = cidr
	}
	if c.SampleStep < 1 {
		c.SampleStep = 4
	}
	if c.SeedCIDRStep < 1 {
		c.SeedCIDRStep = 16
	}
	if c.SeedPreflightMaxPerCycle < 1 {
		c.SeedPreflightMaxPerCycle = 256
	}
	if c.MaxSeedSegmentsPerCycle < 1 {
		c.MaxSeedSegmentsPerCycle = 8
	}
	if c.MaxLearnedSegmentsPerCycle < 0 {
		c.MaxLearnedSegmentsPerCycle = 0
	}
	if c.MaxSamplesPerSegmentPerCycle < 1 {
		c.MaxSamplesPerSegmentPerCycle = 8
	}
	if c.PromoteMinSamples < 1 {
		c.PromoteMinSamples = 6
	}
	if c.PromotePOPProbability <= 0 || c.PromotePOPProbability > 1 {
		c.PromotePOPProbability = 0.70
	}
	if c.HotMaxPerSegment < 1 {
		c.HotMaxPerSegment = 8
	}
	if c.HotMaxScore <= 0 {
		c.HotMaxScore = 95
	}
	for i, pop := range c.PreferredPOPs {
		c.PreferredPOPs[i] = NormalizePOP(pop)
	}
	if len(c.PreferredPOPs) == 0 {
		c.PreferredPOPs = []string{"HK", "JP", "SG"}
	}
	c.CloudflareDNS.ZoneID = strings.TrimSpace(c.CloudflareDNS.ZoneID)
	c.CloudflareDNS.ZoneName = strings.TrimSpace(c.CloudflareDNS.ZoneName)
	c.CloudflareDNS.TokenEnv = strings.TrimSpace(c.CloudflareDNS.TokenEnv)
	if c.CloudflareDNS.TokenEnv == "" {
		c.CloudflareDNS.TokenEnv = "CLOUDFLARE_API_TOKEN"
	}
	if c.CloudflareDNS.TTL == 0 {
		c.CloudflareDNS.TTL = 60
	}
	if c.CloudflareDNS.TTL < 0 || (c.CloudflareDNS.TTL > 0 && c.CloudflareDNS.TTL < 60) {
		return fmt.Errorf("cloudflare_dns.ttl must be 0 or >= 60")
	}
	for region, domain := range c.CloudflareDNS.Records {
		norm := NormalizePOP(region)
		domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
		if norm == "" || domain == "" {
			return fmt.Errorf("cloudflare_dns.records must map non-empty region to non-empty domain")
		}
		if norm != region || domain != c.CloudflareDNS.Records[region] {
			delete(c.CloudflareDNS.Records, region)
			c.CloudflareDNS.Records[norm] = domain
		}
	}
	for i := range c.CloudflareDNS.RecordSets {
		record := &c.CloudflareDNS.RecordSets[i]
		rawCarrier := strings.TrimSpace(record.Carrier)
		record.Carrier = NormalizeCarrier(record.Carrier)
		if rawCarrier == "" || record.Carrier == "auto" {
			record.Carrier = c.Carrier
		}
		record.Region = NormalizePOP(record.Region)
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		if record.Type == "" {
			record.Type = "A"
		}
		if record.Type != "A" && record.Type != "AAAA" {
			return fmt.Errorf("cloudflare_dns.record_sets[%d].type must be A or AAAA", i)
		}
		record.Domain = strings.TrimSpace(strings.TrimSuffix(record.Domain, "."))
		if record.Carrier == "" || record.Region == "" || record.Domain == "" {
			return fmt.Errorf("cloudflare_dns.record_sets[%d] requires carrier, region and domain", i)
		}
	}
	if len(c.CloudflareDNS.RecordSets) == 0 && len(c.CloudflareDNS.Records) > 0 {
		keys := make([]string, 0, len(c.CloudflareDNS.Records))
		for region := range c.CloudflareDNS.Records {
			keys = append(keys, region)
		}
		sort.Strings(keys)
		for _, region := range keys {
			c.CloudflareDNS.RecordSets = append(c.CloudflareDNS.RecordSets, DNSRecordConfig{
				Enabled: true,
				Carrier: c.Carrier,
				Region:  region,
				Type:    "A",
				Domain:  c.CloudflareDNS.Records[region],
			})
		}
	}
	c.SpeedTest.Host = strings.TrimSpace(strings.TrimSuffix(c.SpeedTest.Host, "."))
	if c.SpeedTest.Host == "" {
		c.SpeedTest.Host = "speed.cloudflare.com"
	}
	if c.SpeedTest.Path == "" {
		c.SpeedTest.Path = "/__down"
	}
	if !strings.HasPrefix(c.SpeedTest.Path, "/") {
		c.SpeedTest.Path = "/" + c.SpeedTest.Path
	}
	if c.SpeedTest.Bytes <= 0 {
		c.SpeedTest.Bytes = 262144
	}
	if c.SpeedTest.Bytes < 4096 {
		c.SpeedTest.Bytes = 4096
	}
	if c.SpeedTest.Bytes > 4*1024*1024 {
		c.SpeedTest.Bytes = 4 * 1024 * 1024
	}
	if c.SpeedTest.TopN <= 0 {
		c.SpeedTest.TopN = 5
	}
	if c.SpeedTest.TopN > 20 {
		c.SpeedTest.TopN = 20
	}
	for i := range c.Pools {
		p := &c.Pools[i]
		p.Name = strings.TrimSpace(p.Name)
		p.Carrier = NormalizeCarrier(p.Carrier)
		p.POP = NormalizePOP(p.POP)
		if p.Name == "" {
			return fmt.Errorf("pools[%d].name is required", i)
		}
		if p.Carrier == "" {
			return fmt.Errorf("pools[%d].carrier is required", i)
		}
		if p.POP == "" {
			return fmt.Errorf("pools[%d].pop is required", i)
		}
		for _, ip := range p.IPs {
			if net.ParseIP(strings.TrimSpace(ip)) == nil {
				return fmt.Errorf("pool %s has invalid IP %q", p.Name, ip)
			}
		}
	}
	c.ProbeTimeout = time.Duration(c.ProbeTimeoutSec) * time.Second
	c.CheckInterval = time.Duration(c.CheckIntervalSec) * time.Second
	return nil
}

func NormalizeCarrier(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cu", "unicom", "china_unicom", "联通", "中国联通":
		return "cu"
	case "ct", "telecom", "china_telecom", "电信", "中国电信":
		return "ct"
	case "cm", "mobile", "china_mobile", "移动", "中国移动":
		return "cm"
	case "unknown", "unk", "other", "其他", "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func InferCarrier(source string) string {
	s := strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(s, "cu"), strings.Contains(s, "unicom"), strings.Contains(s, "联通"):
		return "cu"
	case strings.Contains(s, "ct"), strings.Contains(s, "telecom"), strings.Contains(s, "电信"):
		return "ct"
	case strings.Contains(s, "cm"), strings.Contains(s, "mobile"), strings.Contains(s, "移动"):
		return "cm"
	default:
		return "unknown"
	}
}

func NormalizePOP(value string) string {
	v := strings.ToUpper(strings.TrimSpace(value))
	switch v {
	case "HKG":
		return "HK"
	case "NRT", "KIX", "FUK":
		return "JP"
	case "SIN":
		return "SG"
	}
	return v
}

func TimeBucket(t time.Time) string {
	h := t.Hour()
	switch {
	case h < 6:
		return "00:00-06:00"
	case h < 12:
		return "06:00-12:00"
	case h < 18:
		return "12:00-18:00"
	default:
		return "18:00-24:00"
	}
}

func (c *Config) CandidatePools() []PoolConfig {
	out := make([]PoolConfig, 0, len(c.Pools))
	for _, pool := range c.Pools {
		if pool.Carrier == c.Carrier || pool.Carrier == "unknown" || c.Carrier == "unknown" {
			out = append(out, pool)
		}
	}
	return out
}

func (c *Config) PreferredPOPSet() map[string]bool {
	out := make(map[string]bool, len(c.PreferredPOPs))
	for _, pop := range c.PreferredPOPs {
		out[NormalizePOP(pop)] = true
	}
	return out
}

func (c *Config) ManageSettings() ManageSettings {
	return ManageSettings{
		ProbeSource:                  c.ProbeSource,
		Carrier:                      c.Carrier,
		CheckIntervalSec:             c.CheckIntervalSec,
		ProbeAttempts:                c.ProbeAttempts,
		ProbeTimeoutSec:              c.ProbeTimeoutSec,
		SpikeThreshold:               c.SpikeThreshold,
		SpikeMultiplier:              c.SpikeMultiplier,
		MaxRouteTracesPerCycle:       c.MaxRouteTracesPerCycle,
		SampleStep:                   c.SampleStep,
		SeedCIDRStep:                 c.SeedCIDRStep,
		SeedPreflightMaxPerCycle:     c.SeedPreflightMaxPerCycle,
		MaxSeedSegmentsPerCycle:      c.MaxSeedSegmentsPerCycle,
		MaxLearnedSegmentsPerCycle:   c.MaxLearnedSegmentsPerCycle,
		MaxSamplesPerSegmentPerCycle: c.MaxSamplesPerSegmentPerCycle,
		PromoteMinSamples:            c.PromoteMinSamples,
		PromotePOPProbability:        c.PromotePOPProbability,
		HotMaxPerSegment:             c.HotMaxPerSegment,
		HotMaxScore:                  c.HotMaxScore,
		CloudflareDNS:                c.CloudflareDNS,
		SpeedTest:                    c.SpeedTest,
	}
}

func (c CloudflareDNSConfig) RegionRecords() []DNSRecordConfig {
	if len(c.RecordSets) > 0 {
		out := make([]DNSRecordConfig, 0, len(c.RecordSets))
		for _, record := range c.RecordSets {
			if !record.Enabled {
				continue
			}
			out = append(out, record)
		}
		return out
	}
	out := make([]DNSRecordConfig, 0, len(c.Records))
	keys := make([]string, 0, len(c.Records))
	for region := range c.Records {
		keys = append(keys, region)
	}
	sort.Strings(keys)
	for _, region := range keys {
		out = append(out, DNSRecordConfig{Enabled: true, Carrier: "unknown", Region: NormalizePOP(region), Type: "A", Domain: c.Records[region]})
	}
	return out
}

func (c CloudflareDNSConfig) CarrierRegionRecords(carrier string) []DNSRecordConfig {
	carrier = NormalizeCarrier(carrier)
	out := make([]DNSRecordConfig, 0, len(c.RecordSets))
	for _, record := range c.RegionRecords() {
		if NormalizeCarrier(record.Carrier) == carrier {
			out = append(out, record)
		}
	}
	return out
}

func ParseSeedText(text string) ([]string, []string, error) {
	ipSeen := map[string]bool{}
	cidrSeen := map[string]bool{}
	var ips []string
	var cidrs []string
	fields := seedFields(text)
	for _, field := range fields {
		token := normalizeSeedToken(field)
		if token == "" {
			continue
		}
		if ip := net.ParseIP(token); ip != nil {
			value := ip.String()
			if !ipSeen[value] {
				ipSeen[value] = true
				ips = append(ips, value)
			}
			continue
		}
		if _, network, err := net.ParseCIDR(token); err == nil {
			value := network.String()
			if !cidrSeen[value] {
				cidrSeen[value] = true
				cidrs = append(cidrs, value)
			}
			continue
		}
		return nil, nil, fmt.Errorf("invalid seed %q; use IP, CIDR, 104.20.x.x, or 104.20.23.x", field)
	}
	if len(ips) == 0 && len(cidrs) == 0 {
		return nil, nil, fmt.Errorf("no valid IP or CIDR seeds found")
	}
	return ips, cidrs, nil
}

func SaveSeeds(path, text string) ([]string, []string, error) {
	ips, cidrs, err := ParseSeedText(text)
	if err != nil {
		return nil, nil, err
	}
	if err := SaveSeedLists(path, ips, cidrs); err != nil {
		return nil, nil, err
	}
	return ips, cidrs, nil
}

func SaveSeedLists(path string, ips, cidrs []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config root must be a YAML mapping")
	}
	mapping := root.Content[0]
	upsertStringSeq(mapping, "seed_ips", ips)
	upsertStringSeq(mapping, "seed_cidrs", cidrs)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		_ = enc.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close encoder: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func SaveManageSettings(path string, settings ManageSettings) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	cfg.ProbeSource = strings.TrimSpace(settings.ProbeSource)
	cfg.Carrier = strings.TrimSpace(settings.Carrier)
	cfg.CheckIntervalSec = settings.CheckIntervalSec
	cfg.ProbeAttempts = settings.ProbeAttempts
	cfg.ProbeTimeoutSec = settings.ProbeTimeoutSec
	cfg.SpikeThreshold = settings.SpikeThreshold
	cfg.SpikeMultiplier = settings.SpikeMultiplier
	cfg.MaxRouteTracesPerCycle = settings.MaxRouteTracesPerCycle
	cfg.SampleStep = settings.SampleStep
	cfg.SeedCIDRStep = settings.SeedCIDRStep
	cfg.SeedPreflightMaxPerCycle = settings.SeedPreflightMaxPerCycle
	cfg.MaxSeedSegmentsPerCycle = settings.MaxSeedSegmentsPerCycle
	cfg.MaxLearnedSegmentsPerCycle = settings.MaxLearnedSegmentsPerCycle
	cfg.MaxSamplesPerSegmentPerCycle = settings.MaxSamplesPerSegmentPerCycle
	cfg.PromoteMinSamples = settings.PromoteMinSamples
	cfg.PromotePOPProbability = settings.PromotePOPProbability
	cfg.HotMaxPerSegment = settings.HotMaxPerSegment
	cfg.HotMaxScore = settings.HotMaxScore
	cfg.CloudflareDNS = settings.CloudflareDNS
	cfg.SpeedTest = settings.SpeedTest
	if cfg.ProbeSource == "" {
		cfg.ProbeSource = "local-agent"
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if err := saveManageSettingsNode(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func saveManageSettingsNode(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config root must be a YAML mapping")
	}
	mapping := root.Content[0]
	upsertScalar(mapping, "probe_source", cfg.ProbeSource)
	upsertScalar(mapping, "carrier", cfg.Carrier)
	upsertScalarWithTag(mapping, "check_interval_seconds", fmt.Sprintf("%d", cfg.CheckIntervalSec), "!!int")
	upsertScalarWithTag(mapping, "probe_attempts", fmt.Sprintf("%d", cfg.ProbeAttempts), "!!int")
	upsertScalarWithTag(mapping, "probe_timeout_seconds", fmt.Sprintf("%d", cfg.ProbeTimeoutSec), "!!int")
	upsertScalarWithTag(mapping, "spike_threshold_ms", fmt.Sprintf("%g", cfg.SpikeThreshold), "!!float")
	upsertScalarWithTag(mapping, "spike_multiplier", fmt.Sprintf("%g", cfg.SpikeMultiplier), "!!float")
	upsertScalarWithTag(mapping, "max_route_traces_per_cycle", fmt.Sprintf("%d", cfg.MaxRouteTracesPerCycle), "!!int")
	upsertScalarWithTag(mapping, "sample_step", fmt.Sprintf("%d", cfg.SampleStep), "!!int")
	upsertScalarWithTag(mapping, "seed_cidr_step", fmt.Sprintf("%d", cfg.SeedCIDRStep), "!!int")
	upsertScalarWithTag(mapping, "seed_preflight_max_per_cycle", fmt.Sprintf("%d", cfg.SeedPreflightMaxPerCycle), "!!int")
	upsertScalarWithTag(mapping, "max_seed_segments_per_cycle", fmt.Sprintf("%d", cfg.MaxSeedSegmentsPerCycle), "!!int")
	upsertScalarWithTag(mapping, "max_learned_segments_per_cycle", fmt.Sprintf("%d", cfg.MaxLearnedSegmentsPerCycle), "!!int")
	upsertScalarWithTag(mapping, "max_samples_per_segment_per_cycle", fmt.Sprintf("%d", cfg.MaxSamplesPerSegmentPerCycle), "!!int")
	upsertScalarWithTag(mapping, "promote_min_samples", fmt.Sprintf("%d", cfg.PromoteMinSamples), "!!int")
	upsertScalarWithTag(mapping, "promote_pop_probability", fmt.Sprintf("%g", cfg.PromotePOPProbability), "!!float")
	upsertScalarWithTag(mapping, "hot_max_per_segment", fmt.Sprintf("%d", cfg.HotMaxPerSegment), "!!int")
	upsertScalarWithTag(mapping, "hot_max_score", fmt.Sprintf("%g", cfg.HotMaxScore), "!!float")
	upsertCloudflareDNS(mapping, cfg.CloudflareDNS)
	upsertSpeedTest(mapping, cfg.SpeedTest)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		_ = enc.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close encoder: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func MergeSeeds(path string, addIPs, addCIDRs []string) ([]string, []string, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, nil, err
	}
	ipSeen := map[string]bool{}
	cidrSeen := map[string]bool{}
	ips := make([]string, 0, len(cfg.SeedIPs)+len(addIPs))
	cidrs := make([]string, 0, len(cfg.SeedCIDRs)+len(addCIDRs))
	for _, ip := range append(cfg.SeedIPs, addIPs...) {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil && !ipSeen[parsed.String()] {
			ipSeen[parsed.String()] = true
			ips = append(ips, parsed.String())
		}
	}
	for _, cidr := range append(cfg.SeedCIDRs, addCIDRs...) {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && !cidrSeen[network.String()] {
			cidrSeen[network.String()] = true
			cidrs = append(cidrs, network.String())
		}
	}
	if err := SaveSeedLists(path, ips, cidrs); err != nil {
		return nil, nil, err
	}
	return ips, cidrs, nil
}

func seedFields(text string) []string {
	var cleaned []string
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		cleaned = append(cleaned, line)
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}
	return strings.FieldsFunc(strings.Join(cleaned, "\n"), splitter)
}

var wildcard24 = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(x|\*)$`)
var wildcard16 = regexp.MustCompile(`^(\d{1,3}\.\d{1,3})\.(x|\*)\.(x|\*)$`)

func normalizeSeedToken(token string) string {
	token = strings.TrimSpace(strings.Trim(token, `"'[]()`))
	token = strings.TrimSuffix(token, ".")
	token = strings.ToLower(token)
	if match := wildcard24.FindStringSubmatch(token); match != nil {
		return match[1] + ".0/24"
	}
	if match := wildcard16.FindStringSubmatch(token); match != nil {
		return match[1] + ".0.0/16"
	}
	return token
}

func upsertStringSeq(mapping *yaml.Node, key string, values []string) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	seqNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, value := range values {
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: value,
		})
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1] = seqNode
			return
		}
	}
	mapping.Content = append(mapping.Content, keyNode, seqNode)
}

func upsertScalar(mapping *yaml.Node, key, value string) {
	upsertScalarWithTag(mapping, key, value, "!!str")
}

func upsertScalarWithTag(mapping *yaml.Node, key, value, tag string) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valueNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1] = valueNode
			return
		}
	}
	mapping.Content = append(mapping.Content, keyNode, valueNode)
}

func upsertCloudflareDNS(mapping *yaml.Node, cfg CloudflareDNSConfig) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	addMapScalar(node, "enabled", fmt.Sprintf("%t", cfg.Enabled), "!!bool")
	addMapScalar(node, "zone_id", cfg.ZoneID, "!!str")
	addMapScalar(node, "zone_name", cfg.ZoneName, "!!str")
	addMapScalar(node, "token_env", cfg.TokenEnv, "!!str")
	addMapScalar(node, "ttl", fmt.Sprintf("%d", cfg.TTL), "!!int")
	addMapScalar(node, "proxied", fmt.Sprintf("%t", cfg.Proxied), "!!bool")
	records := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, record := range cfg.RecordSets {
		item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		addMapScalar(item, "enabled", fmt.Sprintf("%t", record.Enabled), "!!bool")
		addMapScalar(item, "carrier", record.Carrier, "!!str")
		addMapScalar(item, "region", record.Region, "!!str")
		addMapScalar(item, "type", record.Type, "!!str")
		addMapScalar(item, "domain", record.Domain, "!!str")
		records.Content = append(records.Content, item)
	}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "record_sets"}, records)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "cloudflare_dns" {
			mapping.Content[i+1] = node
			return
		}
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "cloudflare_dns"}, node)
}

func upsertSpeedTest(mapping *yaml.Node, cfg SpeedTestConfig) {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	addMapScalar(node, "enabled", fmt.Sprintf("%t", cfg.Enabled), "!!bool")
	addMapScalar(node, "host", cfg.Host, "!!str")
	addMapScalar(node, "path", cfg.Path, "!!str")
	addMapScalar(node, "bytes", fmt.Sprintf("%d", cfg.Bytes), "!!int")
	addMapScalar(node, "top_n", fmt.Sprintf("%d", cfg.TopN), "!!int")
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "speed_test" {
			mapping.Content[i+1] = node
			return
		}
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "speed_test"}, node)
}

func addMapScalar(mapping *yaml.Node, key, value, tag string) {
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
	)
}
