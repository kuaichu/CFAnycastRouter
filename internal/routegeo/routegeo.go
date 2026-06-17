package routegeo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP         string   `json:"ip"`
	Hops       []string `json:"hops"`
	Region     string   `json:"region"`
	Country    string   `json:"country"`
	City       string   `json:"city"`
	ISP        string   `json:"isp"`
	ASN        string   `json:"asn"`
	HintIP     string   `json:"hint_ip"`
	Confidence float64  `json:"confidence"`
	Error      string   `json:"error,omitempty"`
	Raw        string   `json:"raw,omitempty"`
}

type TraceOptions struct {
	Command string
	Args    []string

	runner     traceRunner
	geoQuerier geoQuerier
	cache      *geoInfoCache
}

type geoInfo struct {
	Status      string `json:"status"`
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	AS          string `json:"as"`
}

var ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var ntrRawHopPattern = regexp.MustCompile(`^\s*(\d+)\|((?:\d{1,3}\.){3}\d{1,3})\|`)
var asnPattern = regexp.MustCompile(`\bAS\d+\b`)

var geoLookupSem = make(chan struct{}, 2)
var defaultGeoCache = newGeoInfoCache(4096, 6*time.Hour)

type traceRunner interface {
	Run(ctx context.Context, ip string, opts TraceOptions) (string, error)
}

type geoQuerier interface {
	Lookup(ctx context.Context, ips []string) ([]geoInfo, error)
}

type routeResolver struct {
	runner traceRunner
	geo    geoQuerier
	cache  *geoInfoCache
}

type execTraceRunner struct{}

type ipAPIGeoQuerier struct {
	client *http.Client
}

type geoInfoCache struct {
	sync.RWMutex
	items map[string]geoCacheEntry
	ttl   time.Duration
	max   int
}

type geoCacheEntry struct {
	info      geoInfo
	expiresAt time.Time
}

type routeHintSelector struct{}

const (
	baseRouteConfidence  = 0.65
	nearTargetConfidence = 0.85
	cloudflareBonus      = 0.10
	targetHintPenalty    = 0.20
	maxRouteConfidence   = 0.98
	nearTargetHopWindow  = 3
)

type traceRegionRule struct {
	country     string
	countryCode string
	city        string
	terms       []string
}

type traceNetworkRule struct {
	isp string
	asn string
	any []string
}

type traceCommandPlan struct {
	Path string
	Args []string
}

type traceCommandPlanner struct {
	goos     string
	lookPath func(string) (string, error)
}

var traceRegionRules = []traceRegionRule{
	{country: "Hong Kong", countryCode: "HK", city: "Hong Kong", terms: []string{"hong kong", "香港", "newthk", ".hk.", "-hk", "_hk", "hkg"}},
	{country: "Singapore", countryCode: "SG", city: "Singapore", terms: []string{"singapore", "新加坡"}},
	{country: "Japan", countryCode: "JP", terms: []string{"japan", "日本", "tokyo"}},
	{country: "United States", countryCode: "US", terms: []string{"united states", "美国", "los angeles", "california"}},
	{country: "Canada", countryCode: "CA", terms: []string{"canada", "加拿大"}},
	{country: "Germany", countryCode: "DE", terms: []string{"germany", "德国"}},
	{country: "China", countryCode: "CN", terms: []string{"china", "中国"}},
}

var traceNetworkRules = []traceNetworkRule{
	{isp: "Cloudflare, Inc.", asn: "AS13335 Cloudflare, Inc.", any: []string{"cloudflare"}},
	{isp: "NTT America, Inc.", asn: "AS2914 NTT America, Inc.", any: []string{"ntt"}},
	{isp: "China Unicom", any: []string{"unicom", "china169"}},
}

func Trace(ip string, timeout time.Duration) Result {
	return TraceWithOptions(ip, timeout, TraceOptions{})
}

func TraceWithOptions(ip string, timeout time.Duration, opts TraceOptions) Result {
	return newRouteResolver(opts).Trace(ip, timeout, opts)
}

func newRouteResolver(opts TraceOptions) *routeResolver {
	runner := opts.runner
	if runner == nil {
		runner = execTraceRunner{}
	}
	querier := opts.geoQuerier
	if querier == nil {
		querier = ipAPIGeoQuerier{client: http.DefaultClient}
	}
	cache := opts.cache
	if cache == nil {
		cache = defaultGeoCache
	}
	return &routeResolver{runner: runner, geo: querier, cache: cache}
}

func (r *routeResolver) Trace(ip string, timeout time.Duration, opts TraceOptions) Result {
	out := Result{IP: strings.TrimSpace(ip)}
	if net.ParseIP(out.IP).To4() == nil {
		out.Error = "invalid IPv4"
		return out
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	raw, err := r.runTrace(out.IP, timeout, opts)
	out.Raw = raw
	if err != nil {
		out.Error = err.Error()
	}
	out.Hops = parseHops(raw)
	if len(out.Hops) == 0 {
		if out.Error == "" {
			out.Error = "no route hops parsed"
		}
		return out
	}
	infos := parseEmbeddedGeoInfos(raw)
	for ip, info := range r.lookupGeo(out.Hops, timeout, infos) {
		infos[ip] = info
	}
	pick := pickRouteHint(out.IP, out.Hops, infos)
	if pick == nil || shouldTryEmbeddedFallback(*pick) {
		if fallback := r.traceEmbeddedGeoFallback(out.IP, timeout, opts); fallback != nil {
			fallbackPick := pickRouteHint(out.IP, fallback.hops, fallback.infos)
			if shouldUseEmbeddedFallback(out.IP, out.Hops, pick, fallback.hops, fallbackPick) {
				out.Hops = fallback.hops
				infos = fallback.infos
				pick = fallbackPick
			}
		}
	}
	if pick == nil {
		if out.Error == "" {
			out.Error = "no geocoded public hop"
		}
		return out
	}
	out.HintIP = pick.Query
	out.Country = pick.Country
	out.City = pick.City
	out.ISP = pick.ISP
	out.ASN = pick.AS
	out.Region = regionFromGeo(*pick)
	out.Confidence = confidenceFor(out.IP, out.HintIP, out.Hops, *pick)
	return out
}

type embeddedGeoTrace struct {
	hops  []string
	infos map[string]geoInfo
}

func (r *routeResolver) traceEmbeddedGeoFallback(ip string, timeout time.Duration, opts TraceOptions) *embeddedGeoTrace {
	args, ok := nextTraceReportArgs(opts.Args)
	if !ok || strings.TrimSpace(opts.Command) == "" {
		return nil
	}
	raw, err := r.runTrace(ip, timeout, TraceOptions{Command: opts.Command, Args: args})
	if err != nil && raw == "" {
		return nil
	}
	hops := parseHops(raw)
	infos := parseEmbeddedGeoInfos(raw)
	if len(hops) == 0 || len(infos) == 0 {
		return nil
	}
	return &embeddedGeoTrace{hops: hops, infos: infos}
}

func (r *routeResolver) runTrace(ip string, timeout time.Duration, opts TraceOptions) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return r.runner.Run(ctx, ip, opts)
}

func (execTraceRunner) Run(ctx context.Context, ip string, opts TraceOptions) (string, error) {
	plan := defaultTraceCommandPlanner().Plan(ip, opts)
	cmd := exec.CommandContext(ctx, plan.Path, plan.Args...)
	data, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(data), fmt.Errorf("route trace timed out")
	}
	if err != nil && len(data) == 0 {
		return "", err
	}
	return string(data), nil
}

func defaultTraceCommandPlanner() traceCommandPlanner {
	return traceCommandPlanner{goos: runtime.GOOS, lookPath: exec.LookPath}
}

func (p traceCommandPlanner) Plan(ip string, opts TraceOptions) traceCommandPlan {
	if p.goos == "" {
		p.goos = runtime.GOOS
	}
	if p.lookPath == nil {
		p.lookPath = exec.LookPath
	}
	if strings.TrimSpace(opts.Command) != "" {
		args := replaceIPArg(opts.Args, ip)
		if len(args) == 0 {
			args = []string{ip}
		}
		return traceCommandPlan{Path: opts.Command, Args: args}
	}
	for _, name := range []string{"nexttrace", "nxtrace", "/usr/local/bin/nexttrace", "/usr/local/bin/nxtrace", "/usr/bin/nexttrace", "/usr/bin/nxtrace"} {
		if path, err := p.lookPath(name); err == nil {
			return traceCommandPlan{Path: path, Args: []string{"--raw", "-C", "-g", "cn", "--report", "--wide", "--show-ips", "-q", "3", "-n", "-m", "18", ip}}
		}
	}
	if path, err := p.lookPath("mtr"); err == nil && p.goos != "windows" {
		return traceCommandPlan{Path: path, Args: []string{"-n", "-r", "-c", "1", "-m", "18", ip}}
	}
	if p.goos != "windows" {
		if path, err := p.lookPath("traceroute"); err == nil {
			return traceCommandPlan{Path: path, Args: []string{"-n", "-m", "18", "-w", "1", "-q", "1", ip}}
		}
		return traceCommandPlan{Path: "tracepath", Args: []string{"-n", "-m", "18", ip}}
	}
	return traceCommandPlan{Path: "tracert", Args: []string{"-d", "-h", "18", "-w", "700", ip}}
}

func replaceIPArg(args []string, ip string) []string {
	out := make([]string, 0, len(args)+1)
	replaced := false
	for _, arg := range args {
		if strings.Contains(arg, "{ip}") {
			replaced = true
			out = append(out, strings.ReplaceAll(arg, "{ip}", ip))
			continue
		}
		out = append(out, arg)
	}
	if !replaced && len(out) > 0 {
		out = append(out, ip)
	}
	return out
}

func nextTraceReportArgs(args []string) ([]string, bool) {
	hasRaw := false
	hasReport := false
	hasWide := false
	hasShowIPs := false
	hasNoColor := false
	hasLanguage := false
	out := make([]string, 0, len(args)+6)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--raw":
			hasRaw = true
			continue
		case "--report", "-r":
			hasReport = true
		case "--wide", "-w":
			hasWide = true
		case "--show-ips":
			hasShowIPs = true
		case "-C", "--no-color":
			hasNoColor = true
		case "-g", "--language":
			hasLanguage = true
		case "-d", "--data-provider":
			out = append(out, arg)
			if i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
			continue
		case "-q", "--queries":
			out = append(out, arg)
			if i+1 < len(args) {
				i++
				out = append(out, maxNumericArg(args[i], 3))
			}
			continue
		}
		out = append(out, arg)
	}
	if !hasRaw {
		return nil, false
	}
	if !hasNoColor {
		out = append([]string{"-C"}, out...)
	}
	if !hasLanguage {
		out = append([]string{"-g", "cn"}, out...)
	}
	if !hasReport {
		out = append(out, "--report")
	}
	if !hasWide {
		out = append(out, "--wide")
	}
	if !hasShowIPs {
		out = append(out, "--show-ips")
	}
	return out, true
}

func maxNumericArg(value string, min int) string {
	n, err := strconv.Atoi(value)
	if err != nil || n >= min {
		return value
	}
	return strconv.Itoa(min)
}

func parseHops(raw string) []string {
	if hops := parseNTRRawHops(raw); len(hops) > 0 {
		return hops
	}
	seen := map[string]bool{}
	var hops []string
	for _, match := range ipv4Pattern.FindAllString(raw, -1) {
		ip := net.ParseIP(match).To4()
		if ip == nil || seen[match] {
			continue
		}
		seen[match] = true
		hops = append(hops, match)
	}
	return hops
}

func parseNTRRawHops(raw string) []string {
	byHop := map[int]string{}
	for _, line := range strings.Split(raw, "\n") {
		match := ntrRawHopPattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 {
			continue
		}
		hop, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		ip := net.ParseIP(match[2]).To4()
		if ip == nil {
			continue
		}
		byHop[hop] = match[2]
	}
	if len(byHop) == 0 {
		return nil
	}
	keys := make([]int, 0, len(byHop))
	for hop := range byHop {
		keys = append(keys, hop)
	}
	sort.Ints(keys)
	seen := map[string]bool{}
	out := make([]string, 0, len(keys))
	for _, hop := range keys {
		ip := byHop[hop]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

func (r *routeResolver) lookupGeo(ips []string, timeout time.Duration, known map[string]geoInfo) map[string]geoInfo {
	out := map[string]geoInfo{}
	var missing []string
	seen := map[string]bool{}
	now := time.Now()
	for _, ip := range ips {
		if !isPublicIPv4(ip) || seen[ip] {
			continue
		}
		seen[ip] = true
		if info, ok := known[ip]; ok && regionFromGeo(info) != "unknown" {
			out[ip] = info
			continue
		}
		if info, ok := r.cache.Get(ip, now); ok {
			out[ip] = info
			continue
		}
		missing = append(missing, ip)
	}
	if len(missing) == 0 {
		return out
	}
	geoLookupSem <- struct{}{}
	defer func() { <-geoLookupSem }()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	infos, err := r.geo.Lookup(ctx, missing)
	if err != nil {
		return out
	}
	cacheUpdates := map[string]geoInfo{}
	for _, info := range infos {
		if info.Status == "success" && info.Query != "" {
			out[info.Query] = info
			cacheUpdates[info.Query] = info
		}
	}
	r.cache.SetMany(cacheUpdates, now)
	return out
}

func (q ipAPIGeoQuerier) Lookup(ctx context.Context, ips []string) ([]geoInfo, error) {
	body, err := json.Marshal(ips)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,isp,as", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := q.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("geo lookup status %d", resp.StatusCode)
	}
	var infos []geoInfo
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil {
		return nil, err
	}
	return infos, nil
}

func newGeoInfoCache(max int, ttl time.Duration) *geoInfoCache {
	if max <= 0 {
		max = 4096
	}
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	return &geoInfoCache{items: map[string]geoCacheEntry{}, max: max, ttl: ttl}
}

func (c *geoInfoCache) Get(ip string, now time.Time) (geoInfo, bool) {
	if c == nil {
		return geoInfo{}, false
	}
	c.RLock()
	entry, ok := c.items[ip]
	c.RUnlock()
	if !ok {
		return geoInfo{}, false
	}
	if now.After(entry.expiresAt) {
		c.Lock()
		if current, exists := c.items[ip]; exists && now.After(current.expiresAt) {
			delete(c.items, ip)
		}
		c.Unlock()
		return geoInfo{}, false
	}
	return entry.info, true
}

func (c *geoInfoCache) SetMany(infos map[string]geoInfo, now time.Time) {
	if c == nil || len(infos) == 0 {
		return
	}
	c.Lock()
	defer c.Unlock()
	for ip, info := range infos {
		c.items[ip] = geoCacheEntry{info: info, expiresAt: now.Add(c.ttl)}
	}
	c.evict(now)
}

func (c *geoInfoCache) evict(now time.Time) {
	for ip, entry := range c.items {
		if now.After(entry.expiresAt) {
			delete(c.items, ip)
		}
	}
	for len(c.items) > c.max {
		for ip := range c.items {
			delete(c.items, ip)
			break
		}
	}
}

func parseEmbeddedGeoInfos(raw string) map[string]geoInfo {
	out := map[string]geoInfo{}
	for _, line := range strings.Split(raw, "\n") {
		ips := ipv4Pattern.FindAllString(line, -1)
		if len(ips) == 0 {
			continue
		}
		info, ok := geoInfoFromTraceLine(line)
		if !ok {
			continue
		}
		for _, ip := range ips {
			if isPublicIPv4(ip) {
				info.Query = ip
				out[ip] = info
			}
		}
	}
	return out
}

func geoInfoFromTraceLine(line string) (geoInfo, bool) {
	lower := strings.ToLower(line)
	info := geoInfo{Status: "success"}
	rule, ok := matchTraceRegion(lower)
	if !ok {
		return geoInfo{}, false
	}
	info.Country = rule.country
	info.CountryCode = rule.countryCode
	info.City = rule.city
	if rule.countryCode == "JP" && strings.Contains(lower, "tokyo") {
		info.City = "Tokyo"
	}
	if rule.countryCode == "US" && strings.Contains(lower, "los angeles") {
		info.City = "Los Angeles"
	}
	if network, ok := matchTraceNetwork(lower); ok {
		info.ISP = network.isp
		info.AS = network.asn
	}
	if match := asnPattern.FindString(line); match != "" {
		if info.AS == "" {
			info.AS = match
		} else if !strings.HasPrefix(info.AS, match) {
			info.AS = match + " " + info.AS
		}
	}
	return info, true
}

func matchTraceRegion(lower string) (traceRegionRule, bool) {
	for _, rule := range traceRegionRules {
		if containsAny(lower, rule.terms) {
			return rule, true
		}
	}
	return traceRegionRule{}, false
}

func matchTraceNetwork(lower string) (traceNetworkRule, bool) {
	for _, rule := range traceNetworkRules {
		if containsAny(lower, rule.any) {
			return rule, true
		}
	}
	return traceNetworkRule{}, false
}

func containsAny(value string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func pickRouteHint(target string, hops []string, infos map[string]geoInfo) *geoInfo {
	return routeHintSelector{}.Pick(target, hops, infos)
}

func (routeHintSelector) Pick(target string, hops []string, infos map[string]geoInfo) *geoInfo {
	limit := targetLimit(target, hops)
	if info := pickLastMatchingHop(target, hops, infos, limit, isCloudflareInfo); info != nil {
		return info
	}
	return pickLastMatchingHop(target, hops, infos, limit, func(info geoInfo) bool {
		// For Anycast classification, early domestic carrier hops only describe
		// the local access path. Use the last non-mainland hop before the target
		// as the route-region hint when no Cloudflare hop is geocoded.
		return regionFromGeo(info) != "CN"
	})
}

func targetLimit(target string, hops []string) int {
	limit := len(hops)
	for i, hop := range hops {
		if hop == target {
			limit = i
			break
		}
	}
	if limit <= 0 {
		limit = len(hops)
	}
	return limit
}

func pickLastMatchingHop(target string, hops []string, infos map[string]geoInfo, limit int, match func(geoInfo) bool) *geoInfo {
	for i := limit - 1; i >= 0; i-- {
		hop := hops[i]
		if hop == target {
			continue
		}
		info, ok := infos[hop]
		if !ok {
			continue
		}
		if match(info) {
			return &info
		}
	}
	return nil
}

func shouldTryEmbeddedFallback(pick geoInfo) bool {
	text := strings.ToLower(pick.ISP + " " + pick.AS)
	return !isCloudflareInfo(pick) && (strings.Contains(text, "ntt") || strings.Contains(text, "as2914"))
}

func shouldUseEmbeddedFallback(target string, primaryHops []string, primary *geoInfo, fallbackHops []string, fallback *geoInfo) bool {
	if fallback == nil {
		return false
	}
	if primary == nil {
		return true
	}
	if isCloudflareInfo(*fallback) && !isCloudflareInfo(*primary) {
		return true
	}
	primaryConfidence := confidenceFor(target, primary.Query, primaryHops, *primary)
	fallbackConfidence := confidenceFor(target, fallback.Query, fallbackHops, *fallback)
	if regionFromGeo(*fallback) != regionFromGeo(*primary) && fallbackConfidence > primaryConfidence {
		return true
	}
	return false
}

func isCloudflareInfo(info geoInfo) bool {
	return strings.Contains(strings.ToLower(info.ISP+" "+info.AS), "cloudflare")
}

func regionFromGeo(info geoInfo) string {
	cc := strings.ToUpper(strings.TrimSpace(info.CountryCode))
	country := strings.ToLower(info.Country + " " + info.RegionName + " " + info.City)
	switch {
	case cc == "HK" || strings.Contains(country, "hong kong") || strings.Contains(country, "香港"):
		return "HK"
	case cc == "JP" || strings.Contains(country, "japan"):
		return "JP"
	case cc == "SG" || strings.Contains(country, "singapore"):
		return "SG"
	case cc == "US":
		return "US"
	case cc == "CN":
		return "CN"
	case isEUCountry(cc):
		return "EU"
	case cc != "":
		return cc
	default:
		return "unknown"
	}
}

func confidenceFor(target, hint string, hops []string, info geoInfo) float64 {
	if hint == "" {
		return 0
	}
	base := baseRouteConfidence
	for i := len(hops) - 1; i >= 0; i-- {
		if hops[i] == hint && i >= len(hops)-nearTargetHopWindow {
			base = nearTargetConfidence
			break
		}
	}
	if isCloudflareInfo(info) {
		base += cloudflareBonus
	}
	if hint == target {
		base -= targetHintPenalty
	}
	if base > maxRouteConfidence {
		return maxRouteConfidence
	}
	if base < 0 {
		return 0
	}
	return base
}

func isPublicIPv4(value string) bool {
	ip := net.ParseIP(value).To4()
	if ip == nil {
		return false
	}
	if ip[0] == 10 || ip[0] == 127 || ip[0] == 0 {
		return false
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return false
	}
	if ip[0] == 192 && ip[1] == 168 {
		return false
	}
	if ip[0] == 169 && ip[1] == 254 {
		return false
	}
	return true
}

func isEUCountry(cc string) bool {
	switch cc {
	case "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB", "CH", "NO":
		return true
	default:
		return false
	}
}
