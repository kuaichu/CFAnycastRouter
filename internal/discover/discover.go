package discover

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/history"
)

type CandidateIP struct {
	IP      string
	Pool    string
	Carrier string
	POP     string
}

type Target struct {
	IP      string
	Stage   string
	Segment string
	Carrier string
	Weight  float64
}

type SeedSegment struct {
	CIDR     string
	Large    bool
	ProbeIP  string
	Parent   string
	Position int
}

func Targets(cfg *config.Config, st *history.State) []Target {
	seen := map[string]Target{}
	for _, ip := range cfg.SeedIPs {
		cidr, ok := IPv4Slash24(ip)
		if !ok {
			continue
		}
		putTarget(seen, Target{IP: ip, Stage: "seed", Segment: cidr, Carrier: cfg.Carrier, Weight: 1})
	}
	readyLarge := 0
	preflightCount := 0
	var readyLargeSegments []SeedSegment
	for _, seg := range SeedSegments(cfg) {
		if seg.Large {
			profile := segmentProfile(st, cfg.Carrier, seg.CIDR)
			if profile != nil && profile.PreflightOK {
				readyLargeSegments = append(readyLargeSegments, seg)
				continue
			}
			if profile != nil && !profile.PreflightAt.IsZero() && time.Since(profile.PreflightAt) < time.Hour {
				continue
			}
			if preflightCount >= cfg.SeedPreflightMaxPerCycle {
				continue
			}
			preflightCount++
			putTarget(seen, Target{IP: seg.ProbeIP, Stage: "segment-probe", Segment: seg.CIDR, Carrier: cfg.Carrier, Weight: 0.5})
			continue
		}
		for _, sample := range seedSegmentSamples(seg.CIDR, cfg) {
			putTarget(seen, Target{IP: sample, Stage: "seed-sample", Segment: seg.CIDR, Carrier: cfg.Carrier, Weight: 1})
		}
	}
	for _, seg := range selectReadySeedSegments(readyLargeSegments, cfg.MaxSeedSegmentsPerCycle, cfg.SampleAllSeedSegments) {
		if !cfg.SampleAllSeedSegments && readyLarge >= cfg.MaxSeedSegmentsPerCycle {
			break
		}
		readyLarge++
		for _, sample := range seedSegmentSamples(seg.CIDR, cfg) {
			putTarget(seen, Target{IP: sample, Stage: "seed-sample", Segment: seg.CIDR, Carrier: cfg.Carrier, Weight: 1})
		}
	}
	if st != nil {
		learnedCount := 0
		for _, seg := range st.Segments {
			if seg.Carrier != cfg.Carrier {
				continue
			}
			for _, hot := range seg.HotIPs {
				putTarget(seen, Target{IP: hot.IP, Stage: "hot", Segment: seg.CIDR, Carrier: seg.Carrier, Weight: 4})
			}
			if !seg.Promoted {
				continue
			}
			if learnedCount >= cfg.MaxLearnedSegmentsPerCycle {
				continue
			}
			learnedCount++
			start := seg.ScanCursor
			samples := SegmentSamples(seg.CIDR, cfg.SampleStep, start, cfg.MaxSamplesPerSegmentPerCycle)
			seg.ScanCursor += cfg.MaxSamplesPerSegmentPerCycle * cfg.SampleStep
			for _, sample := range samples {
				putTarget(seen, Target{IP: sample, Stage: "learned", Segment: seg.CIDR, Carrier: seg.Carrier, Weight: seg.Weight})
			}
		}
	}
	out := make([]Target, 0, len(seen))
	for _, target := range seen {
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool {
		if stageRank(out[i].Stage) != stageRank(out[j].Stage) {
			return stageRank(out[i].Stage) < stageRank(out[j].Stage)
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func SeedSegments(cfg *config.Config) []SeedSegment {
	seen := map[string]bool{}
	out := make([]SeedSegment, 0, cfg.MaxSeedSegmentsPerCycle)
	add := func(seg SeedSegment) {
		if seg.CIDR == "" || seen[seg.CIDR] {
			return
		}
		seen[seg.CIDR] = true
		if seg.ProbeIP == "" {
			seg.ProbeIP = firstHost(seg.CIDR)
		}
		if seg.Parent == "" {
			seg.Parent = seg.CIDR
		}
		out = append(out, seg)
	}
	for _, ip := range cfg.SeedIPs {
		cidr, ok := IPv4Slash24(ip)
		if ok {
			add(SeedSegment{CIDR: cidr, ProbeIP: ip, Parent: cidr})
		}
	}
	for _, raw := range cfg.SeedCIDRs {
		parent := strings.TrimSpace(raw)
		ip, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		base := ip.To4()
		if base == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if bits != 32 {
			continue
		}
		if ones >= 24 {
			cidr, ok := IPv4Slash24(base.String())
			if ok {
				add(SeedSegment{CIDR: cidr, Parent: parent})
			}
			continue
		}
		start := ipv4ToUint(base) & maskToUint(ones)
		total := uint32(1) << uint32(32-ones)
		if total < 256 {
			continue
		}
		if ones < 24 {
			segments := int(total / 256)
			for i := 0; i < segments; i++ {
				cidr := segmentCIDRFromUint(start + uint32(i)*256)
				add(SeedSegment{CIDR: cidr, Large: true, ProbeIP: ipFromUint(start + uint32(i)*256 + 1), Parent: parent, Position: i})
			}
			continue
		}
		step := uint32(cfg.SeedCIDRStep)
		if step < 1 {
			step = 16
		}
		for offset := uint32(0); offset < total && len(out) < cfg.MaxSeedSegmentsPerCycle; offset += step * 256 {
			add(SeedSegment{CIDR: segmentCIDRFromUint(start + offset), Parent: parent})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

func seedSegmentSamples(cidr string, cfg *config.Config) []string {
	if cfg.SampleAllSeedSegments {
		return RandomSamples(cidr, cfg.MaxSamplesPerSegmentPerCycle)
	}
	return SegmentSamples(cidr, cfg.SampleStep, randomStart(cidr), cfg.MaxSamplesPerSegmentPerCycle)
}

func selectReadySeedSegments(segments []SeedSegment, limit int, all bool) []SeedSegment {
	if all {
		return segments
	}
	if limit <= 0 || len(segments) <= limit {
		return segments
	}
	byParent := map[string][]SeedSegment{}
	var parents []string
	for _, seg := range segments {
		parent := seg.Parent
		if parent == "" {
			parent = seg.CIDR
		}
		if _, ok := byParent[parent]; !ok {
			parents = append(parents, parent)
		}
		byParent[parent] = append(byParent[parent], seg)
	}
	out := make([]SeedSegment, 0, limit)
	for len(out) < limit {
		added := false
		for _, parent := range parents {
			group := byParent[parent]
			if len(group) == 0 {
				continue
			}
			out = append(out, group[0])
			byParent[parent] = group[1:]
			added = true
			if len(out) >= limit {
				break
			}
		}
		if !added {
			break
		}
	}
	return out
}

func segmentProfile(st *history.State, carrier, cidr string) *history.SegmentProfile {
	if st == nil || st.Segments == nil {
		return nil
	}
	return st.Segments[carrier+"|"+cidr]
}

func putTarget(seen map[string]Target, target Target) {
	existing, ok := seen[target.IP]
	if !ok || stageRank(target.Stage) < stageRank(existing.Stage) {
		seen[target.IP] = target
	}
}

func stageRank(stage string) int {
	switch stage {
	case "hot":
		return 0
	case "learned":
		return 1
	case "seed":
		return 2
	case "segment-probe":
		return 3
	case "seed-sample":
		return 4
	default:
		return 9
	}
}

func firstHost(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	base := ip.To4()
	if base == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.1", base[0], base[1], base[2])
}

func IPv4Slash24(ip string) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.0/24", parsed[0], parsed[1], parsed[2]), true
}

func SegmentSamples(cidr string, step, start, limit int) []string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	base := ip.To4()
	if base == nil {
		return nil
	}
	if step < 1 {
		step = 4
	}
	if limit < 1 {
		limit = 8
	}
	out := make([]string, 0, limit)
	offset := positiveMod(start, 254)
	if offset < 1 {
		offset = 1
	}
	for tries := 0; len(out) < limit && tries < 254; tries++ {
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], offset))
		offset += step
		if offset > 254 {
			offset = ((offset - 1) % 254) + 1
		}
	}
	return out
}

func RandomSamples(cidr string, limit int) []string {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || limit <= 0 {
		return nil
	}
	base := ip.To4()
	if base == nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return nil
	}
	start := ipv4ToUint(base) & maskToUint(ones)
	size := uint32(1) << uint32(32-ones)
	if size <= 2 {
		return nil
	}
	if int(size-2) < limit {
		limit = int(size - 2)
	}
	seen := map[uint32]bool{}
	out := make([]string, 0, limit)
	r := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(start)))
	for len(out) < limit && len(seen) < int(size-2) {
		offset := uint32(r.Intn(int(size-2))) + 1
		if seen[offset] {
			continue
		}
		seen[offset] = true
		out = append(out, ipFromUint(start+offset))
	}
	sort.Strings(out)
	return out
}

func positiveMod(v, m int) int {
	if m <= 0 {
		return v
	}
	r := v % m
	if r < 0 {
		return r + m
	}
	return r
}

func randomStart(cidr string) int {
	h := uint32(2166136261)
	for _, b := range []byte(cidr) {
		h ^= uint32(b)
		h *= 16777619
	}
	return int((uint64(h) + uint64(time.Now().UnixNano())) % 254)
}

func ipv4ToUint(ip net.IP) uint32 {
	v4 := ip.To4()
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func maskToUint(ones int) uint32 {
	if ones <= 0 {
		return 0
	}
	return ^uint32(0) << uint32(32-ones)
}

func segmentCIDRFromUint(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.0/24", byte(v>>24), byte(v>>16), byte(v>>8))
}

func ipFromUint(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func FromPools(pools []config.PoolConfig) []CandidateIP {
	seen := map[string]CandidateIP{}
	for _, pool := range pools {
		for _, raw := range pool.IPs {
			ip := strings.TrimSpace(raw)
			if ip == "" {
				continue
			}
			key := pool.Carrier + "|" + pool.POP + "|" + ip
			seen[key] = CandidateIP{
				IP:      ip,
				Pool:    pool.Name,
				Carrier: pool.Carrier,
				POP:     pool.POP,
			}
		}
	}
	out := make([]CandidateIP, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Carrier != out[j].Carrier {
			return out[i].Carrier < out[j].Carrier
		}
		if out[i].POP != out[j].POP {
			return out[i].POP < out[j].POP
		}
		if out[i].Pool != out[j].Pool {
			return out[i].Pool < out[j].Pool
		}
		return out[i].IP < out[j].IP
	})
	return out
}
