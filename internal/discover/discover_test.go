package discover

import (
	"strings"
	"testing"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/history"
)

func TestTargetsSelectReadyLargeSeedSegmentsFairly(t *testing.T) {
	cfg := &config.Config{
		Carrier:                      "cu",
		SeedCIDRs:                    []string{"104.17.144.0/20", "104.20.16.0/20"},
		SampleStep:                   4,
		MaxSeedSegmentsPerCycle:      4,
		MaxSamplesPerSegmentPerCycle: 1,
		SeedPreflightMaxPerCycle:     16,
	}
	st := history.New()
	now := time.Now()
	for _, seg := range SeedSegments(cfg) {
		st.RecordSegmentPreflight(seg.CIDR, cfg.Carrier, seg.ProbeIP, true, "", now)
	}

	targets := Targets(cfg, st)
	counts := map[string]int{}
	for _, target := range targets {
		if target.Stage != "seed-sample" {
			continue
		}
		switch {
		case strings.HasPrefix(target.Segment, "104.17."):
			counts["104.17"]++
		case strings.HasPrefix(target.Segment, "104.20."):
			counts["104.20"]++
		}
	}
	if counts["104.17"] == 0 || counts["104.20"] == 0 {
		t.Fatalf("ready seed samples were not spread across parents: %#v targets=%#v", counts, targets)
	}
	if got := counts["104.17"] + counts["104.20"]; got != cfg.MaxSeedSegmentsPerCycle {
		t.Fatalf("seed sample segment count=%d want %d: %#v", got, cfg.MaxSeedSegmentsPerCycle, counts)
	}
}

func TestTargetsCanSampleEveryReadySeedSegment(t *testing.T) {
	cfg := &config.Config{
		Carrier:                      "cu",
		SeedCIDRs:                    []string{"104.17.144.0/20", "104.20.16.0/20"},
		SampleAllSeedSegments:        true,
		MaxSeedSegmentsPerCycle:      4,
		MaxSamplesPerSegmentPerCycle: 1,
		SeedPreflightMaxPerCycle:     32,
	}
	st := history.New()
	now := time.Now()
	segments := SeedSegments(cfg)
	for _, seg := range segments {
		st.RecordSegmentPreflight(seg.CIDR, cfg.Carrier, seg.ProbeIP, true, "", now)
	}

	targets := Targets(cfg, st)
	seenSegments := map[string]int{}
	for _, target := range targets {
		if target.Stage == "seed-sample" {
			seenSegments[target.Segment]++
		}
	}
	if len(seenSegments) != len(segments) {
		t.Fatalf("sampled segments=%d want all %d: %#v", len(seenSegments), len(segments), seenSegments)
	}
	for segment, count := range seenSegments {
		if count != cfg.MaxSamplesPerSegmentPerCycle {
			t.Fatalf("segment %s sample count=%d want %d", segment, count, cfg.MaxSamplesPerSegmentPerCycle)
		}
	}
}
