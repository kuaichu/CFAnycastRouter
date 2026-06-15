package router

import "testing"

func TestPopPenalty(t *testing.T) {
	cases := []struct {
		region string
		rtt    float64
		want   float64
	}{
		{"HK", 80, 0},
		{"JP", 80, 0},
		{"SG", 80, 0},
		{"US", 80, 100},
		{"EU", 80, 150},
		{"unknown", 90, 120},
		{"unknown", 120, 120},
	}
	for _, tc := range cases {
		if got := popPenalty(tc.region, tc.rtt); got != tc.want {
			t.Fatalf("popPenalty(%q, %.1f)=%v want %v", tc.region, tc.rtt, got, tc.want)
		}
	}
}

func TestEffectiveRegionFallsBackToCFColo(t *testing.T) {
	region, source := effectiveRegion("", "JP", "")
	if region != "JP" || source != "cf" {
		t.Fatalf("effectiveRegion without local route=%s/%s want JP/cf", region, source)
	}
	region, source = effectiveRegion("HK", "JP", "")
	if region != "HK" || source != "route" {
		t.Fatalf("effectiveRegion with local route=%s/%s want HK/route", region, source)
	}
	region, source = effectiveRegion("HK", "JP", "route trace timed out")
	if region != "JP" || source != "cf" {
		t.Fatalf("effectiveRegion with failed conflicting route=%s/%s want JP/cf", region, source)
	}
	region, source = effectiveRegion("JP", "JP", "route trace timed out")
	if region != "JP" || source != "route" {
		t.Fatalf("effectiveRegion with failed matching route=%s/%s want JP/route", region, source)
	}
}

func TestSelectableCandidateSkipsSegmentProbe(t *testing.T) {
	candidates := []Candidate{
		{IP: "172.67.177.1", Stage: "segment-probe", Region: "preflight", RouteRegion: "US", Score: 10},
		{IP: "104.20.1.1", Stage: "seed-sample", Region: "US", RouteRegion: "US", Score: 200},
	}

	if got := firstHealthy(candidates); got == nil || got.IP != "104.20.1.1" {
		t.Fatalf("firstHealthy selected %#v, want seed-sample", got)
	}
	if got := firstHealthyInRouteRegionForType(candidates, "US", "A"); got == nil || got.IP != "104.20.1.1" {
		t.Fatalf("route-region candidate selected %#v, want seed-sample", got)
	}
	if isSelectableCandidate(candidates[0]) {
		t.Fatal("segment-probe should not be selectable")
	}
}

func TestRouteRegionCandidateFallsBackToEffectiveRegion(t *testing.T) {
	candidates := []Candidate{
		{IP: "104.20.1.1", Stage: "seed-sample", Region: "unknown", CFRegion: "JP", Score: 50},
		{
			IP:          "108.162.198.4",
			Stage:       "hot",
			Region:      "HK",
			RouteRegion: "HK",
			CFRegion:    "JP",
			RouteError:  "route trace timed out",
			Score:       40,
		},
	}

	if got := firstHealthyInRouteRegionForType(candidates, "JP", "A"); got == nil || got.IP != "104.20.1.1" {
		t.Fatalf("route-region fallback selected %#v, want JP seed-sample", got)
	}
	if !isSelectableCandidate(candidates[0]) {
		t.Fatal("candidate with CF region fallback should be selectable")
	}
	if got := candidateRecordRegion(candidates[1]); got != "JP" {
		t.Fatalf("failed conflicting route record region=%s want JP", got)
	}
}
