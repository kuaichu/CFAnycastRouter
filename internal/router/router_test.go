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

func TestEffectiveRegionDoesNotFallBackToCFColo(t *testing.T) {
	region, source := effectiveRegion("", "JP", 0, 0)
	if region != "unknown" || source != "unknown" {
		t.Fatalf("effectiveRegion without local route=%s/%s want unknown/unknown", region, source)
	}
	region, source = effectiveRegion("HK", "JP", 0, 0)
	if region != "HK" || source != "route" {
		t.Fatalf("effectiveRegion with local route=%s/%s want HK/route", region, source)
	}
}
