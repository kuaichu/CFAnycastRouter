package router

import "math"

// JSONSafeCycleResult returns a copy whose floating-point values can be encoded
// by encoding/json. Failed probes use infinite scores internally for sorting.
func JSONSafeCycleResult(in *CycleResult) *CycleResult {
	if in == nil {
		return nil
	}
	out := *in
	if in.Best != nil {
		best := JSONSafeCandidate(*in.Best)
		out.Best = &best
	}
	out.Candidates = make([]Candidate, len(in.Candidates))
	for i, candidate := range in.Candidates {
		out.Candidates[i] = JSONSafeCandidate(candidate)
	}
	return &out
}

func JSONSafeCandidate(candidate Candidate) Candidate {
	candidate.RouteConfidence = finiteOr(candidate.RouteConfidence, 0)
	candidate.CFSpeedRTTMs = finiteOr(candidate.CFSpeedRTTMs, 0)
	candidate.CFSpeedJitterMs = finiteOr(candidate.CFSpeedJitterMs, 0)
	candidate.CFSpeedLossRate = finiteOr(candidate.CFSpeedLossRate, 1)
	candidate.CFSpeedMbps = finiteOr(candidate.CFSpeedMbps, 0)
	candidate.PingRTTMs = finiteOr(candidate.PingRTTMs, 0)
	candidate.PingLossRate = finiteOr(candidate.PingLossRate, 1)
	candidate.AvgRTTMs = finiteOr(candidate.AvgRTTMs, 0)
	candidate.JitterMs = finiteOr(candidate.JitterMs, 0)
	candidate.LossRate = finiteOr(candidate.LossRate, 1)
	candidate.SpikeRate = finiteOr(candidate.SpikeRate, 0)
	candidate.Score = finiteOr(candidate.Score, 999999)
	candidate.PopPenalty = finiteOr(candidate.PopPenalty, 0)
	candidate.DriftPenalty = finiteOr(candidate.DriftPenalty, 0)
	candidate.HijackPenalty = finiteOr(candidate.HijackPenalty, 0)
	candidate.LearnedBonus = finiteOr(candidate.LearnedBonus, 0)
	return candidate
}

func finiteOr(value, fallback float64) float64 {
	if math.IsInf(value, 0) || math.IsNaN(value) {
		return fallback
	}
	return value
}
