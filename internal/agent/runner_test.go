package agent

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/protocol"
	"cf-anycast-router/internal/router"
)

func TestApplyAssignmentUsesManagedAgentMetadata(t *testing.T) {
	cfg := &config.Config{ProbeSource: "local", Carrier: "ct"}
	runner := &Runner{cfg: cfg}

	runner.applyAssignment(protocol.AgentAssignment{
		ProbeSource: "Los Angeles",
		Carrier:     "cu",
	})

	if cfg.ProbeSource != "Los Angeles" || cfg.Carrier != "cu" {
		t.Fatalf("managed metadata was not applied: source=%q carrier=%q", cfg.ProbeSource, cfg.Carrier)
	}
}

func TestPostReportAcceptsFailedCandidatesWithInfiniteScore(t *testing.T) {
	var received protocol.AgentReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode report: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runner := &Runner{
		cfg:    &config.Config{ServerURL: server.URL},
		client: server.Client(),
	}
	err := runner.postReport(context.Background(), protocol.AgentReport{
		AgentID: "vps-01",
		Result: &router.CycleResult{
			Candidates: []router.Candidate{{IP: "104.20.1.1", Score: math.Inf(1), Error: "probe failed"}},
		},
	})
	if err != nil {
		t.Fatalf("post report: %v", err)
	}
	if received.Result == nil || len(received.Result.Candidates) != 1 {
		t.Fatalf("missing candidates in report: %#v", received)
	}
	if math.IsInf(received.Result.Candidates[0].Score, 0) || math.IsNaN(received.Result.Candidates[0].Score) {
		t.Fatalf("report contains non-finite score: %#v", received.Result.Candidates[0])
	}
}

func TestBestCandidateSkipsSegmentProbe(t *testing.T) {
	got := bestCandidate([]router.Candidate{
		{IP: "172.67.177.1", Stage: "segment-probe", Region: "preflight", Score: 10},
		{IP: "104.20.1.1", Stage: "seed-sample", Region: "US", Score: 200},
	})
	if got == nil || got.IP != "104.20.1.1" {
		t.Fatalf("bestCandidate=%#v, want seed-sample", got)
	}
}
