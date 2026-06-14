package agent

import (
	"testing"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/protocol"
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
