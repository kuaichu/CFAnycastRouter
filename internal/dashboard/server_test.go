package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cf-anycast-router/internal/history"
	"cf-anycast-router/internal/protocol"
	"cf-anycast-router/internal/router"
)

func TestLastSnapshotCopiesCandidatesUnderLock(t *testing.T) {
	s := New(0, "", "", nil, nil, nil, nil, nil)
	s.SetLast(&router.CycleResult{
		Candidates: []router.Candidate{
			{IP: "104.20.23.137", Score: 42},
		},
	})

	got := s.lastSnapshot()
	if got == nil {
		t.Fatal("snapshot is nil")
	}
	if len(got.Candidates) != 1 || got.Candidates[0].IP != "104.20.23.137" {
		t.Fatalf("unexpected candidates: %#v", got.Candidates)
	}

	s.UpsertCandidate(router.Candidate{IP: "104.20.23.138", Score: 43})
	if len(got.Candidates) != 1 {
		t.Fatalf("snapshot changed after server mutation: %#v", got.Candidates)
	}
}

func TestShutdownHandlerPausesAutomaticScanning(t *testing.T) {
	var action string
	s := New(0, "", "", nil, nil, nil, nil, func(next string) (ControlStatus, error) {
		action = next
		return ControlStatus{Paused: true, Message: "automatic scanning is paused"}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	rec := httptest.NewRecorder()
	s.handleShutdown(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if action != "stop" {
		t.Fatalf("action=%q want stop", action)
	}
	if !strings.Contains(rec.Body.String(), `"paused":true`) {
		t.Fatalf("expected paused response, got %s", rec.Body.String())
	}
}

func TestStateSummaryDoesNotReturnFullHistory(t *testing.T) {
	path := t.TempDir() + "/state.json"
	st := history.New()
	st.CurrentIP = "172.67.73.253"
	st.LastDecision = "kept current"
	st.Profiles["104.20.23.137"] = &history.IPProfile{IP: "104.20.23.137"}
	if err := st.Save(path); err != nil {
		t.Fatalf("save state: %v", err)
	}

	s := New(0, path, "", nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/state-summary", nil)
	rec := httptest.NewRecorder()
	s.handleStateSummary(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, `"current_ip":"172.67.73.253"`) {
		t.Fatalf("summary missing current IP: %s", body)
	}
	if strings.Contains(body, `"profiles"`) {
		t.Fatalf("summary leaked full profiles: %s", body)
	}
}

func TestAgentBinaryDownload(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	root := filepath.Clean(filepath.Join(originalDir, "..", ".."))
	if err := os.Chdir(root); err != nil {
		t.Fatalf("change to repository root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	s := New(0, "", "", nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodHead, "/download/cf-router-linux-amd64", nil)
	rec := httptest.NewRecorder()
	s.handleAgentBinary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Fatal("download response is missing Content-Length")
	}

	req = httptest.NewRequest(http.MethodGet, "/download/../../config.yaml", nil)
	rec = httptest.NewRecorder()
	s.handleAgentBinary(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalid download status=%d want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAgentBinaryPathUsesRunningExecutableForCurrentPlatform(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable path: %v", err)
	}
	name := "cf-router-" + runtime.GOOS + "-" + runtime.GOARCH
	if got := agentBinaryPath(name); got != executable {
		t.Fatalf("binary path=%q want running executable %q", got, executable)
	}
}

func TestNormalizeShellScriptRemovesCRLF(t *testing.T) {
	got := normalizeShellScript([]byte("#!/usr/bin/env bash\r\nset -euo pipefail\r\n"))
	if strings.Contains(string(got), "\r") {
		t.Fatalf("script still contains carriage returns: %q", got)
	}
	if string(got) != "#!/usr/bin/env bash\nset -euo pipefail\n" {
		t.Fatalf("unexpected normalized script: %q", got)
	}
}

func TestAgentCandidatesAreGroupedByCarrierAndFreshness(t *testing.T) {
	registry := newAgentRegistry()
	registry.upsert(protocol.AgentReport{
		AgentID: "cu-01",
		Carrier: "cu",
		Result:  &router.CycleResult{Candidates: []router.Candidate{{IP: "104.20.1.1", Carrier: "cu"}}},
	})
	registry.upsert(protocol.AgentReport{
		AgentID: "ct-01",
		Carrier: "ct",
		Result:  &router.CycleResult{Candidates: []router.Candidate{{IP: "104.20.2.2", Carrier: "ct"}}},
	})
	stale := registry.agents["cu-01"]
	stale.LastSeen = time.Now().Add(-time.Hour)
	registry.agents["cu-01"] = stale

	if got := registry.candidatesByCarrier("cu", 15*time.Minute); len(got) != 0 {
		t.Fatalf("stale CU candidates were included: %#v", got)
	}
	registry.upsert(protocol.AgentReport{
		AgentID: "cu-02",
		Carrier: "cu",
		Result:  &router.CycleResult{Candidates: []router.Candidate{{IP: "104.20.3.3", Carrier: "cu"}}},
	})
	got := registry.candidatesByCarrier("cu", 15*time.Minute)
	if len(got) != 1 || got[0].IP != "104.20.3.3" {
		t.Fatalf("unexpected CU candidates: %#v", got)
	}
}

func TestAgentRegistryPersistsAndRemovesSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	registry := newAgentRegistry(path)
	registry.upsert(protocol.AgentReport{AgentID: "cu-01", Hostname: "edge-01", Carrier: "cu"})

	reloaded := newAgentRegistry(path)
	items := reloaded.list()
	if len(items) != 1 || items[0].AgentID != "cu-01" || items[0].FirstSeen.IsZero() {
		t.Fatalf("unexpected persisted agents: %#v", items)
	}
	if !reloaded.remove("cu-01") {
		t.Fatal("expected persisted agent to be removed")
	}
	if got := newAgentRegistry(path).list(); len(got) != 0 {
		t.Fatalf("removed agent returned after reload: %#v", got)
	}
}

func TestAgentHeartbeatPreservesLastMeasurement(t *testing.T) {
	registry := newAgentRegistry()
	registry.upsert(protocol.AgentReport{
		AgentID: "cu-01",
		Carrier: "cu",
		Result: &router.CycleResult{
			Candidates: []router.Candidate{{IP: "104.20.1.1"}},
			Best:       &router.Candidate{IP: "104.20.1.1"},
		},
	})
	registry.upsert(protocol.AgentReport{AgentID: "cu-01", Carrier: "cu"})

	got := registry.list()
	if len(got) != 1 || got[0].Result == nil || got[0].CandidateCount != 1 || got[0].Best == nil {
		t.Fatalf("heartbeat discarded measurement: %#v", got)
	}
}

func TestAgentRegistryRecordsScanStatusAndErrors(t *testing.T) {
	registry := newAgentRegistry()
	registry.upsert(protocol.AgentReport{AgentID: "cu-01", Carrier: "cu", Status: "scanning"})
	registry.upsert(protocol.AgentReport{AgentID: "cu-01", Carrier: "cu", Status: "error", Error: "save state failed"})

	got := registry.list()
	if len(got) != 1 || got[0].Status != "error" || got[0].LastError != "save state failed" {
		t.Fatalf("agent status was not retained: %#v", got)
	}
}

func TestManagedAgentConfigurationOverridesReportedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	registry := newAgentRegistry(path)
	configured, err := registry.configure(protocol.AgentConfig{
		AgentID:     "vps-01",
		DisplayName: "洛杉矶联通",
		ProbeSource: "Los Angeles",
		Carrier:     "cu",
	})
	if err != nil {
		t.Fatalf("configure agent: %v", err)
	}
	if !configured.Managed || !configured.LastSeen.IsZero() {
		t.Fatalf("unexpected configured snapshot: %#v", configured)
	}

	registry.upsert(protocol.AgentReport{
		AgentID:     "vps-01",
		Hostname:    "edge-host",
		ProbeSource: "agent-local-value",
		Carrier:     "ct",
	})

	got, ok := newAgentRegistry(path).get("vps-01")
	if !ok {
		t.Fatal("managed agent was not persisted")
	}
	if got.DisplayName != "洛杉矶联通" || got.ProbeSource != "Los Angeles" || got.Carrier != "cu" {
		t.Fatalf("report overwrote managed metadata: %#v", got)
	}
	if got.Hostname != "edge-host" || got.FirstSeen.IsZero() || got.LastSeen.IsZero() {
		t.Fatalf("report metadata was not recorded: %#v", got)
	}
}
