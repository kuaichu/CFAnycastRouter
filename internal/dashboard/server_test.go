package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cf-anycast-router/internal/history"
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
