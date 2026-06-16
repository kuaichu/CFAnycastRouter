package dashboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/history"
	"cf-anycast-router/internal/router"
)

type ScanFunc func() (*router.CycleResult, error)
type SeedsFunc func(ips, cidrs []string) error
type LookupFunc func(ip string) (*router.RangeValidation, error)
type SettingsFunc func(*config.Config) error
type ControlFunc func(action string) (ControlStatus, error)

type ControlStatus struct {
	Paused   bool   `json:"paused"`
	Scanning bool   `json:"scanning"`
	Message  string `json:"message,omitempty"`
}

type Server struct {
	port          int
	statePath     string
	cfgPath       string
	onScan        ScanFunc
	onSeeds       SeedsFunc
	onLookup      LookupFunc
	onSettings    SettingsFunc
	onControl     ControlFunc
	agentTokenEnv string
	agents        *agentRegistry
	mu            sync.RWMutex
	dnsMu         sync.Mutex
	last          *router.CycleResult
	scanning      bool
	server        *http.Server
}

func New(port int, statePath, cfgPath string, onScan ScanFunc, onSeeds SeedsFunc, onLookup LookupFunc, onSettings SettingsFunc, onControl ControlFunc) *Server {
	agentStatePath := ""
	if strings.TrimSpace(statePath) != "" {
		agentStatePath = filepath.Join(filepath.Dir(statePath), "agents.json")
	}
	return &Server{port: port, statePath: statePath, cfgPath: cfgPath, onScan: onScan, onSeeds: onSeeds, onLookup: onLookup, onSettings: onSettings, onControl: onControl, agents: newAgentRegistry(agentStatePath)}
}

func (s *Server) SetAgentTokenEnv(name string) {
	s.agentTokenEnv = strings.TrimSpace(name)
}

func (s *Server) SetLast(result *router.CycleResult) {
	s.mu.Lock()
	s.last = result
	s.scanning = false
	s.mu.Unlock()
}

func (s *Server) BeginScan(currentIP, carrier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanning = true
	if s.last != nil {
		s.last.Time = time.Now()
		s.last.CurrentIP = currentIP
		s.last.Carrier = carrier
		s.last.Decision = fmt.Sprintf("正在扫描，保留上一轮 %d 个候选并实时更新", len(s.last.Candidates))
		return
	}
	s.last = &router.CycleResult{
		Time:       time.Now(),
		Carrier:    carrier,
		CurrentIP:  currentIP,
		Decision:   "正在扫描，等待首个候选返回",
		Candidates: []router.Candidate{},
	}
}

func (s *Server) EndScan() {
	s.mu.Lock()
	s.scanning = false
	s.mu.Unlock()
}

func (s *Server) UpsertCandidate(candidate router.Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last = &router.CycleResult{
			Time:       time.Now(),
			Carrier:    candidate.Carrier,
			Decision:   "正在扫描",
			Candidates: []router.Candidate{},
		}
	}
	replaced := false
	for i := range s.last.Candidates {
		if s.last.Candidates[i].IP == candidate.IP {
			s.last.Candidates[i] = candidate
			replaced = true
			break
		}
	}
	if !replaced {
		s.last.Candidates = append(s.last.Candidates, candidate)
	}
	s.last.Decision = fmt.Sprintf("正在扫描，已返回 %d 个候选", len(s.last.Candidates))
	s.last.Time = time.Now()
	s.last.Best = bestPartial(s.last.Candidates)
}

func (s *Server) Start() {
	if s.port <= 0 {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/install.sh", s.handleInstallScript)
	mux.HandleFunc("/download/", s.handleAgentBinary)
	mux.HandleFunc("/source.tar.gz", s.handleSourceArchive)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/state-summary", s.handleStateSummary)
	mux.HandleFunc("/api/last", s.handleLast)
	mux.HandleFunc("/api/seeds", s.handleSeeds)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/lookup-ip", s.handleLookupIP)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/control", s.handleControl)
	mux.HandleFunc("/api/shutdown", s.handleShutdown)
	mux.HandleFunc("/api/agents", s.handleAgents)
	mux.HandleFunc("/api/agent/config", s.handleAgentConfig)
	mux.HandleFunc("/api/agent/report", s.handleAgentReport)
	s.server = &http.Server{Addr: fmt.Sprintf(":%d", s.port), Handler: mux}
	go func() {
		log.Printf("[dashboard] http://0.0.0.0:%d", s.port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[dashboard] error: %v", err)
		}
	}()
}

func bestPartial(candidates []router.Candidate) *router.Candidate {
	var best *router.Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.Error != "" || c.Quarantined || c.Region == "" || c.Region == "unknown" || math.IsInf(c.Score, 0) {
			continue
		}
		if best == nil || c.Score < best.Score {
			best = c
		}
	}
	return best
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, nil)
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(".", "install.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "install.sh not found: "+err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(normalizeShellScript(data))
}

func normalizeShellScript(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/download/")
	switch name {
	case "cf-router-linux-amd64", "cf-router-linux-arm64":
	default:
		http.NotFound(w, r)
		return
	}

	path := agentBinaryPath(name)
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "agent binary not found: "+err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeFile(w, r, path)
}

func agentBinaryPath(name string) string {
	currentName := fmt.Sprintf("cf-router-%s-%s", runtime.GOOS, runtime.GOARCH)
	if name == currentName {
		if executable, err := os.Executable(); err == nil {
			return executable
		}
	}
	return filepath.Join(".", "dist", name)
}

func (s *Server) handleSourceArchive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="cf-anycast-router-source.tar.gz"`)
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	root, err := filepath.Abs(".")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skipArchivePath(rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		log.Printf("[dashboard] source archive failed: %v", err)
	}
}

func skipArchivePath(rel string, isDir bool) bool {
	first := rel
	if idx := strings.IndexByte(rel, '/'); idx >= 0 {
		first = rel[:idx]
	}
	switch first {
	case ".git", "data", "out":
		return true
	}
	base := filepath.Base(rel)
	if strings.HasSuffix(base, ".log") || strings.HasSuffix(base, ".err") || strings.HasSuffix(base, ".pid") {
		return true
	}
	if base == "cf-router" || strings.HasPrefix(base, "cf-router") || strings.HasSuffix(base, ".exe") || strings.HasSuffix(base, ".dll") || strings.HasSuffix(base, ".sys") {
		return true
	}
	if isDir && (base == "tmp" || base == "node_modules") {
		return true
	}
	return false
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st, err := history.Load(s.statePath)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("full") != "1" {
		writeStateSummary(w, st)
		return
	}
	writeJSON(w, st)
}

func (s *Server) handleStateSummary(w http.ResponseWriter, r *http.Request) {
	st, err := history.Load(s.statePath)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeStateSummary(w, st)
}

func writeStateSummary(w http.ResponseWriter, st *history.State) {
	writeJSON(w, map[string]any{
		"current_ip":          st.CurrentIP,
		"current_score":       st.CurrentScore,
		"last_decision":       st.LastDecision,
		"last_decision_time":  st.LastDecisionTime,
		"last_output_summary": st.LastOutputSummary,
	})
}

func (s *Server) handleLast(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.lastSnapshot())
}

func (s *Server) lastSnapshot() *router.CycleResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return safeCycleResult(s.last)
}

func (s *Server) handleSeeds(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg, err := config.Load(s.cfgPath)
		if err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{
			"seed_ips":   cfg.SeedIPs,
			"seed_cidrs": cfg.SeedCIDRs,
			"text":       seedText(cfg.SeedIPs, cfg.SeedCIDRs),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Seeds string `json:"seeds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	ips, cidrs, err := config.SaveSeeds(s.cfgPath, body.Seeds)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	if s.onSeeds != nil {
		if err := s.onSeeds(ips, cidrs); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, map[string]any{"ok": true, "seed_ips": len(ips), "seed_cidrs": len(cidrs)})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.onScan == nil {
		writeJSON(w, map[string]string{"error": "scan callback is not configured"})
		return
	}
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		writeJSON(w, map[string]string{"error": "scan already running"})
		return
	}
	s.scanning = true
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			s.scanning = false
			s.mu.Unlock()
		}()
		result, err := s.onScan()
		if err != nil {
			log.Printf("[dashboard] scan failed: %v", err)
			return
		}
		s.SetLast(result)
	}()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleLookupIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.onLookup == nil {
		writeJSON(w, map[string]string{"error": "lookup callback is not configured"})
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	result, err := s.onLookup(body.IP)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	if result != nil && len(result.Samples) > 0 {
		s.SetLast(&router.CycleResult{
			Carrier:    "",
			CurrentIP:  "",
			Decision:   result.Reason,
			Candidates: result.Samples,
		})
	}
	writeJSON(w, safeRangeValidation(result))
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg, err := config.Load(s.cfgPath)
		if err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, cfg.ManageSettings())
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body config.ManageSettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	cfg, err := config.SaveManageSettings(s.cfgPath, body)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	if s.onSettings != nil {
		if err := s.onSettings(cfg); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, map[string]any{"ok": true, "settings": cfg.ManageSettings()})
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		status, err := s.control("status")
		if err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, status)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	status, err := s.control(body.Action)
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status)
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status, err := s.control("stop")
	if err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status)
}

func (s *Server) control(action string) (ControlStatus, error) {
	var status ControlStatus
	if s.onControl != nil {
		var err error
		status, err = s.onControl(action)
		if err != nil {
			return status, err
		}
	} else {
		status.Message = "control callback is not configured"
	}
	s.mu.RLock()
	status.Scanning = s.scanning
	s.mu.RUnlock()
	return status, nil
}

func seedText(ips, cidrs []string) string {
	out := make([]string, 0, len(ips)+len(cidrs))
	out = append(out, ips...)
	out = append(out, cidrs...)
	return strings.Join(out, "\n")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "json encode failed: "+err.Error(), http.StatusInternalServerError)
	}
}

func safeCycleResult(in *router.CycleResult) *router.CycleResult {
	return router.JSONSafeCycleResult(in)
}

func safeRangeValidation(in *router.RangeValidation) *router.RangeValidation {
	if in == nil {
		return nil
	}
	out := *in
	out.Samples = make([]router.Candidate, len(in.Samples))
	for i, c := range in.Samples {
		out.Samples[i] = safeCandidate(c)
	}
	if in.Fallback != nil {
		out.Fallback = safeRangeValidation(in.Fallback)
	}
	return &out
}

func safeCandidate(c router.Candidate) router.Candidate {
	return router.JSONSafeCandidate(c)
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CF Anycast Router</title>
<style>
:root{color-scheme:dark;--bg:#0b0f14;--panel:#121820;--muted:#8a96a8;--text:#eef3f8;--line:#253040;--ok:#36d399;--warn:#f7c948;--bad:#ff6b6b}
body{margin:0;background:#0b0f14;color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
body.modal-open{position:fixed;width:100%;overflow:hidden}
main{max-width:1280px;margin:0 auto;padding:28px}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}
.top-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
h1{font-size:28px;margin:0}
.hint{color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.settings{display:grid;grid-template-columns:minmax(280px,420px) 1fr;gap:12px;margin-top:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.k{color:var(--muted);font-size:12px}.v{font:22px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;margin-top:4px;overflow-wrap:anywhere}
.seedbox{width:100%;min-height:132px;box-sizing:border-box;background:#0b1118;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:10px;font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;resize:vertical}
.lookup-row{display:flex;gap:8px;margin-top:10px}
.lookup-row input{flex:1;background:#0b1118;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font:13px ui-monospace,SFMono-Regular,Consolas,monospace;min-width:0}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
button{background:#1b2532;color:var(--text);border:1px solid #344255;border-radius:6px;padding:8px 12px;cursor:pointer}
button:hover{border-color:#5b7190}button.primary{background:#123325;border-color:#236a4b;color:#d8fff0}
button.ghost{background:transparent}button.danger{background:#3a151a;border-color:#7b2732;color:#ffd7dc}button.danger:hover{border-color:#d14b5d}button:disabled{opacity:.55;cursor:not-allowed}
.small{font-size:12px;color:var(--muted);margin-top:8px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;padding:24px;z-index:10;overscroll-behavior:none}
.modal.open{display:flex}
.modal-card{width:min(1120px,calc(100vw - 48px));max-height:calc(100vh - 48px);overflow:auto;overscroll-behavior:contain;background:linear-gradient(135deg,#101820,#0f2929);border:1px solid #31546a;border-radius:12px;padding:24px;box-shadow:0 20px 80px rgba(0,0,0,.45)}
.modal-head{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;margin-bottom:18px}
.modal h2{font-size:24px;margin:0}.settings-layout{display:grid;grid-template-columns:170px minmax(0,1fr);gap:18px;align-items:start}.tabs{position:sticky;top:0;display:grid;gap:6px;border:1px solid var(--line);border-radius:8px;padding:6px;background:rgba(7,16,24,.34);margin:0}
.tab{padding:9px 10px;color:var(--muted);cursor:pointer;border:1px solid transparent;border-radius:6px}.tab.active{color:#d8fff0;background:#123325;border-color:#236a4b}.tab:hover{color:var(--text);border-color:#344255}
.settings-content{min-width:0}.settings-pane{display:block}.settings-card{background:rgba(18,24,32,.72);border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:12px}.settings-card-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:12px}.settings-card-title{font-weight:700;color:var(--text)}.settings-card .small{margin-top:4px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 14px}.form-grid.compact{grid-template-columns:repeat(4,minmax(0,1fr))}.field label{display:block;color:#c7d5e8;font-weight:600;margin-bottom:6px}
.field input,.field select{width:100%;box-sizing:border-box;background:#071018;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font:14px ui-monospace,SFMono-Regular,Consolas,monospace}
.field input:focus,.field select:focus{outline:none;border-color:#18c99b;box-shadow:0 0 0 3px rgba(24,201,155,.14)}
.settings-group-title{margin:0 0 10px;color:var(--text);font-size:13px;font-weight:700}
.advanced-settings{border:1px solid var(--line);border-radius:8px;background:rgba(7,16,24,.24);padding:10px 12px;margin-top:12px}.advanced-settings summary{cursor:pointer;color:#c7d5e8;font-weight:700}.advanced-settings .form-grid{margin-top:12px}
.check-row{display:flex;gap:8px;align-items:center;color:#c7d5e8;margin:10px 0}.check-row input{width:auto}
.record-list{display:grid;gap:10px;margin-top:10px}.record-row{display:grid;grid-template-columns:80px 72px 72px 1fr 80px 40px;gap:8px;align-items:center}
.record-row input,.record-row select{background:#071018;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
.icon-btn{width:36px;height:36px;padding:0;display:grid;place-items:center}
.agent-manage-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.agent-summary{display:flex;gap:18px;align-items:center;color:var(--muted)}
.agent-summary strong{color:var(--text);font-size:18px;margin-right:4px}.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:var(--muted)}
.status-dot.online{background:var(--ok);box-shadow:0 0 0 3px rgba(54,211,153,.12)}.status-dot.offline{background:var(--bad)}
.agent-manage-list{display:grid;gap:12px}.agent-editor{border:1px solid #315064;border-radius:8px;padding:16px;background:rgba(7,16,24,.42)}
.agent-editor-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:14px}.agent-editor-title{font-weight:700;font-size:15px}.agent-editor-status{color:var(--muted);font-size:12px;margin-top:3px}
.agent-editor-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 16px}.agent-editor .field input,.agent-editor .field select{border-radius:7px;padding:10px 12px}.agent-editor .field input[readonly]{color:#9dabbc;background:#0c141d}
.agent-editor-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}.agent-editor-meta{color:var(--muted);font-size:12px;min-width:0}.agent-editor-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.agent-empty{border:1px dashed #315064;border-radius:8px;padding:24px;text-align:center;color:var(--muted)}
.agent-error{color:var(--bad)}.agent-scanning{color:var(--warn)}
.section-title{margin:20px 0 8px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.final-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.final-carriers{justify-content:flex-end}.final-results-wrap{overflow-x:auto;margin-top:10px}
.final-table{margin-top:10px;table-layout:fixed}.final-table th,.final-table td{padding:8px 10px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}
.final-table td:nth-child(2){font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ok)}
.final-table .col-region{width:42px}.final-table .col-ip{width:132px}.final-table .col-domain{width:150px}.final-table .col-ping{width:66px}.final-table .col-loss{width:58px}
.final-table .col-hint,.final-table .col-entry{width:auto}
.table-tools{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:10px 0 -6px}
.segments{display:flex;gap:6px;flex-wrap:wrap}.seg{padding:6px 10px;border-radius:999px;background:#101722;border:1px solid var(--line);color:var(--muted);cursor:pointer}.seg.active{color:#d8fff0;background:#123325;border-color:#236a4b}
table{width:100%;border-collapse:collapse;margin-top:16px;background:var(--panel);border:1px solid var(--line)}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;font-variant-numeric:tabular-nums}
th{color:var(--muted);font-size:12px}th.sortable{cursor:pointer;user-select:none}th.sortable:hover{color:var(--text)}th.sortable.active{color:var(--ok)}tr.best td{color:var(--ok)}tr.bad td{color:var(--bad)}tr.hot td{color:var(--ok)}
/* Operational dashboard */
:root{--bg:#081018;--panel:#0e1923;--panel-2:#101d28;--panel-soft:#0a151e;--line:#243544;--line-strong:#315064;--ok:#35d39a;--ok-soft:#0f3c31;--warn:#f0b84b;--bad:#ff6868;--text:#e9f0f5;--muted:#8fa0ae}
body{background:radial-gradient(circle at 45% -20%,#122938 0,#081018 36%,#070d13 100%);min-height:100vh}
main{max-width:1440px;padding:0 22px 28px}
.app-header{height:68px;display:flex;align-items:center;justify-content:space-between;gap:18px;border-bottom:1px solid rgba(49,80,100,.7);margin-bottom:14px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}.brand-mark{position:relative;width:32px;height:32px;flex:0 0 32px}.brand-mark i{position:absolute;width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px rgba(53,211,154,.35)}.brand-mark i:nth-child(1){left:2px;top:12px}.brand-mark i:nth-child(2){left:13px;top:2px}.brand-mark i:nth-child(3){right:1px;top:14px}.brand-mark i:nth-child(4){left:12px;bottom:1px}.brand-mark:before,.brand-mark:after{content:"";position:absolute;height:1px;background:#279d78;transform-origin:left center}.brand-mark:before{width:24px;left:6px;top:14px;transform:rotate(-29deg)}.brand-mark:after{width:23px;left:7px;top:16px;transform:rotate(32deg)}
.brand-title{font-size:18px;font-weight:750;letter-spacing:0}.brand-sub{font-size:11px;color:var(--muted);margin-top:1px}.header-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.header-actions [hidden]{display:none!important}.live-chip{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:6px;padding:7px 10px;color:#cbd7df;background:#0b151e;font-size:12px}.live-dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(53,211,154,.1)}.live-dot.paused{background:var(--warn);box-shadow:none}.last-update{color:var(--muted);font-size:12px;margin:0 4px}
button{border-radius:5px;background:#111d27;border-color:#304150;padding:7px 12px}button.primary{background:linear-gradient(90deg,#14946c,#29c995);border-color:#36d39a;color:#f5fffb;font-weight:650}button.danger{background:#251317;border-color:#7e303a;color:#ff8a92}.icon-text{display:inline-flex;align-items:center;gap:6px}
.panel{background:linear-gradient(145deg,rgba(15,28,38,.97),rgba(12,23,32,.97));border-color:var(--line);box-shadow:0 8px 28px rgba(0,0,0,.08)}
.overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));padding:0;margin-bottom:14px}.overview-item{padding:19px 22px;min-width:0;position:relative}.overview-item+.overview-item:before{content:"";position:absolute;left:0;top:18px;bottom:18px;width:1px;background:var(--line)}.overview-value{font:17px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.overview-value.decision-value{font-family:inherit;font-size:18px}.overview-sub{font-size:12px;color:var(--muted);margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.workbench{display:grid;grid-template-columns:minmax(280px,37%) 1fr;gap:14px;margin-bottom:14px;align-items:start}.section-heading{font-size:18px;font-weight:720;margin:0}.section-copy{font-size:12px;color:var(--muted);margin-top:3px}.seed-panel{padding:16px 18px}.scan-panel{padding:14px 18px}.seedbox{min-height:104px;background:#08131c;border-color:#2b3d4b}.scan-status-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.scan-stage{color:var(--ok);font-size:20px;font-weight:720;margin-top:7px}.scan-stage-badge{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:999px;border:1px solid #31536d;background:#112a3c;color:#70bbed;font-size:11px;vertical-align:middle}.scan-count{font-size:15px;margin-top:4px}.scan-count strong{font:700 18px ui-monospace,SFMono-Regular,Consolas,monospace}.scan-meta{font-size:12px;color:#b3c0ca;margin-top:8px}.scan-steps{display:flex;align-items:center;margin-top:15px}.scan-step{display:flex;align-items:center;gap:8px;white-space:nowrap;color:var(--muted);font-size:12px}.scan-step.active{color:#dffcf1}.step-num{width:23px;height:23px;border:1px solid #50606e;border-radius:50%;display:grid;place-items:center}.scan-step.active .step-num{border-color:var(--ok);color:var(--ok);background:rgba(53,211,154,.08)}.step-line{height:1px;background:#526170;flex:1;min-width:36px;margin:0 10px}.scan-note{font-size:12px;color:var(--muted);margin-top:14px}
.dashboard-section{margin-bottom:14px;padding:18px}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px}.section-title-wrap{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}.section-title-wrap .section-copy{margin:0}.final-carriers{justify-content:flex-end}.segments{gap:0}.seg{border-radius:0;padding:7px 14px}.seg:first-child{border-radius:5px 0 0 5px}.seg:last-child{border-radius:0 5px 5px 0}.seg+.seg{margin-left:-1px}.seg.active{background:linear-gradient(90deg,#14946c,#2acb97);color:white;border-color:#2acb97}
.notice{display:none;align-items:center;gap:9px;color:var(--warn);font-size:12px;margin:14px 0 2px}.notice.show{display:flex}.notice button{border:0;background:transparent;color:var(--ok);padding:0}.notice.info{color:#9fb0bd}.notice-icon{width:16px;height:16px;border:1px solid currentColor;border-radius:50%;display:grid;place-items:center;font-size:10px;flex:0 0 auto}
.final-results-wrap,.data-table-wrap{overflow:auto}.final-table,.data-table{background:transparent;border:0;margin-top:12px;table-layout:auto}.final-table th,.final-table td,.data-table th,.data-table td{border-bottom:1px solid rgba(49,65,79,.8);padding:12px 10px}.final-table tr.recommended,.data-table tr.best{background:linear-gradient(90deg,rgba(20,148,108,.12),rgba(20,148,108,.02));box-shadow:inset 2px 0 var(--ok)}.result-badge{display:inline-block;border:1px solid #176d52;background:#0c3027;color:var(--ok);border-radius:4px;padding:2px 6px;font-size:10px;margin-left:7px}.status-good{color:var(--ok)}.status-muted{color:var(--muted)}
.agent-section-head{display:flex;align-items:center;justify-content:space-between;gap:14px}.agent-summary-line{color:var(--muted);font-size:12px}.agent-table td:first-child{font-weight:650}.agent-name-sub{display:block;font-size:10px;color:var(--muted);font-weight:400;margin-top:2px}.agent-status-stack{display:flex;align-items:center;gap:6px;flex-wrap:wrap}.status-pill{display:inline-flex;align-items:center;gap:6px;border:1px solid #1f6c53;border-radius:4px;background:#0c3027;color:#c9fbed;padding:3px 8px;font-size:11px}.status-pill.offline{border-color:#683238;background:#271417;color:#ff989e}.status-pill.running{border-color:#20644f;background:#0c3027;color:#bff8e5}.status-pill.paused{border-color:#7c6830;background:#2a2413;color:#ffd976}.status-pill.pending{border-color:#31536d;background:#112a3c;color:#8fc8ef}.status-pill .status-dot{margin:0;width:6px;height:6px}
.data-section{padding:18px}.data-toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:14px;flex-wrap:wrap}.data-controls{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.search-box{position:relative}.search-box:before{content:"⌕";position:absolute;left:11px;top:5px;color:var(--muted);font-size:20px}.search-box input{width:250px;background:#0a151e;border:1px solid #304150;border-radius:5px;color:var(--text);padding:8px 10px 8px 34px;box-sizing:border-box}.toolbar-select{background:#0a151e;border:1px solid #304150;border-radius:5px;color:var(--text);padding:8px 10px}.column-picker{position:relative}.column-menu{display:none;position:absolute;right:0;top:calc(100% + 8px);z-index:6;width:290px;background:#13212c;border:1px solid #3a5060;border-radius:7px;padding:15px;box-shadow:0 18px 50px rgba(0,0,0,.45)}.column-menu.open{display:block}.column-menu-title{font-weight:700;margin-bottom:12px}.column-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px 14px}.column-grid label{display:flex;align-items:center;gap:7px;color:#cbd6dd;font-size:12px}.column-grid label.column-hidden{color:#748693}.column-grid .hidden-tag{margin-left:auto;border:1px solid #354758;border-radius:999px;padding:1px 5px;color:#8fa0ae;font-size:10px}.column-grid input{accent-color:var(--ok)}.column-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}.selection-notice{margin:12px 0 0;padding:9px 11px;border:1px solid #2d3d4a;background:#0a151e;border-radius:5px}
.data-table{min-width:1080px}.data-table th{white-space:nowrap}.data-table td{font-size:12px;vertical-align:middle}.data-table td[data-col="ip"]{font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.data-table td[data-col="hint"]{max-width:250px;white-space:normal}.data-table td[data-col="speed"]{color:#d9e4ea}.data-table td[data-col="agent"]{white-space:normal}.data-table [hidden]{display:none!important}
.table-footer{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-top:14px;color:var(--muted);font-size:12px}.pagination{display:flex;align-items:center;gap:6px}.page-btn{min-width:30px;padding:6px 8px}.page-btn.active{background:#15946d;border-color:#26c796;color:white}.page-ellipsis{padding:0 3px}.refresh-live{display:inline-flex;align-items:center;gap:7px;color:#aebac3}.refresh-live .live-dot{width:6px;height:6px}.refresh-live.paused{color:var(--warn)}
.modal-card{background:#101d27;border-color:#315064}.settings-card{background:#0d1821}
@media(max-width:900px){main{padding:0 14px 22px}.app-header{height:auto;padding:14px 0;align-items:flex-start}.header-actions{max-width:58%}.overview{grid-template-columns:1fr 1fr}.overview-item:nth-child(3):before{display:none}.overview-item:nth-child(n+3){border-top:1px solid var(--line)}.workbench{grid-template-columns:1fr}.section-head,.agent-section-head{align-items:stretch;flex-direction:column}.final-carriers{justify-content:flex-start}.search-box input{width:210px}.settings-layout,.form-grid,.form-grid.compact,.agent-editor-grid{grid-template-columns:1fr}.tabs{position:static;display:flex;overflow:auto}}
@media(max-width:620px){.brand-sub,.last-update{display:none}.header-actions{max-width:none}.app-header{flex-direction:column}.overview{grid-template-columns:1fr}.overview-item+.overview-item:before{top:0;right:18px;bottom:auto;width:auto;height:1px}.overview-item:nth-child(n+3){border-top:0}.scan-steps{align-items:flex-start}.step-line{min-width:18px;margin:13px 7px 0}.data-controls{justify-content:flex-start;width:100%}.search-box,.search-box input{width:100%}.table-footer{align-items:flex-start;flex-direction:column}.modal{padding:10px}.modal-card{width:calc(100vw - 20px);max-height:calc(100vh - 20px);padding:16px}.record-row{grid-template-columns:1fr 1fr}.agent-manage-head,.agent-editor-foot{align-items:stretch;flex-direction:column}.agent-editor-actions{justify-content:flex-start}}
</style>
</head>
<body><main>
<header class="app-header">
<div class="brand"><span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span><div><div class="brand-title">CF Anycast Router</div><div class="brand-sub">Anycast 路由学习与调度</div></div></div>
<div class="header-actions"><span id="liveStatus" class="live-chip"><span class="live-dot"></span><span id="mode">正在加载</span></span><span id="lastUpdated" class="last-update">最后刷新：-</span><button class="ghost" onclick="refreshNow()">立即刷新</button><button class="ghost icon-text" onclick="openSettings()">⚙ 设置</button><button id="stopBtn" class="danger" onclick="setAutoScan('stop')">暂停探测</button><button id="startBtn" class="primary" onclick="setAutoScan('start')" hidden disabled>恢复探测</button></div>
</header>
<section class="panel overview">
<div class="overview-item"><div class="k">当前入口</div><div id="current" class="overview-value">-</div><div id="currentSub" class="overview-sub">等待状态数据</div></div>
<div class="overview-item"><div class="k">最优候选</div><div id="best" class="overview-value">-</div><div id="bestSub" class="overview-sub">等待 Agent 上报</div></div>
<div class="overview-item"><div class="k">路由地区</div><div id="pop" class="overview-value">-</div><div id="popSub" class="overview-sub">等待 Cloudflare Colo</div></div>
<div class="overview-item"><div class="k">当前决策</div><div id="decisionTitle" class="overview-value decision-value">等待判断</div><div id="decision" class="overview-sub">-</div></div>
</section>
<section class="workbench">
<div class="panel seed-panel">
<h2 class="section-heading">种子与扫描</h2><div class="section-copy">维护候选网段并启动本轮抽样</div>
<textarea id="seedInput" class="seedbox" spellcheck="false" placeholder="104.20.23.137&#10;104.20.0.0/16&#10;104.26.x.x&#10;172.67.73.x"></textarea>
<div class="actions">
<button class="primary" onclick="saveSeeds()">保存种子</button>
<button onclick="scanNow()">立即扫描</button>
</div>
<div id="seedMsg" class="small">粘贴 IP、CIDR 或通配段，每行一个。</div>
<div class="lookup-row">
<input id="lookupIP" placeholder="输入 IP，例如 104.20.23.137">
<button onclick="lookupIPRange()">验证 IP / 网段</button>
</div>
<div id="lookupMsg" class="small">查询会先找 BGP 前缀，再抽样验证；只有本地路由地区一致的段才会保留。</div>
</div>
<div class="panel scan-panel">
<div class="scan-status-head"><div><h2 class="section-heading">当前扫描</h2><div id="scanStage" class="scan-stage">等待 Agent <span class="scan-stage-badge">待机</span></div><div id="scanCount" class="scan-count">已完成 <strong>0</strong> 个候选</div></div><div id="scanRound" class="section-copy">等待本轮状态</div></div>
<div id="scanMeta" class="scan-meta">可用候选 0 · 已追踪路由 0 · 剩余预算 -</div>
<div class="scan-steps"><div id="scanStep1" class="scan-step active"><span class="step-num">1</span><span>种子段预检</span></div><span class="step-line"></span><div id="scanStep2" class="scan-step"><span class="step-num">2</span><span>候选测量</span></div><span class="step-line"></span><div id="scanStep3" class="scan-step"><span class="step-num">3</span><span>结果汇总</span></div></div>
<div class="scan-note">阶段与数量来自 Agent 实际任务；地区以有效路由结果和 Cloudflare Colo 裁决。</div>
</div>
</section>
<div id="settingsModal" class="modal" onclick="if(event.target===this)closeSettings()">
<div class="modal-card">
<div class="modal-head"><div><h2>管理设置</h2><div class="hint">修改后会写入配置文件，下一轮检测使用新设置。</div></div><button class="icon-btn" onclick="closeSettings()">×</button></div>
<div class="settings-layout">
<div class="tabs"><div class="tab active" data-tab="basic" onclick="switchSettingsTab('basic')">基础设置</div><div class="tab" data-tab="budget" onclick="switchSettingsTab('budget')">扫描预算</div><div class="tab" data-tab="speed" onclick="switchSettingsTab('speed')">官方测速</div><div class="tab" data-tab="dns" onclick="switchSettingsTab('dns')">地区解析</div><div class="tab" data-tab="agent" onclick="switchSettingsTab('agent')">Agent 安装</div><div class="tab" data-tab="agents" onclick="switchSettingsTab('agents')">Agent 管理</div></div>
<div class="settings-content">
<section id="settings-basic" class="settings-pane">
<input id="setProbeSource" type="hidden">
<input id="setCarrier" type="hidden" value="auto">
<div class="settings-card">
<div class="settings-card-head"><div><div class="settings-card-title">母鸡调度</div><div class="small">安装命令和在线 Agent 都使用这里的母鸡地址。</div></div></div>
<div class="form-grid">
<div class="field"><label>母鸡地址</label><input id="agentServerURL" oninput="this.dataset.autoDefault='0';updateAgentInstallCommand()" placeholder="http://172.23.93.195:19199"></div>
<div class="field"><label>检测间隔（秒）</label><input id="setInterval" type="number" min="10" step="10"></div>
</div>
</div>
</section>
<section id="settings-budget" class="settings-pane" style="display:none">
<div class="settings-card">
<div class="settings-group-title">单 IP 探测</div>
<div class="form-grid">
<div class="field"><label>每个 IP 探测次数</label><input id="setProbeAttempts" type="number" min="1" max="20" step="1"></div>
<div class="field"><label>单次探测超时（秒）</label><input id="setProbeTimeout" type="number" min="1" max="30" step="1"></div>
<div class="field"><label>本轮路由追踪预算</label><input id="setTraceBudget" type="number" min="1" step="1"></div>
</div>
</div>
<div class="settings-card">
<div class="settings-group-title">段抽样预算</div>
<div class="form-grid">
<div class="field"><label>种子段预检上限 / 轮</label><input id="setSeedPreflight" type="number" min="1" step="1"></div>
<div class="field"><label>种子段上限 / 轮</label><input id="setSeedSegments" type="number" min="1" step="1"></div>
<div class="field"><label>学习段上限 / 轮</label><input id="setLearnedSegments" type="number" min="0" step="1"></div>
<div class="field"><label>每段样本数 / 轮</label><input id="setSamplesPerSegment" type="number" min="1" step="1"></div>
</div>
<details class="advanced-settings">
<summary>高级抽样与学习参数</summary>
<div class="form-grid">
<div class="field"><label>段内 IP 步进</label><input id="setSampleStep" type="number" min="1" step="1"></div>
<div class="field"><label>种子 CIDR 步进</label><input id="setSeedCIDRStep" type="number" min="1" step="1"></div>
<div class="field"><label>晋级最少样本</label><input id="setPromoteMinSamples" type="number" min="1" step="1"></div>
<div class="field"><label>晋级命中率（%）</label><input id="setPromoteProbability" type="number" min="1" max="100" step="1"></div>
<div class="field"><label>每段热点 IP 上限</label><input id="setHotMaxPerSegment" type="number" min="1" step="1"></div>
<div class="field"><label>热点最高得分</label><input id="setHotMaxScore" type="number" min="1" step="1"></div>
<div class="field"><label>尖刺阈值（ms）</label><input id="setSpikeThreshold" type="number" min="1" step="5"></div>
<div class="field"><label>尖刺倍率</label><input id="setSpikeMultiplier" type="number" min="1" step="0.1"></div>
</div>
</details>
</div>
</section>
<section id="settings-speed" class="settings-pane" style="display:none">
<div class="settings-card">
<label class="check-row"><input id="setSpeedEnabled" type="checkbox"> 启用 Cloudflare 官方下载测速</label>
<input id="setSpeedHost" type="hidden" value="speed.cloudflare.com">
<input id="setSpeedPath" type="hidden" value="/__down">
<div class="form-grid compact">
<div class="field"><label>每次下载字节数</label><input id="setSpeedBytes" type="number" min="4096" max="4194304" step="4096"></div>
<div class="field"><label>短名单数量</label><input id="setSpeedTopN" type="number" min="1" max="20" step="1"></div>
</div>
</div>
</section>
<section id="settings-dns" class="settings-pane" style="display:none">
<div class="settings-card">
<label class="check-row"><input id="setDnsEnabled" type="checkbox"> 启用 Cloudflare DNS 动态解析</label>
<div class="form-grid">
<div class="field"><label>Zone Name</label><input id="setZoneName" placeholder="yeque.top"></div>
</div>
<details class="advanced-settings">
<summary>Cloudflare 连接参数</summary>
<div class="form-grid">
<div class="field"><label>Zone ID</label><input id="setZoneID" placeholder="可选，填了更快"></div>
<div class="field"><label>Token 环境变量</label><input id="setTokenEnv" placeholder="CLOUDFLARE_API_TOKEN"></div>
<div class="field"><label>TTL</label><input id="setTTL" type="number" min="60" step="60"></div>
</div>
<label class="check-row"><input id="setProxied" type="checkbox"> 开启 Cloudflare 代理</label>
</details>
</div>
<div class="settings-card">
<div class="field"><label>按运营商和地区解析域名</label><div id="recordList" class="record-list"></div></div>
<div class="actions"><button onclick="addRecordRow()">添加地区记录</button><button class="primary" onclick="autoGenerateDNSRecords()">自动生成解析记录</button></div>
<div id="dnsGenerateMsg" class="small">自动生成会按 Zone Name 补齐 cu/ct/cm × HK/US/JP/SG，例如 cu-cf-us.example.com。</div>
</div>
</section>
<section id="settings-agent" class="settings-pane" style="display:none">
<div class="settings-card">
<div class="form-grid">
<div class="field"><label>运营商</label><select id="agentInstallCarrier" onchange="updateAgentInstallCommand()"><option value="auto">自动识别</option><option value="cu">联通</option><option value="ct">电信</option><option value="cm">移动</option><option value="unknown">未知</option></select></div>
<div class="field"><label>共享 Token</label><input id="agentInstallToken" placeholder="可选" oninput="updateAgentInstallCommand()"></div>
</div>
<details class="advanced-settings">
<summary>迁移 / 重连已有 Agent</summary>
<div class="field"><label>指定 Agent ID（可选）</label><input id="agentInstallID" placeholder="留空，由目标 VPS 首次安装时自动生成" oninput="updateAgentInstallCommand()"></div>
</details>
<div class="field"><label>一键安装命令</label><textarea id="agentInstallCommand" class="seedbox" readonly spellcheck="false"></textarea></div>
<div class="actions"><button class="primary" onclick="copyAgentInstallCommand()">复制命令</button><button onclick="resetAgentInstallCommand()">恢复默认</button></div>
<div id="agentInstallMsg" class="small"></div>
</div>
</section>
<section id="settings-agents" class="settings-pane" style="display:none">
<div class="settings-card">
<div class="agent-manage-head"><div><div class="k">预期在线 Agent</div><div id="agentManageSummary" class="agent-summary"><span><strong>0</strong>节点</span><span><strong>0</strong>在线</span></div></div><button class="primary" onclick="addAgentDraft()">＋ 新增 Agent</button></div>
<div id="agentManageList" class="agent-manage-list" oninput="agentEditorDirty=true" onchange="agentEditorDirty=true"><div class="agent-empty">尚未配置 Agent</div></div>
</div>
</section>
</div>
</div>
<div id="settingsMsg" class="small"></div>
<div class="modal-actions"><button onclick="closeSettings()">关闭</button><button id="saveSettingsBtn" class="primary" onclick="saveSettings()">保存设置</button></div>
</div>
</div>
<section class="panel dashboard-section">
<div class="section-head"><div class="section-title-wrap"><h2 class="section-heading">优选结果</h2><div class="section-copy">按运营商聚合在线 Agent，展示各地区当前推荐入口</div></div><div id="finalCarrierTabs" class="segments final-carriers"></div></div>
<div id="finalNotice" class="notice"><span class="notice-icon">!</span><span id="finalNoticeText"></span><button onclick="refreshNow()">重试</button></div>
<div class="final-results-wrap"><table class="final-table"><thead><tr><th>地区</th><th>推荐 IP</th><th>解析域名</th><th>Ping</th><th>测速 IP</th><th>Mbps</th><th>Agent</th><th>状态</th></tr></thead><tbody id="carrierFinalRows"><tr><td colspan="8">等待 Agent 扫描数据</td></tr></tbody></table></div>
</section>
<section class="panel dashboard-section">
<div class="agent-section-head"><div class="section-title-wrap"><h2 class="section-heading">探针上报</h2><div class="section-copy">Agent 状态与最近一次测量摘要</div></div><div id="agentSummaryLine" class="agent-summary-line">等待 Agent 上报</div></div>
<div class="final-results-wrap"><table class="final-table agent-table"><thead><tr><th>Agent</th><th>探测源</th><th>运营商</th><th>状态</th><th>最后上报</th><th>候选</th><th>最优 IP</th><th>地区</th><th>得分</th></tr></thead><tbody id="agentRows"><tr><td colspan="9">等待 Agent 上报</td></tr></tbody></table></div>
</section>
<section class="panel data-section">
<div class="section-title-wrap"><h2 class="section-heading">IP 探测数据</h2><div id="filterInfo" class="section-copy">等待 Agent 测量结果</div></div>
<div class="data-toolbar"><div class="segments" id="regionFilters">
<button class="seg active" data-region="ALL">全部</button>
<button class="seg" data-region="HK">HK</button>
<button class="seg" data-region="US">US</button>
<button class="seg" data-region="JP">JP</button>
<button class="seg" data-region="SG">SG</button>
</div><div class="data-controls"><label class="search-box"><input id="dataSearch" placeholder="搜索 IP、网段或 Agent"></label><div class="column-picker"><button id="columnPickerBtn" onclick="toggleColumnMenu()">列设置 · <span id="columnCount">11 / 16</span></button><div id="columnMenu" class="column-menu"><div class="column-menu-title">显示字段</div><div id="columnGrid" class="column-grid"></div><div class="column-actions"><button onclick="resetColumns()">恢复默认</button><button class="primary" onclick="toggleColumnMenu(false)">完成</button></div></div></div><button id="sortButton" onclick="setScoreSort()">得分 ↑</button><select id="pageSizeSelect" class="toolbar-select"><option value="25">每页 25 条</option><option value="50">每页 50 条</option><option value="100">每页 100 条</option></select></div></div>
<div id="selectionNotice" class="notice info selection-notice"><span class="notice-icon">i</span><span>检测到文本选择，表格刷新已暂停</span><button onclick="clearTableSelection()">恢复刷新</button></div>
<div class="data-table-wrap"><table class="data-table"><thead><tr>
<th class="sortable" data-col="ip" data-sort="ip">IP</th>
<th class="sortable" data-col="stage" data-sort="stage">阶段</th>
<th class="sortable" data-col="segment" data-sort="segment">网段</th>
<th class="sortable" data-col="region" data-sort="region">判定地区</th>
<th class="sortable" data-col="hint" data-sort="hint">判断依据</th>
<th class="sortable" data-col="speed" data-sort="cf_speed">CF 官方测速</th>
<th class="sortable" data-col="mbps" data-sort="cf_mbps">估算 Mbps</th>
<th class="sortable" data-col="colo" data-sort="colo">CF Colo</th>
<th class="sortable" data-col="ping" data-sort="ping">Ping 延迟</th>
<th class="sortable" data-col="pingloss" data-sort="pingloss">Ping 丢包</th>
<th class="sortable" data-col="rtt" data-sort="rtt">TLS 延迟</th>
<th class="sortable" data-col="jitter" data-sort="jitter">抖动</th>
<th class="sortable" data-col="loss" data-sort="loss">TLS 丢包</th>
<th class="sortable" data-col="spike" data-sort="spike">尖刺</th>
<th class="sortable active" data-col="score" data-sort="score">得分</th>
<th data-col="agent">Agent</th>
</tr></thead><tbody id="rows"></tbody></table></div>
<div class="table-footer"><div id="pageSummary">显示 0 条</div><div class="refresh-live" id="tableRefreshStatus"><span class="live-dot"></span><span>实时数据持续接收</span></div><div id="pagination" class="pagination"></div></div>
</section>
</main>
<script>
function pct(v){ return (((v||0)*100).toFixed(0))+'%'; }
function fmt(v){ return Number.isFinite(v)?v.toFixed(1):'-'; }
let sortState={key:'score',dir:'asc'};
let regionFilter='ALL';
let seedDirty=false;
let dataQuery='';
let dataPage=1;
let dataPageSize=50;
const columnLabels={ip:'IP',stage:'阶段',segment:'网段',region:'判定地区',hint:'判断依据',speed:'CF 官方测速',mbps:'估算 Mbps',colo:'CF Colo',ping:'Ping 延迟',pingloss:'Ping 丢包',rtt:'TLS 延迟',jitter:'抖动',loss:'TLS 丢包',spike:'尖刺',score:'得分',agent:'Agent'};
const defaultColumns=['ip','stage','segment','region','hint','speed','ping','rtt','jitter','score','agent'];
let visibleColumns=new Set(defaultColumns);
const dashboardStateKey='cfAnycastRouter.ui.v1';
const dashboardSortKeys=['ip','stage','segment','region','hint','cf_speed','cf_mbps','colo','ping','pingloss','rtt','jitter','loss','spike','score'];
const dashboardRegions=['ALL','HK','US','JP','SG'];
const settingsTabs=['basic','budget','speed','dns','agent','agents'];
function readDashboardState(){
 try{ return JSON.parse(localStorage.getItem(dashboardStateKey)||'{}')||{}; }
 catch(_){ return {}; }
}
function saveDashboardState(){
 try{
   localStorage.setItem(dashboardStateKey,JSON.stringify({
     carrier:selectedFinalCarrier,
     region:regionFilter,
     sort:sortState,
     settings_tab:activeSettingsTab,
     query:dataQuery,
     page_size:dataPageSize,
     columns:[...visibleColumns]
   }));
 }catch(_){}
}
function restoreDashboardState(){
 const state=readDashboardState();
 if(typeof state.carrier==='string'&&state.carrier){ selectedFinalCarrier=state.carrier.toLowerCase(); }
 if(dashboardRegions.includes(state.region)){ regionFilter=state.region; }
 if(state.sort&&dashboardSortKeys.includes(state.sort.key)&&['asc','desc'].includes(state.sort.dir)){
   sortState={key:state.sort.key,dir:state.sort.dir};
 }
 if(typeof state.query==='string'){ dataQuery=state.query.slice(0,120); }
 if([25,50,100].includes(Number(state.page_size))){ dataPageSize=Number(state.page_size); }
 if(Array.isArray(state.columns)){
   const columns=state.columns.filter(column=>columnLabels[column]);
   if(columns.length){ visibleColumns=new Set(columns); }
 }
 if(settingsTabs.includes(state.settings_tab)){ activeSettingsTab=state.settings_tab; }
 document.querySelectorAll('#regionFilters .seg').forEach(btn=>btn.classList.toggle('active',btn.dataset.region===regionFilter));
 dataSearch.value=dataQuery;
 pageSizeSelect.value=String(dataPageSize);
 renderColumnMenu();
 applyVisibleColumns();
 switchSettingsTab(activeSettingsTab,false);
 updateSortHeaders();
}
function stageLabel(v){
 const map={
   'seed':'种子',
   'seed-sample':'种子抽样',
   'segment-probe':'段探活',
   'learned':'学习段',
   'learning':'学习中',
   'hot':'热点',
   'lookup-reference':'查询基准',
   'lookup-sample':'查询抽样'
 };
 return map[v]||v||'-';
}
function decisionLabel(v){
 if(!v){ return '-'; }
 return String(v)
   .replace('agent measurement report','等待 Agent 完成本轮测量')
   .replace('BGP prefix was mixed; accepted local /24 instead','BGP 前缀结果混杂，已改用本地 /24')
   .replace('reference IP could not be classified','基准 IP 暂时无法判定本地路由地区')
   .replace('no usable samples','没有可用抽样结果')
   .replace('no sample IPs generated','没有生成抽样 IP')
   .replace('no geocoded public hop','没有找到可定位的公网路由跳点')
   .replace('route trace timed out','路由追踪超时')
   .replace('route trace skipped by per-cycle budget','本轮路由追踪预算已用完')
   .replace('temporarily quarantined after POP drift','POP 漂移后临时隔离，暂不探测')
   .replace('accepted:','已接受：')
   .replace('discarded:','已舍弃：')
   .replace('samples matched reference route region','抽样匹配基准路由地区')
   .replace('only','只有')
   .replace('no healthy candidate','暂无可用候选')
   .replace('no active route','当前没有活动入口')
   .replace('current route remains best','当前入口仍是最优')
   .replace('best candidate is not usable','最优候选不可用')
   .replace('active route has no baseline score','当前入口没有基准分')
   .replace('no active route yet;','还没有活动入口；')
   .replace('switched:','已切换：')
   .replace('kept current;','保持当前入口；')
   .replace('improvement is below','优势低于')
   .replace('candidate','候选')
   .replace('is better by','优势')
   .replace('observing','观察')
   .replace('rounds','轮')
   .replace('held advantage for','连续领先')
   .replace('better','更优')
   .replace('active route loss','当前入口丢包')
   .replace('exceeds','超过')
   .replace('active route RTT','当前入口 RTT')
   .replace('active route spike rate','当前入口尖刺率');
}
function regionSourceLabel(v){
 const map={
   'route':'ICMP 路由',
   'cf':'CF Colo',
   'cf-colo':'CF Colo',
   'cf-speed':'CF 官方测速',
   'cf-colo-tls':'443 服务面',
   'unknown':'未知'
 };
 return map[v]||v||'-';
}
function ipValue(ip){
 return String(ip||'').split('.').reduce((n,p)=>n*256+(parseInt(p,10)||0),0);
}
function candidateValue(c,key){
 const colo=(c.observed_colo&&c.observed_pop&&c.observed_colo!==c.observed_pop)?(c.observed_colo+' / '+c.observed_pop):(c.observed_colo||c.observed_pop||'');
 const hint=[c.route_hint_ip,c.route_city,c.route_isp].filter(Boolean).join(' ')||c.route_error||'';
 switch(key){
   case 'ip': return ipValue(c.ip);
   case 'stage': return stageLabel(c.stage);
   case 'segment': return c.segment||'';
   case 'region': return candidateRegion(c);
   case 'hint': return hint;
   case 'cf_speed': return Number.isFinite(c.cf_speed_rtt_ms)&&c.cf_speed_rtt_ms>0?c.cf_speed_rtt_ms:Number.POSITIVE_INFINITY;
   case 'cf_mbps': return Number.isFinite(c.cf_speed_mbps)?c.cf_speed_mbps:0;
   case 'colo': return colo;
   case 'ping': return Number.isFinite(c.ping_rtt_ms)?c.ping_rtt_ms:Number.POSITIVE_INFINITY;
   case 'pingloss': return Number.isFinite(c.ping_loss_rate)?c.ping_loss_rate:Number.POSITIVE_INFINITY;
   case 'rtt': return Number.isFinite(c.avg_rtt_ms)?c.avg_rtt_ms:Number.POSITIVE_INFINITY;
   case 'jitter': return Number.isFinite(c.jitter_ms)?c.jitter_ms:Number.POSITIVE_INFINITY;
   case 'loss': return Number.isFinite(c.loss_rate)?c.loss_rate:Number.POSITIVE_INFINITY;
   case 'spike': return Number.isFinite(c.spike_rate)?c.spike_rate:Number.POSITIVE_INFINITY;
   case 'score': return Number.isFinite(c.score)?c.score:Number.POSITIVE_INFINITY;
   default: return '';
 }
}
function isSelectableStage(stage){
 return ['seed','seed-sample','learned','hot','lookup-reference','lookup-sample'].includes(String(stage||''));
}
function candidateStageRank(stage){
 const order={'hot':0,'learned':1,'seed':2,'seed-sample':3,'lookup-reference':4,'lookup-sample':5,'segment-probe':8};
 return order[String(stage||'')]??7;
}
function sortCandidates(candidates){
 const arr=[...(candidates||[])].filter(c=>matchesRegion(c)&&matchesSearch(c));
 arr.sort((a,b)=>{
   const ar=candidateStageRank(a.stage), br=candidateStageRank(b.stage);
   if(ar!==br){ return ar-br; }
   const av=candidateValue(a,sortState.key);
   const bv=candidateValue(b,sortState.key);
   let cmp=0;
   if(typeof av==='number'&&typeof bv==='number'){ cmp=av-bv; }
   else { cmp=String(av).localeCompare(String(bv),'zh-Hans',{numeric:true,sensitivity:'base'}); }
   if(cmp===0){ cmp=(Number.isFinite(a.score)?a.score:999999)-(Number.isFinite(b.score)?b.score:999999); }
   return sortState.dir==='asc'?cmp:-cmp;
 });
 return arr;
}
function matchesSearch(c){
 if(!dataQuery){ return true; }
 const haystack=[c.ip,c.segment,c.stage,c.region,c.route_region,c.cf_region,c.route_hint_ip,c.route_city,c.route_isp,c._agent_source].join(' ').toLowerCase();
 return haystack.includes(dataQuery.toLowerCase());
}
function knownRegion(v){
 v=String(v||'').toUpperCase();
 return v&&v!=='UNKNOWN'&&v!=='-'&&v!=='PREFLIGHT'?v:'';
}
function candidateRegion(c){
 const route=knownRegion(c?.route_region);
 const cf=knownRegion(c?.cf_region);
 if(String(c?.route_error||'').trim()&&route&&cf&&route!==cf){ return cf; }
 return knownRegion(c?.region)||route||cf||'unknown';
}
function matchesRegion(c){
 const region=candidateRegion(c);
 if(region==='unknown'){ return false; }
 if(regionFilter==='ALL'){ return true; }
 return region===regionFilter;
}
function filterSummary(candidates){
 const total=(candidates||[]).length;
 const shown=(candidates||[]).filter(c=>matchesRegion(c)&&matchesSearch(c)).length;
 const carrier=finalCarrierLabel(selectedFinalCarrier);
 const region=regionFilter==='ALL'?'全部':regionFilter;
 const sortNames={score:'得分',cf_mbps:'Mbps',cf_speed:'CF 官方测速',ping:'Ping 延迟',pingloss:'Ping 丢包',rtt:'TLS 延迟',jitter:'抖动',loss:'TLS 丢包',spike:'尖刺',colo:'CF Colo',ip:'IP',stage:'阶段',segment:'网段',region:'判定地区',agent:'Agent'};
 const order=sortState.dir==='asc'?'升序':'降序';
 filterInfo.textContent=carrier+' · '+region+' · '+shown+' / '+total+' 条 · 按'+(sortNames[sortState.key]||sortState.key)+order;
}
function renderColumnMenu(){
 if(!columnGrid){ return; }
 columnGrid.innerHTML=Object.entries(columnLabels).map(([key,label])=>{
   const visible=visibleColumns.has(key);
   return '<label class="'+(visible?'':'column-hidden')+'"><input type="checkbox" data-column="'+key+'" '+(visible?'checked':'')+' onchange="toggleColumn(\''+key+'\',this.checked)">'+label+(visible?'':'<span class="hidden-tag">隐藏</span>')+'</label>';
 }).join('');
 columnCount.textContent=visibleColumns.size+' / '+Object.keys(columnLabels).length;
}
function toggleColumnMenu(force){
 const open=typeof force==='boolean'?force:!columnMenu.classList.contains('open');
 columnMenu.classList.toggle('open',open);
}
function toggleColumn(column,visible){
 if(visible){ visibleColumns.add(column); }else if(visibleColumns.size>1){ visibleColumns.delete(column); }
 renderColumnMenu();
 applyVisibleColumns();
 saveDashboardState();
}
function resetColumns(){
 visibleColumns=new Set(defaultColumns);
 renderColumnMenu();
 applyVisibleColumns();
 saveDashboardState();
}
function applyVisibleColumns(){
 document.querySelectorAll('.data-table [data-col]').forEach(cell=>{ cell.hidden=!visibleColumns.has(cell.dataset.col); });
}
function pageButtons(totalPages){
 if(totalPages<=1){ return []; }
 const pages=new Set([1,totalPages,dataPage-1,dataPage,dataPage+1]);
 return [...pages].filter(page=>page>=1&&page<=totalPages).sort((a,b)=>a-b);
}
function renderPagination(total){
 const totalPages=Math.max(1,Math.ceil(total/dataPageSize));
 dataPage=Math.min(Math.max(1,dataPage),totalPages);
 const start=total?((dataPage-1)*dataPageSize+1):0;
 const end=Math.min(total,dataPage*dataPageSize);
 pageSummary.textContent='显示 '+start+'–'+end+'，共 '+total+' 条';
 const pages=pageButtons(totalPages);
 let previous=0;
 const parts=['<button class="page-btn" '+(dataPage<=1?'disabled':'')+' onclick="changePage('+(dataPage-1)+')">上一页</button>'];
 for(const page of pages){
   if(previous&&page-previous>1){ parts.push('<span class="page-ellipsis">…</span>'); }
   parts.push('<button class="page-btn '+(page===dataPage?'active':'')+'" onclick="changePage('+page+')">'+page+'</button>');
   previous=page;
 }
 parts.push('<button class="page-btn" '+(dataPage>=totalPages?'disabled':'')+' onclick="changePage('+(dataPage+1)+')">下一页</button>');
 pagination.innerHTML=parts.join('');
 return {startIndex:(dataPage-1)*dataPageSize,endIndex:dataPage*dataPageSize};
}
function changePage(page){ dataPage=page; renderCarrierData(agentsCache); }
function setScoreSort(){ sortState={key:'score',dir:sortState.key==='score'&&sortState.dir==='asc'?'desc':'asc'}; dataPage=1; saveDashboardState(); renderCarrierData(agentsCache); }
function attr(v){ return String(v??'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
function rowAttrs(values){
 return Object.entries(values).map(([k,v])=>' data-'+k+'="'+attr(v)+'"').join('');
}
function isHealthy(c){ return c&&!c.error&&!c.quarantined&&Number.isFinite(c.score); }
function isSelectableCandidate(c){ return isHealthy(c)&&isSelectableStage(c.stage)&&candidateRegion(c)!=='unknown'&&candidateRegion(c)!=='preflight'; }
function routeDnsScore(c){
 const rtt=c.ping_rtt_ms>0?c.ping_rtt_ms:(c.avg_rtt_ms>0?c.avg_rtt_ms:9999);
 return rtt+(c.ping_loss_rate||0)*800+(c.loss_rate||0)*300+(c.spike_rate||0)*80;
}
function domainForRegion(settings,carrier,region){
 const dns=settings?.cloudflare_dns||{};
 const records=(dns.record_sets&&dns.record_sets.length)?dns.record_sets:Object.entries(dns.records||{}).map(([r,domain])=>({enabled:true,carrier,region:r,type:'A',domain}));
 const rec=records.find(r=>r.enabled!==false&&String(r.carrier||settings?.carrier||'unknown').toLowerCase()===carrier&&String(r.type||'A').toUpperCase()==='A'&&String(r.region||'').toUpperCase()===region);
 return rec?.domain||'-';
}
function finalRegions(settings,candidates,field,carrier){
 const set=new Set(['HK','US','JP','SG']);
 const dns=settings?.cloudflare_dns||{};
 const records=(dns.record_sets&&dns.record_sets.length)?dns.record_sets:[];
 records.forEach(r=>{ if(String(r.carrier||settings?.carrier||'unknown').toLowerCase()===carrier&&r.region){ set.add(String(r.region).toUpperCase()); } });
 (candidates||[]).forEach(c=>{ const v=field==='route_region'?candidateRegion(c):knownRegion(c[field]); if(v&&v!=='unknown'){ set.add(v); } });
 return [...set].sort((a,b)=>{
   const order={HK:1,US:2,JP:3,SG:4,EU:5};
   return (order[a]||99)-(order[b]||99)||a.localeCompare(b);
 });
}
function bestRouteForRegion(candidates,region){
 let best=null, bestScore=Number.POSITIVE_INFINITY;
 for(const c of candidates||[]){
   if(!isSelectableCandidate(c)||candidateRegion(c)!==region){ continue; }
   const score=routeDnsScore(c);
   if(score<bestScore){ best=c; bestScore=score; }
 }
 return best;
}
function bestSpeedForRegion(candidates,region){
 let best=null, bestScore=Number.POSITIVE_INFINITY;
 let failed=null, failedScore=Number.POSITIVE_INFINITY;
 for(const c of candidates||[]){
   if(!isSelectableCandidate(c)||candidateRegion(c)!==region){ continue; }
   if(!(c.cf_speed_rtt_ms>0)){
     if(c.cf_speed_tested&&routeDnsScore(c)<failedScore){ failed=c; failedScore=routeDnsScore(c); }
     continue;
   }
   const score=(c.cf_speed_rtt_ms||9999)+(c.cf_speed_jitter_ms||0)*0.5+(c.cf_speed_loss_rate||0)*800;
   if(score<bestScore){ best=c; bestScore=score; }
 }
 return best||failed;
}
function finalCarrierLabel(value){
 return ({cu:'联通',ct:'电信',cm:'移动',unknown:'未知'})[value]||String(value||'未知').toUpperCase();
}
function finalCarrierValues(list){
 const values=['cu','ct','cm'];
 for(const agent of list||[]){
   const carrier=String(agent.carrier||'unknown').toLowerCase();
   if(!values.includes(carrier)){ values.push(carrier); }
 }
 return values;
}
function selectFinalCarrier(carrier){
 selectedFinalCarrier=carrier;
 dataPage=1;
 saveDashboardState();
 updateAgentOverview(agentsCache);
 renderScanStatus(agentsCache);
 renderCarrierFinal(agentsCache);
 renderCarrierData(agentsCache);
}
function carrierCandidates(list,carrier,onlineOnly){
 const candidates=[];
 for(const agent of list||[]){
   if(String(agent.carrier||'unknown').toLowerCase()!==carrier||!agent.result||(onlineOnly&&!agentOnline(agent))){ continue; }
   const source=agent.display_name||agent.probe_source||agent.agent_id||'-';
   for(const candidate of agent.result.candidates||[]){
     candidates.push({...candidate,_agent_source:source,_agent_best_ip:agent.best?.ip||'',_agent_online:agentOnline(agent)});
   }
 }
 return candidates;
}
function renderCarrierFinal(list){
 const carriers=finalCarrierValues(list);
 if(!carriers.includes(selectedFinalCarrier)){ selectedFinalCarrier=carriers[0]||'cu'; }
 finalCarrierTabs.innerHTML=carriers.map(carrier=>'<button class="seg '+(carrier===selectedFinalCarrier?'active':'')+'" onclick="selectFinalCarrier(\''+attr(carrier)+'\')">'+finalCarrierLabel(carrier)+'</button>').join('');
 const candidates=carrierCandidates(list,selectedFinalCarrier,true);
 const carrierAgents=(list||[]).filter(agent=>String(agent.carrier||'unknown').toLowerCase()===selectedFinalCarrier);
 const onlineAgents=carrierAgents.filter(agentOnline);
 const newest=carrierAgents.map(agent=>agentSeenDate(agent.last_seen)).filter(Boolean).sort((a,b)=>b-a)[0];
 const offlineOnly=carrierAgents.length>0&&onlineAgents.length===0;
 finalNotice.classList.toggle('show',lastAgentFetchError||offlineOnly);
 finalNoticeText.textContent=lastAgentFetchError?'最近一次 Agent 数据刷新失败，当前保留上次成功结果':(offlineOnly?'当前没有在线 '+finalCarrierLabel(selectedFinalCarrier)+' Agent，最终区不采用离线结果'+(newest?'；最近上报 '+relativeTime(newest):''):'');
 const regions=finalRegions(settingsCache,candidates,'route_region',selectedFinalCarrier);
 carrierFinalRows.innerHTML=regions.map(region=>{
   const route=bestRouteForRegion(candidates,region);
   const speed=bestSpeedForRegion(candidates,region);
   const sources=[route?route._agent_source:'',speed?speed._agent_source:''].filter(Boolean);
   const source=[...new Set(sources)].join(' / ')||'-';
   const recommended=Boolean(route);
   const speedOK=speed&&speed.cf_speed_rtt_ms>0&&!speed.cf_speed_error;
   const speedIP=speed?speed.ip:'-';
   const speedMbps=speedOK?fmt(speed.cf_speed_mbps||0):(speed?.cf_speed_tested?'失败':'-');
   const status=recommended?(speed&& !speedOK?'测速失败':'推荐'):'待测';
   return '<tr class="'+(recommended?'recommended':'')+'"><td>'+region+(recommended?'<span class="result-badge">推荐</span>':'')+'</td><td>'+escapeHTML(route?.ip||'暂无可用结果')+'</td><td>'+escapeHTML(domainForRegion(settingsCache,selectedFinalCarrier,region))+'</td><td>'+(route?fmt(route.ping_rtt_ms||route.avg_rtt_ms||0)+' ms':'-')+'</td><td>'+escapeHTML(speedIP)+'</td><td>'+speedMbps+'</td><td>'+escapeHTML(source)+'</td><td class="'+(recommended&&(!speed||speedOK)?'status-good':'status-muted')+'">'+status+'</td></tr>';
 }).join('')||'<tr><td colspan="8">'+finalCarrierLabel(selectedFinalCarrier)+'暂无在线 Agent 数据</td></tr>';
}
function renderCarrierData(list){
 const candidates=carrierCandidates(list,selectedFinalCarrier,false);
 filterSummary(candidates);
 const filtered=sortCandidates(candidates);
 const page=renderPagination(filtered.length);
 rows.innerHTML=filtered.slice(page.startIndex,page.endIndex).map(c=>candidateRow(c,null)).join('')||'<tr><td colspan="16">'+finalCarrierLabel(selectedFinalCarrier)+'暂无匹配的测试数据</td></tr>';
 updateSortHeaders();
 applyVisibleColumns();
 sortButton.textContent=(sortState.key==='score'?'得分':'当前排序')+(sortState.dir==='asc'?' ↑':' ↓');
}
function updateSortHeaders(){
 document.querySelectorAll('th.sortable').forEach(th=>{
   const active=th.dataset.sort===sortState.key;
   th.classList.toggle('active',active);
   const base=th.textContent.replace(/[ ↑↓]+$/,'');
   th.textContent=base+(active?(sortState.dir==='asc'?' ↑':' ↓'):'');
 });
}
function sortRenderedRows(){
 const body=document.getElementById('rows');
 const trs=[...body.querySelectorAll('tr')];
 trs.sort((a,b)=>{
   if(sortState.key==='score'){
     const as=Number(a.dataset.speedok||0), bs=Number(b.dataset.speedok||0);
     if(as!==bs){ return bs-as; }
   }
   const av=a.dataset[sortState.key]??'';
   const bv=b.dataset[sortState.key]??'';
   const an=Number(av), bn=Number(bv);
   let cmp=0;
   if(Number.isFinite(an)&&Number.isFinite(bn)&&av!==''&&bv!==''){ cmp=an-bn; }
   else { cmp=String(av).localeCompare(String(bv),'zh-Hans',{numeric:true,sensitivity:'base'}); }
   return sortState.dir==='asc'?cmp:-cmp;
 });
 body.replaceChildren(...trs);
 updateSortHeaders();
}
function candidateRow(c,last){
 const klass=c.error?'bad':((c._agent_best_ip===c.ip||(last&&last.best&&last.best.ip===c.ip))?'best':'');
 const skipped=Boolean(c.error||c.quarantined);
 const score=skipped?'跳过':(Number.isFinite(c.score)?c.score.toFixed(1):'跳过');
 const colo=(c.observed_colo&&c.observed_pop&&c.observed_colo!==c.observed_pop)?(c.observed_colo+' / '+c.observed_pop):(c.observed_colo||c.observed_pop||'-');
 const region=candidateRegion(c);
 const routeRegion=(c.route_region||'-');
 const hint=[c.route_hint_ip,c.route_city,c.route_isp].filter(Boolean).join(' ');
 const source=regionSourceLabel(c.region_source);
 const routeFailedConflict=Boolean(
   String(c.route_error||'').trim()&&
   knownRegion(c.route_region)&&
   knownRegion(c.cf_region)&&
   knownRegion(c.route_region)!==knownRegion(c.cf_region)
 );
 const speedText=c.cf_speed_rtt_ms>0?(fmt(c.cf_speed_rtt_ms)+'ms'):(c.cf_speed_error?'失败':'-');
 const speedMbps=c.cf_speed_mbps>0?fmt(c.cf_speed_mbps):'-';
 const reason=routeFailedConflict
   ? ('CF Colo 回退：'+colo+'；'+decisionLabel(c.route_error))
   : (c.region_source==='cf-colo-tls')
   ? (source+'：'+colo+'，TLS '+fmt(c.avg_rtt_ms||0)+'ms；ICMP '+routeRegion+(hint?'，'+hint:''))
   : ((source&&source!=='-'?source+'：':'')+(hint||decisionLabel(c.route_error||c.error)||'-'));
 const pingText=skipped?'-':(c.ping_rtt_ms>0?fmt(c.ping_rtt_ms):(c.ping_error?'失败':'-'));
 const attrs=rowAttrs({ip:ipValue(c.ip),stage:stageLabel(c.stage),segment:c.segment||'',region,hint:reason,speedok:(c.cf_speed_rtt_ms>0&&!c.cf_speed_error)?1:0,cf_speed:skipped?999999:(c.cf_speed_rtt_ms||999999),cf_mbps:skipped?0:(c.cf_speed_mbps||0),colo,ping:skipped?999999:(c.ping_rtt_ms>0?c.ping_rtt_ms:999999),pingloss:skipped?999999:(c.ping_loss_rate||0),rtt:skipped?999999:(c.avg_rtt_ms||0),jitter:skipped?999999:(c.jitter_ms||0),loss:skipped?999999:(c.loss_rate||0),spike:skipped?999999:(c.spike_rate||0),score:skipped?999999:(Number.isFinite(c.score)?c.score:999999)});
 const agent=c._agent_source?(escapeHTML(c._agent_source)+(c._agent_online?'':'（离线）')):'-';
 return '<tr class="'+klass+'"'+attrs+' title="'+attr(c.ping_error||c.cf_speed_error||'')+'">'
  +'<td data-col="ip">'+c.ip+'</td><td data-col="stage">'+stageLabel(c.stage)+'</td><td data-col="segment">'+(c.segment||'-')+'</td><td data-col="region">'+region+'</td><td data-col="hint">'+reason+'</td>'
  +'<td data-col="speed">'+speedText+'</td><td data-col="mbps">'+speedMbps+'</td><td data-col="colo">'+colo+'</td><td data-col="ping">'+pingText+'</td><td data-col="pingloss">'+(skipped?'-':pct(c.ping_loss_rate))+'</td>'
  +'<td data-col="rtt">'+(skipped?'-':fmt(c.avg_rtt_ms||0))+'</td><td data-col="jitter">'+(skipped?'-':fmt(c.jitter_ms||0))+'</td><td data-col="loss">'+(skipped?'-':pct(c.loss_rate))+'</td><td data-col="spike">'+(skipped?'-':pct(c.spike_rate))+'</td><td data-col="score">'+score+'</td><td data-col="agent">'+agent+'</td></tr>';
}
function stateRows(state){
 const rows=[];
 const segments=Object.values(state.segments||{}).sort((a,b)=>{
   if((b.hot_ips?Object.keys(b.hot_ips).length:0)!==(a.hot_ips?Object.keys(a.hot_ips).length:0)){
     return (b.hot_ips?Object.keys(b.hot_ips).length:0)-(a.hot_ips?Object.keys(a.hot_ips).length:0);
   }
   return (b.preferred_rate||0)-(a.preferred_rate||0);
 });
 for(const seg of segments){
   const hot=Object.values(seg.hot_ips||{}).sort((a,b)=>(a.score||9999)-(b.score||9999));
   for(const item of hot){
     const attrs=rowAttrs({ip:ipValue(item.ip),stage:'热点',segment:seg.cidr,region:item.pop||'',hint:'',speedok:0,cf_speed:999999,cf_mbps:0,colo:'',ping:item.ping_rtt_ms||0,pingloss:item.ping_loss_rate||0,rtt:item.avg_rtt_ms||0,jitter:item.jitter_ms||0,loss:item.loss_rate||0,spike:item.spike_rate||0,score:item.score||0});
     rows.push('<tr class="hot"'+attrs+'><td>'+item.ip+'</td><td>热点</td><td>'+seg.cidr+'</td><td>'+item.pop+'</td><td>-</td><td>-</td><td>-</td><td>-</td><td>'+fmt(item.ping_rtt_ms||0)+'</td><td>'+pct(item.ping_loss_rate)+'</td><td>'+fmt(item.avg_rtt_ms||0)+'</td><td>'+fmt(item.jitter_ms||0)+'</td><td>'+pct(item.loss_rate)+'</td><td>'+pct(item.spike_rate)+'</td><td>'+fmt(item.score||0)+'</td></tr>');
   }
   const popText=Object.entries(seg.pop_counts||{}).map(([k,v])=>k+':'+v).join(' ');
   const stage=seg.promoted?'学习段':'学习中';
   const attrs=rowAttrs({ip:seg.cidr,stage,segment:seg.carrier,region:popText,hint:'',speedok:0,cf_speed:999999,cf_mbps:0,colo:'',ping:999999,pingloss:999999,rtt:seg.avg_rtt_ms||0,jitter:999999,loss:seg.loss_rate||0,spike:seg.spike_rate||0,score:seg.preferred_rate||0});
   rows.push('<tr'+attrs+'><td>'+seg.cidr+'</td><td>'+stage+'</td><td>'+seg.carrier+'</td><td>'+popText+'</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>'+fmt(seg.avg_rtt_ms||0)+'</td><td>-</td><td>'+pct(seg.loss_rate)+'</td><td>'+pct(seg.spike_rate)+'</td><td>'+pct(seg.preferred_rate)+'</td></tr>');
 }
 return rows.join('');
}
let settingsCache=null;
let controlCache=null;
let fullStateCache=null;
let agentsCache=[];
let lastAgentFetchError=false;
let agentDrafts=[];
let agentEditorDirty=false;
let selectedFinalCarrier='cu';
let activeSettingsTab='basic';
let modalScrollY=0;
function switchSettingsTab(tab,persist=true){
 if(!settingsTabs.includes(tab)){ tab='basic'; }
 activeSettingsTab=tab;
 document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===tab));
 document.querySelectorAll('.settings-pane').forEach(x=>x.style.display=x.id==='settings-'+tab?'block':'none');
 saveSettingsBtn.style.display=(tab==='agent'||tab==='agents')?'none':'';
 if(persist){ saveDashboardState(); }
}
async function openSettings(){
 modalScrollY=window.scrollY;
 document.body.style.top='-'+modalScrollY+'px';
 document.body.classList.add('modal-open');
 settingsModal.classList.add('open');
 settingsMsg.textContent='正在加载设置...';
 const res=await fetch('/api/settings?ts='+Date.now()).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ settingsMsg.textContent=res.error; return; }
 settingsCache=res;
 fillSettings(res);
 renderAgentManagement(agentsCache,true);
 settingsMsg.textContent='';
}
function closeSettings(){
 if(!settingsModal.classList.contains('open')){ return; }
 settingsModal.classList.remove('open');
 document.body.classList.remove('modal-open');
 document.body.style.top='';
 agentEditorDirty=false;
 window.scrollTo(0,modalScrollY);
}
function shellQuote(v){
 v=String(v||'');
 if(/^[A-Za-z0-9_./:@-]+$/.test(v)){ return v; }
 return "'"+v.replace(/'/g,"'\\''")+"'";
}
function defaultAgentServerURL(){
 const configured=(settingsCache?.server_url||'').trim().replace(/\/+$/,'');
 return configured||'http://172.23.93.195:19199';
}
function resetAgentInstallCommand(){
 agentServerURL.value=defaultAgentServerURL();
 agentServerURL.dataset.autoDefault='1';
 agentInstallID.value='';
 agentInstallCarrier.value='auto';
 agentInstallToken.value='';
 updateAgentInstallCommand();
}
function updateAgentInstallCommand(){
 const server=(agentServerURL.value||defaultAgentServerURL()).trim().replace(/\/+$/,'');
 const id=agentInstallID.value.trim();
 const carrier=(agentInstallCarrier.value||'auto').trim();
 const token=(agentInstallToken.value||'').trim();
 const fallbackInstall='https://raw.githubusercontent.com/kuaichu/CFAnycastRouter/main/install.sh';
 const parts=[
   '(curl -fsSL --connect-timeout 5 --max-time 30 '+shellQuote(server+'/install.sh')+' || curl -fsSL --connect-timeout 5 --max-time 30 '+shellQuote(fallbackInstall)+')',
   '| sudo bash -s --',
   '--server '+shellQuote(server),
   '--carrier '+shellQuote(carrier)
 ];
 if(id){ parts.push('--id '+shellQuote(id)); }
 if(token){ parts.push('--token '+shellQuote(token)); }
 agentInstallCommand.value=parts.join(' ');
}
async function copyAgentInstallCommand(){
 updateAgentInstallCommand();
 try{
   await navigator.clipboard.writeText(agentInstallCommand.value);
   agentInstallMsg.textContent='已复制安装命令';
 }catch(e){
   agentInstallCommand.focus();
   agentInstallCommand.select();
   agentInstallMsg.textContent='浏览器不允许自动复制，请手动复制文本框内容';
 }
}
function fillSettings(s){
 setProbeSource.value=s.probe_source||'';
 setCarrier.value=s.carrier||'auto';
 if(!agentServerURL.value||agentServerURL.dataset.autoDefault==='1'){
   agentServerURL.value=defaultAgentServerURL();
   agentServerURL.dataset.autoDefault='1';
 }
 setInterval.value=s.check_interval_seconds||300;
 setProbeAttempts.value=s.probe_attempts||5;
 setProbeTimeout.value=s.probe_timeout_seconds||3;
 setSpikeThreshold.value=s.spike_threshold_ms||120;
 setSpikeMultiplier.value=s.spike_multiplier||2;
 setTraceBudget.value=s.max_route_traces_per_cycle||24;
 setSampleStep.value=s.sample_step||4;
 setSeedCIDRStep.value=s.seed_cidr_step||16;
 setSeedPreflight.value=s.seed_preflight_max_per_cycle||256;
 setSeedSegments.value=s.max_seed_segments_per_cycle||8;
 setLearnedSegments.value=s.max_learned_segments_per_cycle??16;
 setSamplesPerSegment.value=s.max_samples_per_segment_per_cycle||8;
 setPromoteMinSamples.value=s.promote_min_samples||6;
 setPromoteProbability.value=Math.round((s.promote_pop_probability||0.7)*100);
 setHotMaxPerSegment.value=s.hot_max_per_segment||8;
 setHotMaxScore.value=s.hot_max_score||95;
 const dns=s.cloudflare_dns||{};
 setDnsEnabled.checked=Boolean(dns.enabled);
 setZoneName.value=dns.zone_name||'';
 setZoneID.value=dns.zone_id||'';
 setTokenEnv.value=dns.token_env||'CLOUDFLARE_API_TOKEN';
 setTTL.value=dns.ttl||60;
 setProxied.checked=Boolean(dns.proxied);
 recordList.innerHTML='';
 const records=(dns.record_sets&&dns.record_sets.length)?dns.record_sets:Object.entries(dns.records||{}).map(([region,domain])=>({enabled:true,carrier:s.carrier||'unknown',region,type:'A',domain}));
 for(const record of records){ addRecordRow(record); }
 if(recordList.children.length===0){
   autoGenerateDNSRecords(true);
 }
 const speed=s.speed_test||{};
 setSpeedEnabled.checked=speed.enabled!==false;
 setSpeedHost.value=speed.host||'speed.cloudflare.com';
 setSpeedPath.value=speed.path||'/__down';
 setSpeedBytes.value=speed.bytes||262144;
 setSpeedTopN.value=speed.top_n||5;
 if(!agentServerURL.value){ resetAgentInstallCommand(); }
 updateAgentInstallCommand();
}
function addRecordRow(record={}){
 const row=document.createElement('div');
 row.className='record-row';
 row.innerHTML="<select class=\"rec-carrier\"><option value=\"cu\">联通</option><option value=\"ct\">电信</option><option value=\"cm\">移动</option><option value=\"unknown\">未知</option></select><select class=\"rec-region\"><option>HK</option><option>US</option><option>JP</option><option>SG</option><option>EU</option><option>CN</option></select><select class=\"rec-type\"><option>A</option><option>AAAA</option></select><input class=\"rec-domain\" placeholder=\"cu-cf-us.example.com\"><label class=\"check-row\"><input class=\"rec-enabled\" type=\"checkbox\">启用</label><button class=\"icon-btn\" type=\"button\" onclick=\"this.closest('.record-row').remove()\">×</button>";
 recordList.appendChild(row);
 row.querySelector('.rec-carrier').value=(record.carrier||setCarrier.value||'unknown').toLowerCase();
 row.querySelector('.rec-region').value=(record.region||'HK').toUpperCase();
 row.querySelector('.rec-type').value=(record.type||'A').toUpperCase();
 row.querySelector('.rec-domain').value=record.domain||'';
 row.querySelector('.rec-enabled').checked=record.enabled!==false;
}
function dnsBaseDomain(){
 return (setZoneName.value||'').trim().replace(/^\.+|\.+$/g,'').toLowerCase();
}
function existingDNSRecordKeys(){
 const keys=new Set();
 recordList.querySelectorAll('.record-row').forEach(row=>{
   const carrier=row.querySelector('.rec-carrier').value.trim().toLowerCase();
   const region=row.querySelector('.rec-region').value.trim().toUpperCase();
   const type=row.querySelector('.rec-type').value.trim().toUpperCase();
   if(carrier&&region&&type){ keys.add(carrier+'|'+region+'|'+type); }
 });
 return keys;
}
function autoGenerateDNSRecords(silent){
 const base=dnsBaseDomain();
 if(!base){
   if(!silent){ dnsGenerateMsg.textContent='先填写 Zone Name，再自动生成解析记录'; }
   return;
 }
 const keys=existingDNSRecordKeys();
 let added=0;
 for(const carrier of ['cu','ct','cm']){
   for(const region of ['HK','US','JP','SG']){
     const key=carrier+'|'+region+'|A';
     if(keys.has(key)){ continue; }
     addRecordRow({enabled:true,carrier,region,type:'A',domain:carrier+'-cf-'+region.toLowerCase()+'.'+base});
     keys.add(key);
     added++;
   }
 }
 dnsGenerateMsg.textContent=added?'已自动补齐 '+added+' 条解析记录':'解析记录已经齐了，没有重复添加';
}
function collectSettings(){
 const records=[...recordList.querySelectorAll('.record-row')].map(row=>({
   enabled:row.querySelector('.rec-enabled').checked,
   carrier:row.querySelector('.rec-carrier').value.trim().toLowerCase(),
   region:row.querySelector('.rec-region').value.trim().toUpperCase(),
   type:row.querySelector('.rec-type').value.trim().toUpperCase(),
   domain:row.querySelector('.rec-domain').value.trim()
 })).filter(r=>r.region&&r.type&&r.domain);
 return {
   probe_source:setProbeSource.value.trim(),
   carrier:setCarrier.value,
   server_url:(agentServerURL.value||defaultAgentServerURL()).trim().replace(/\/+$/,''),
   check_interval_seconds:Number(setInterval.value)||300,
   probe_attempts:Number(setProbeAttempts.value)||5,
   probe_timeout_seconds:Number(setProbeTimeout.value)||3,
   spike_threshold_ms:Number(setSpikeThreshold.value)||120,
   spike_multiplier:Number(setSpikeMultiplier.value)||2,
   max_route_traces_per_cycle:Number(setTraceBudget.value)||24,
   sample_step:Number(setSampleStep.value)||4,
   seed_cidr_step:Number(setSeedCIDRStep.value)||16,
   seed_preflight_max_per_cycle:Number(setSeedPreflight.value)||256,
   max_seed_segments_per_cycle:Number(setSeedSegments.value)||8,
   max_learned_segments_per_cycle:Math.max(0,Number(setLearnedSegments.value)||0),
   max_samples_per_segment_per_cycle:Number(setSamplesPerSegment.value)||8,
   promote_min_samples:Number(setPromoteMinSamples.value)||6,
   promote_pop_probability:(Number(setPromoteProbability.value)||70)/100,
   hot_max_per_segment:Number(setHotMaxPerSegment.value)||8,
   hot_max_score:Number(setHotMaxScore.value)||95,
   cloudflare_dns:{
     enabled:setDnsEnabled.checked,
     zone_id:setZoneID.value.trim(),
     zone_name:setZoneName.value.trim(),
     token_env:setTokenEnv.value.trim()||'CLOUDFLARE_API_TOKEN',
     ttl:Number(setTTL.value)||60,
     proxied:setProxied.checked,
     record_sets:records
   },
   speed_test:{
     enabled:setSpeedEnabled.checked,
     host:setSpeedHost.value.trim()||'speed.cloudflare.com',
     path:setSpeedPath.value.trim()||'/__down',
     bytes:Number(setSpeedBytes.value)||262144,
     top_n:Number(setSpeedTopN.value)||5
   }
 };
}
async function saveSettings(){
 settingsMsg.textContent='正在保存设置...';
 const res=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collectSettings())}).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ settingsMsg.textContent=res.error; return; }
 settingsMsg.textContent='已保存，下一轮检测生效';
 settingsCache=res.settings;
 setTimeout(closeSettings,700);
}
function escapeHTML(v){ return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function agentSeenDate(value){
 if(!value){ return null; }
 const date=new Date(value);
 return Number.isFinite(date.getTime())&&date.getFullYear()>2000?date:null;
}
function relativeTime(value){
 const date=value instanceof Date?value:agentSeenDate(value);
 if(!date){ return '-'; }
 const seconds=Math.max(0,Math.floor((Date.now()-date.getTime())/1000));
 if(seconds<60){ return seconds+' 秒前'; }
 if(seconds<3600){ return Math.floor(seconds/60)+' 分钟前'; }
 if(seconds<86400){ return Math.floor(seconds/3600)+' 小时前'; }
 return Math.floor(seconds/86400)+' 天前';
}
function agentOnline(a){
 const seen=agentSeenDate(a?.last_seen)?.getTime()||0;
 const threshold=Math.max(Number(settingsCache?.check_interval_seconds||300)*2000,180000);
 return seen>0&&Date.now()-seen<=threshold;
}
function carrierLabel(value){ return ({cu:'中国联通',ct:'中国电信',cm:'中国移动',unknown:'未知'})[value]||value||'未知'; }
function agentStatusText(a){
 if(a.last_error){ return '<span class="agent-error">错误：'+escapeHTML(a.last_error)+'</span>'; }
 if(a.status==='paused'){ return '<span class="status-muted">已暂停，等待恢复探测</span>'; }
 if(a.status==='scanning'){ return '<span class="agent-scanning">扫描中，已完成 '+(a.candidate_count||0)+' 个候选</span>'; }
 if(a.status==='idle'){ return '本轮完成，共 '+(a.candidate_count||0)+' 个候选'; }
 return '候选 '+(a.candidate_count||0);
}
function agentRunState(a){
 if(a.status==='paused'){ return {className:'paused', text:'暂停'}; }
 if(controlCache?.paused&&agentOnline(a)){ return {className:'pending', text:'等待暂停'}; }
 if(a.status==='scanning'){ return {className:'running', text:'运行中'}; }
 return {className:'running', text:'运行'};
}
function renderScanStatus(list){
 const carrierAgents=(list||[]).filter(agent=>String(agent.carrier||'unknown').toLowerCase()===selectedFinalCarrier);
 const scanning=carrierAgents.filter(agent=>agent.status==='scanning');
 const candidates=carrierCandidates(list,selectedFinalCarrier,false);
 const completed=carrierAgents.reduce((sum,agent)=>sum+Number(agent.candidate_count||0),0);
 const usable=candidates.filter(isSelectableCandidate).length;
 const routed=candidates.filter(candidate=>knownRegion(candidate.route_region)||knownRegion(candidate.cf_region)).length;
 const budget=Number(settingsCache?.max_route_traces_per_cycle||0);
 const stage=scanning.length?'候选测量':(candidates.length?'结果汇总':'等待 Agent');
 scanStage.innerHTML=stage+' <span class="scan-stage-badge">'+(scanning.length?'扫描中':'待机')+'</span>';
 scanCount.innerHTML='已完成 <strong>'+completed+'</strong> 个候选';
 scanRound.textContent=scanning.length?'本轮运行中 · '+scanning.length+' 个 Agent':'最近结果 · '+carrierAgents.length+' 个 Agent';
 scanMeta.textContent='可用候选 '+usable+' · 已判定地区 '+routed+(budget?' · 单 Agent 路由预算 '+budget:'');
 scanStep1.classList.toggle('active',Boolean(candidates.length||scanning.length));
 scanStep2.classList.toggle('active',Boolean(scanning.length));
 scanStep3.classList.toggle('active',!scanning.length&&Boolean(candidates.length));
}
function updateAgentOverview(list){
 const agents=(list||[]).filter(agent=>String(agent.carrier||'unknown').toLowerCase()===selectedFinalCarrier&&agentOnline(agent)&&agent.best?.ip);
 agents.sort((a,b)=>(Number(a.best?.score)||999999)-(Number(b.best?.score)||999999));
 const agent=agents[0];
 const liveCandidates=carrierCandidates(list,selectedFinalCarrier,true).filter(isSelectableCandidate).sort((a,b)=>(Number(a.score)||999999)-(Number(b.score)||999999));
 const candidate=agent?.best||liveCandidates[0];
 if(!candidate){
   best.textContent='-';
   bestSub.textContent='等待 '+finalCarrierLabel(selectedFinalCarrier)+' Agent 可用候选';
   pop.textContent='-';
   popSub.textContent='等待 Cloudflare Colo';
   return;
 }
 const region=candidate.region||candidate.route_region||candidate.cf_region||'-';
 const colo=candidate.observed_colo||candidate.observed_pop||'';
 best.textContent=candidate.ip;
 bestSub.textContent=((agent&&(agent.display_name||agent.probe_source||agent.agent_id))||candidate._agent_source||finalCarrierLabel(selectedFinalCarrier))+' · '+finalCarrierLabel(selectedFinalCarrier);
 pop.textContent=region+(colo&&colo!==region?' · '+colo:'');
 popSub.textContent=(candidate.route_city||candidate.route_country||colo||'Cloudflare')+(candidate.route_isp?' · '+candidate.route_isp:'');
}
function carrierOptions(value){
 return ['cu','ct','cm','unknown'].map(v=>'<option value="'+v+'"'+(v===value?' selected':'')+'>'+carrierLabel(v)+'</option>').join('');
}
function agentEditorHTML(a,index,isDraft){
 const online=agentOnline(a);
 const best=a.best||{};
 const agentID=escapeHTML(a.agent_id||'');
 const title=escapeHTML(a.display_name||a.agent_id||('Agent '+index));
 const host=a.hostname?' · 主机 '+escapeHTML(a.hostname):'';
 const seenDate=agentSeenDate(a.last_seen);
 const seen=seenDate?seenDate.toLocaleString():'尚未上报';
 const bestText=best.ip?('最佳 '+escapeHTML(best.ip)+' / '+escapeHTML(best.route_region||best.region||'-')):'暂无测速结果';
 return '<article class="agent-editor" data-agent-id="'+attr(a.agent_id||'')+'" data-draft-id="'+attr(a._draft_id||'')+'">'
  +'<div class="agent-editor-head"><div><div class="agent-editor-title">'+title+'</div><div class="agent-editor-status"><span class="status-dot '+(online?'online':'offline')+'"></span>'+(online?'在线':'离线')+host+'</div></div><button class="danger" onclick="removeAgentEditor(this)">'+(isDraft?'取消':'删除')+'</button></div>'
  +'<div class="agent-editor-grid">'
  +'<div class="field"><label>Agent ID</label><input data-field="agent_id" value="'+agentID+'" '+(isDraft?'':'readonly')+' placeholder="例如 hz-cu-01"><div class="small">安装脚本使用同一个 ID；已创建后不可直接改名。</div></div>'
  +'<div class="field"><label>显示名</label><input data-field="display_name" value="'+escapeHTML(a.display_name||'')+'" placeholder="例如 杭州联通入口"></div>'
  +'<div class="field"><label>地区 / 探测源</label><input data-field="probe_source" value="'+escapeHTML(a.probe_source||'')+'" placeholder="例如 宁波联通、洛杉矶机房"></div>'
  +'<div class="field"><label>运营商</label><select data-field="carrier">'+carrierOptions(a.carrier||'unknown')+'</select></div>'
  +'</div><div class="agent-editor-foot"><div class="agent-editor-meta">最后上报：'+seen+' · '+bestText+' · '+agentStatusText(a)+'</div><div class="agent-editor-actions"><button onclick="prepareAgentInstall(this)">生成重连命令</button><button class="primary" onclick="saveAgentConfig(this)">保存 Agent</button></div></div></article>';
}
function renderAgentManagement(list,force){
 if(!force&&(agentEditorDirty||agentManageList.contains(document.activeElement))){ return; }
 const online=list.filter(agentOnline).length;
 agentManageSummary.innerHTML='<span><strong>'+list.length+'</strong>节点</span><span><strong>'+online+'</strong>在线</span>';
 const all=list.map(a=>({agent:a,draft:false})).concat(agentDrafts.map(a=>({agent:a,draft:true})));
 if(!all.length){
   agentManageList.innerHTML='<div class="agent-empty">尚未配置 Agent。先新增节点，再将生成的安装命令放到 VPS 执行。</div>';
   return;
 }
 agentManageList.innerHTML=all.map((item,i)=>agentEditorHTML(item.agent,i+1,item.draft)).join('');
}
function addAgentDraft(){
 const suffix=Math.random().toString(36).slice(2,8);
 agentDrafts.push({_draft_id:suffix,agent_id:'agent-'+suffix,display_name:'',probe_source:'',carrier:'unknown'});
 agentEditorDirty=true;
 renderAgentManagement(agentsCache,true);
 const cards=agentManageList.querySelectorAll('.agent-editor');
 cards[cards.length-1]?.scrollIntoView({block:'nearest',behavior:'smooth'});
}
function readAgentEditor(button){
 const card=button.closest('.agent-editor');
 const value=name=>card.querySelector('[data-field="'+name+'"]').value.trim();
 return {card,config:{agent_id:value('agent_id'),display_name:value('display_name'),probe_source:value('probe_source'),carrier:value('carrier')}};
}
async function saveAgentConfig(button){
 const {card,config}=readAgentEditor(button);
 if(!config.agent_id){ settingsMsg.textContent='Agent ID 不能为空'; return; }
 button.disabled=true;
 settingsMsg.textContent='正在保存 '+config.agent_id+'...';
 const res=await fetch('/api/agents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}).then(r=>r.json()).catch(e=>({error:e.message}));
 button.disabled=false;
 if(res.error){ settingsMsg.textContent=res.error; return; }
 agentDrafts=agentDrafts.filter(a=>a._draft_id!==card.dataset.draftId);
 const pos=agentsCache.findIndex(a=>a.agent_id===res.agent.agent_id);
 if(pos>=0){ agentsCache[pos]=res.agent; }else{ agentsCache.push(res.agent); }
 agentEditorDirty=false;
 renderAgentManagement(agentsCache,true);
 renderAgents({agents:agentsCache});
 settingsMsg.textContent='已保存 '+config.agent_id+'，在线节点下一轮自动生效';
}
function prepareAgentInstall(button){
 const {config}=readAgentEditor(button);
 agentInstallID.value=config.agent_id||'';
 agentInstallCarrier.value=config.carrier||'unknown';
 updateAgentInstallCommand();
 switchSettingsTab('agent');
 agentInstallMsg.textContent='已指定 '+agentInstallID.value+'；此命令只用于该 Agent 原机器重装或重连，不要放到新 VPS 执行。';
}
function removeAgentEditor(button){
 const card=button.closest('.agent-editor');
 if(card.dataset.draftId){
   agentDrafts=agentDrafts.filter(a=>a._draft_id!==card.dataset.draftId);
   agentEditorDirty=false;
   renderAgentManagement(agentsCache,true);
   return;
 }
 removeAgentRecord(card.dataset.agentId);
}
async function removeAgentRecord(agentID){
 if(!agentID||!confirm('删除 Agent '+agentID+'？运行中的 Agent 下次上报时会作为未托管节点重新出现。')){ return; }
 const res=await fetch('/api/agents?id='+encodeURIComponent(agentID),{method:'DELETE'}).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ settingsMsg.textContent=res.error; return; }
 agentsCache=agentsCache.filter(a=>a.agent_id!==agentID);
 agentEditorDirty=false;
 renderAgentManagement(agentsCache,true);
 renderAgents({agents:agentsCache});
 settingsMsg.textContent=res.removed?'已删除 '+agentID:'未找到 '+agentID;
}
function hasActiveDataSelection(){
 const selection=window.getSelection?.();
 if(!selection||selection.isCollapsed||!selection.toString().trim()){
   selectionNotice.classList.remove('show');
   tableRefreshStatus.classList.remove('paused');
   tableRefreshStatus.querySelector('span:last-child').textContent='实时数据持续接收';
   return false;
 }
 const range=selection.rangeCount?selection.getRangeAt(0):null;
 const roots=[carrierFinalRows,agentRows,rows];
 const active=roots.some(root=>root&&range&&range.intersectsNode(root));
 selectionNotice.classList.toggle('show',active);
 tableRefreshStatus.classList.toggle('paused',active);
 tableRefreshStatus.querySelector('span:last-child').textContent=active?'选区保护中':'实时数据持续接收';
 return active;
}
function clearTableSelection(){
 window.getSelection?.().removeAllRanges();
 selectionNotice.classList.remove('show');
 tableRefreshStatus.classList.remove('paused');
 tableRefreshStatus.querySelector('span:last-child').textContent='实时数据持续接收';
 renderAgents({agents:agentsCache});
}
function renderAgents(payload){
 const list=(payload&&payload.agents)||[];
 agentsCache=list;
 renderAgentManagement(list);
 updateAgentOverview(list);
 renderScanStatus(list);
 const online=list.filter(agentOnline).length;
 const offline=Math.max(0,list.length-online);
 const newest=list.map(agent=>agentSeenDate(agent.last_seen)).filter(Boolean).sort((a,b)=>b-a)[0];
 agentSummaryLine.innerHTML='<span class="status-good">●</span> '+online+' 在线 · '+offline+' 离线'+(newest?' · 最近上报 '+relativeTime(newest):'');
 if(hasActiveDataSelection()){ return; }
 renderCarrierFinal(list);
 renderCarrierData(list);
 if(!list.length){
   agentRows.innerHTML='<tr><td colspan="9">等待 Agent 上报</td></tr>';
   return;
 }
 agentRows.innerHTML=list.map(a=>{
   const best=a.best||{};
   const seenDate=agentSeenDate(a.last_seen);
   const online=agentOnline(a);
   const seen=seenDate?relativeTime(seenDate):'-';
   const id=[a.display_name||a.agent_id,a.hostname&&a.hostname!==a.agent_id?a.hostname:''].filter(Boolean).map(escapeHTML).join(' / ');
   const statusText=a.status==='paused'?'已暂停':(a.status==='scanning'?'扫描中 · '+a.candidate_count+' 个':a.candidate_count+' 个');
   const runState=agentRunState(a);
   const stateHTML='<span class="agent-status-stack"><span class="status-pill '+(online?'':'offline')+'"><span class="status-dot '+(online?'online':'offline')+'"></span>'+(online?'在线':'离线')+'</span><span class="status-pill '+runState.className+'">'+runState.text+'</span></span>';
   return '<tr><td>'+id+(!online&&seenDate?'<span class="agent-name-sub">显示最后一次成功上报</span>':'')+'</td><td class="status-good">'+escapeHTML(a.probe_source||'-')+'</td><td>'+finalCarrierLabel(a.carrier)+'</td><td>'+stateHTML+'</td><td>'+seen+'</td><td>'+escapeHTML(statusText)+'</td><td>'+escapeHTML(best.ip||'-')+'</td><td>'+escapeHTML(best.region||best.route_region||'-')+'</td><td>'+(Number.isFinite(best.score)?best.score.toFixed(1):'-')+'</td></tr>';
 }).join('');
}
async function refresh(){
 const settingsPromise=settingsCache?Promise.resolve(settingsCache):fetch('/api/settings?ts='+Date.now()).then(r=>r.json()).catch(()=>null);
 const [last,state,seeds,settings,control,agents]=await Promise.all([
   fetch('/api/last?ts='+Date.now()).then(r=>r.json()).catch(()=>null),
   fetch('/api/state-summary?ts='+Date.now()).then(r=>r.json()).catch(()=>null),
   fetch('/api/seeds?ts='+Date.now()).then(r=>r.json()).catch(()=>null),
   settingsPromise,
   fetch('/api/control?ts='+Date.now()).then(r=>r.json()).catch(()=>null),
   fetch('/api/agents?ts='+Date.now()).then(r=>r.json()).catch(()=>null)
 ]);
 if(settings&&!settings.error){ settingsCache=settings; }
 if(agents&&Array.isArray(agents.agents)){
   lastAgentFetchError=false;
   renderAgents(agents);
 }else{
   lastAgentFetchError=true;
   renderAgents({agents:agentsCache});
 }
 if(control&&!control.error){ controlCache=control; applyControl(control); }
 if(seeds&&seeds.text&&!seedDirty&&document.activeElement!==seedInput){ seedInput.value=seeds.text; }
 lastUpdated.textContent='最后刷新：刚刚';
if(last&&last.candidates){
   mode.textContent=controlModeText(controlCache,'实时探测');
   const currentIP=last.current_ip||state?.current_ip||'';
   current.textContent=currentIP||'-';
   decision.textContent=decisionLabel(last.decision);
   currentSub.textContent=currentIP?(last.current_ip?'当前生效入口':'上轮入口'):'尚未选出活动入口';
   updateAgentOverview(agentsCache);
   const decisionText=String(last.decision||'');
   decisionTitle.textContent=decisionText.startsWith('switched:')?'已切换':(decisionText.includes('kept current')||decisionText.includes('保持当前')?'保持当前':(decisionText.includes('agent measurement report')?'等待汇总':'等待判断'));
   return;
 }
 mode.textContent=controlModeText(controlCache,'状态快照');
 const snapshotIP=state?.current_ip||'';
 current.textContent=snapshotIP||'-';
 decision.textContent=decisionLabel(state?.last_decision)||'等待首次探测';
 currentSub.textContent=snapshotIP?'上轮入口':'尚未选出活动入口';
 updateAgentOverview(agentsCache);
 decisionTitle.textContent='等待判断';
}
async function refreshNow(){
 lastUpdated.textContent='正在刷新...';
 await refresh();
}
async function saveSeeds(){
 seedMsg.textContent='正在保存种子...';
 const res=await fetch('/api/seeds',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({seeds:seedInput.value})}).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ seedMsg.textContent=res.error; return; }
 seedDirty=false;
 seedMsg.textContent='已保存 '+res.seed_ips+' 个 IP 种子和 '+res.seed_cidrs+' 个 CIDR 种子';
 refresh();
}
async function scanNow(){
 seedMsg.textContent='已加入扫描队列...';
 const res=await fetch('/api/scan',{method:'POST'}).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ seedMsg.textContent=res.error; return; }
 seedMsg.textContent='正在扫描，结果会自动刷新';
 setTimeout(refresh,1500);
}
function applyControl(control){
 const paused=Boolean(control?.paused);
 stopBtn.disabled=paused;
 startBtn.disabled=!paused;
 stopBtn.hidden=paused;
 startBtn.hidden=!paused;
 liveStatus.querySelector('.live-dot').classList.toggle('paused',paused);
 mode.textContent=controlModeText(control,mode.textContent||'状态快照');
}
function controlModeText(control,fallback){
 if(!control){ return fallback; }
 if(control.paused&&control.scanning){ return '本轮扫描中，结束后暂停'; }
 if(control.paused){ return '自动探测已暂停，显示最后一次结果'; }
 if(control.scanning){ return '实时探测中'; }
 return fallback;
}
async function setAutoScan(action){
 const stopping=action==='stop';
 const text=stopping?'停止自动探测？当前页面会继续运行。':'恢复自动探测？';
 if(!confirm(text)){ return; }
 stopBtn.disabled=true;
 startBtn.disabled=true;
 mode.textContent=stopping?'正在停止自动探测':'正在恢复自动探测';
 const res=await fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})}).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){
   mode.textContent=res.error;
   applyControl(controlCache);
   return;
 }
 controlCache=res;
 applyControl(res);
 decision.textContent=stopping?'已停止后续自动探测':'已恢复自动探测';
}
async function lookupIPRange(){
 lookupMsg.textContent='正在查询前缀并抽样验证...';
 const res=await fetch('/api/lookup-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:lookupIP.value})}).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ lookupMsg.textContent=res.error; return; }
 const rate=Number.isFinite(res.match_rate)?(res.match_rate*100).toFixed(0)+'%':'-';
 lookupMsg.textContent=(res.accepted?'已保留 ':'已舍弃 ')+(res.accepted_cidr||res.tested_prefix||res.lookup_prefix)+'；基准路由 '+(res.reference_region||'-')+'；CF Colo '+(res.reference_pop||'-')+'；匹配率 '+rate+'；'+decisionLabel(res.reason||'');
 refresh();
}
async function refreshLoop(){
 await refresh();
 const slow=controlCache?.paused&&!controlCache?.scanning;
 setTimeout(refreshLoop,slow?10000:1500);
}
restoreDashboardState();
refreshLoop();
seedInput.addEventListener('input',()=>{ seedDirty=true; });
dataSearch.addEventListener('input',()=>{ dataQuery=dataSearch.value.trim(); dataPage=1; saveDashboardState(); renderCarrierData(agentsCache); });
pageSizeSelect.addEventListener('change',()=>{ dataPageSize=Number(pageSizeSelect.value)||50; dataPage=1; saveDashboardState(); renderCarrierData(agentsCache); });
document.addEventListener('selectionchange',()=>{ hasActiveDataSelection(); });
document.addEventListener('click',event=>{ if(!columnMenu.contains(event.target)&&event.target!==columnPickerBtn){ toggleColumnMenu(false); } });
document.addEventListener('keydown',event=>{ if(event.key==='Escape'){ closeSettings(); toggleColumnMenu(false); } });
document.querySelectorAll('#regionFilters .seg').forEach(btn=>{
 btn.addEventListener('click',()=>{
   regionFilter=btn.dataset.region;
   document.querySelectorAll('#regionFilters .seg').forEach(x=>x.classList.toggle('active',x===btn));
   saveDashboardState();
   renderCarrierData(agentsCache);
 });
});
document.querySelectorAll('th.sortable').forEach(th=>{
 th.addEventListener('click',()=>{
   const key=th.dataset.sort;
   if(sortState.key===key){ sortState.dir=sortState.dir==='asc'?'desc':'asc'; }
   else { sortState={key,dir:['cf_speed','cf_mbps','ping','pingloss','rtt','jitter','loss','spike','score'].includes(key)?'asc':'asc'}; }
   dataPage=1;
   saveDashboardState();
   renderCarrierData(agentsCache);
 });
});
</script>
</body></html>`))
