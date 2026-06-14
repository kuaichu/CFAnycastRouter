package dashboard

import (
	"archive/tar"
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
	return &Server{port: port, statePath: statePath, cfgPath: cfgPath, onScan: onScan, onSeeds: onSeeds, onLookup: onLookup, onSettings: onSettings, onControl: onControl, agents: newAgentRegistry()}
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
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "install.sh not found: "+err.Error(), http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = io.Copy(w, f)
}

func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/download/")
	switch name {
	case "cf-router-linux-amd64", "cf-router-linux-arm64":
	default:
		http.NotFound(w, r)
		return
	}

	path := filepath.Join(".", "dist", name)
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "agent binary not found: "+err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeFile(w, r, path)
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
	if in == nil {
		return nil
	}
	out := *in
	if in.Best != nil {
		best := safeCandidate(*in.Best)
		out.Best = &best
	}
	out.Candidates = make([]router.Candidate, len(in.Candidates))
	for i, c := range in.Candidates {
		out.Candidates[i] = safeCandidate(c)
	}
	return &out
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
	if math.IsInf(c.AvgRTTMs, 0) || math.IsNaN(c.AvgRTTMs) {
		c.AvgRTTMs = 0
	}
	if math.IsInf(c.PingRTTMs, 0) || math.IsNaN(c.PingRTTMs) {
		c.PingRTTMs = 0
	}
	if math.IsInf(c.PingLossRate, 0) || math.IsNaN(c.PingLossRate) {
		c.PingLossRate = 1
	}
	if math.IsInf(c.JitterMs, 0) || math.IsNaN(c.JitterMs) {
		c.JitterMs = 0
	}
	if math.IsInf(c.LossRate, 0) || math.IsNaN(c.LossRate) {
		c.LossRate = 1
	}
	if math.IsInf(c.SpikeRate, 0) || math.IsNaN(c.SpikeRate) {
		c.SpikeRate = 0
	}
	if math.IsInf(c.Score, 0) || math.IsNaN(c.Score) {
		c.Score = 999999
	}
	if math.IsInf(c.PopPenalty, 0) || math.IsNaN(c.PopPenalty) {
		c.PopPenalty = 0
	}
	if math.IsInf(c.DriftPenalty, 0) || math.IsNaN(c.DriftPenalty) {
		c.DriftPenalty = 0
	}
	if math.IsInf(c.HijackPenalty, 0) || math.IsNaN(c.HijackPenalty) {
		c.HijackPenalty = 0
	}
	if math.IsInf(c.LearnedBonus, 0) || math.IsNaN(c.LearnedBonus) {
		c.LearnedBonus = 0
	}
	return c
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
.modal{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;padding:24px;z-index:10}
.modal.open{display:flex}
.modal-card{width:min(900px,calc(100vw - 48px));max-height:calc(100vh - 48px);overflow:auto;background:linear-gradient(135deg,#13202c,#102d2d);border:1px solid #31546a;border-radius:24px;padding:26px;box-shadow:0 20px 80px rgba(0,0,0,.45)}
.modal-head{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;margin-bottom:18px}
.modal h2{font-size:24px;margin:0}.tabs{display:flex;gap:16px;border-bottom:1px solid var(--line);margin-bottom:18px}
.tab{padding:10px 0;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}.tab.active{color:var(--ok);border-color:var(--ok)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px 18px}.field label{display:block;color:#c7d5e8;font-weight:600;margin-bottom:6px}
.field input,.field select{width:100%;box-sizing:border-box;background:#071018;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px 14px;font:14px ui-monospace,SFMono-Regular,Consolas,monospace}
.field input:focus,.field select:focus{outline:none;border-color:#18c99b;box-shadow:0 0 0 3px rgba(24,201,155,.14)}
.check-row{display:flex;gap:8px;align-items:center;color:#c7d5e8;margin:10px 0}.check-row input{width:auto}
.record-list{display:grid;gap:10px;margin-top:10px}.record-row{display:grid;grid-template-columns:80px 72px 72px 1fr 80px 40px;gap:8px;align-items:center}
.record-row input,.record-row select{background:#071018;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
.icon-btn{width:36px;height:36px;padding:0;display:grid;place-items:center}
.section-title{margin:20px 0 8px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.final-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
.final-table{margin-top:10px;table-layout:fixed}.final-table th,.final-table td{padding:8px 10px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}
.final-table td:nth-child(2){font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ok)}
.final-table .col-region{width:42px}.final-table .col-ip{width:132px}.final-table .col-domain{width:150px}.final-table .col-ping{width:66px}.final-table .col-loss{width:58px}
.final-table .col-hint,.final-table .col-entry{width:auto}
.table-tools{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:10px 0 -6px}
.segments{display:flex;gap:6px;flex-wrap:wrap}.seg{padding:6px 10px;border-radius:999px;background:#101722;border:1px solid var(--line);color:var(--muted);cursor:pointer}.seg.active{color:#d8fff0;background:#123325;border-color:#236a4b}
table{width:100%;border-collapse:collapse;margin-top:16px;background:var(--panel);border:1px solid var(--line)}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;font-variant-numeric:tabular-nums}
th{color:var(--muted);font-size:12px}th.sortable{cursor:pointer;user-select:none}th.sortable:hover{color:var(--text)}th.sortable.active{color:var(--ok)}tr.best td{color:var(--ok)}tr.bad td{color:var(--bad)}tr.hot td{color:var(--ok)}
@media(max-width:800px){.grid,.settings,.form-grid,.final-grid{grid-template-columns:1fr}.record-row{grid-template-columns:1fr 1fr}.record-row input:nth-child(3){grid-column:1/-1}main{padding:18px}th:nth-child(4),td:nth-child(4),th:nth-child(8),td:nth-child(8){display:none}}
</style>
</head>
<body><main>
<div class="top"><h1>CF Anycast Router</h1><div class="top-actions"><button class="ghost" onclick="openSettings()">管理设置</button><button id="stopBtn" class="danger" onclick="setAutoScan('stop')">停止自动探测</button><button id="startBtn" class="primary" onclick="setAutoScan('start')" disabled>恢复自动探测</button><span id="mode" class="hint">正在加载状态</span></div></div>
<section class="grid">
<div class="panel"><div class="k">当前入口</div><div id="current" class="v">-</div></div>
<div class="panel"><div class="k">最优候选</div><div id="best" class="v">-</div></div>
<div class="panel"><div class="k">本地路由地区</div><div id="pop" class="v">-</div></div>
<div class="panel"><div class="k">切换决策</div><div id="decision" class="v">-</div></div>
</section>
<section class="settings">
<div class="panel">
<div class="k">种子池输入</div>
<textarea id="seedInput" class="seedbox" spellcheck="false" placeholder="104.20.23.137&#10;104.20.0.0/16&#10;104.26.x.x&#10;172.67.73.x"></textarea>
<div class="actions">
<button class="primary" onclick="saveSeeds()">保存种子</button>
<button onclick="scanNow()">随机抽样扫描</button>
</div>
<div id="seedMsg" class="small">粘贴 IP、CIDR 或通配段，每行一个。</div>
<div class="lookup-row">
<input id="lookupIP" placeholder="输入 IP，例如 104.20.23.137">
<button onclick="lookupIPRange()">查询并验证段</button>
</div>
<div id="lookupMsg" class="small">查询会先找 BGP 前缀，再抽样验证；只有本地路由地区一致的段才会保留。</div>
</div>
<div class="panel">
<div class="k">扫描模型</div>
<div class="v">种子 -> 学习段 -> 热点</div>
<div class="small">CIDR 会先按 /24 抽样，再按步进 IP 抽样。地区只根据本机 traceroute/mtr 的路由跳点判断；Cloudflare Colo 仅作为参考显示。</div>
</div>
</section>
<div id="settingsModal" class="modal" onclick="if(event.target===this)closeSettings()">
<div class="modal-card">
<div class="modal-head"><div><h2>管理设置</h2><div class="hint">修改后会写入配置文件，下一轮检测使用新设置。</div></div><button class="icon-btn" onclick="closeSettings()">×</button></div>
<div class="tabs"><div class="tab active" data-tab="basic" onclick="switchSettingsTab('basic')">基础设置</div><div class="tab" data-tab="speed" onclick="switchSettingsTab('speed')">官方测速</div><div class="tab" data-tab="dns" onclick="switchSettingsTab('dns')">地区解析</div><div class="tab" data-tab="agent" onclick="switchSettingsTab('agent')">Agent 安装</div></div>
<section id="settings-basic" class="settings-pane">
<div class="form-grid">
<div class="field"><label>探测源说明</label><input id="setProbeSource" placeholder="宁波联通"></div>
<div class="field"><label>运营商策略</label><select id="setCarrier"><option value="auto">自动识别</option><option value="cu">联通</option><option value="ct">电信</option><option value="cm">移动</option><option value="unknown">未知</option></select></div>
<div class="field"><label>检测间隔（秒）</label><input id="setInterval" type="number" min="10" step="10"></div>
<div class="field"><label>本轮路由追踪预算</label><input id="setTraceBudget" type="number" min="1" step="1"></div>
</div>
</section>
<section id="settings-speed" class="settings-pane" style="display:none">
<label class="check-row"><input id="setSpeedEnabled" type="checkbox"> 启用 Cloudflare 官方下载测速</label>
<div class="form-grid">
<div class="field"><label>测速域名</label><input id="setSpeedHost" placeholder="speed.cloudflare.com"></div>
<div class="field"><label>测速路径</label><input id="setSpeedPath" placeholder="/__down"></div>
<div class="field"><label>每次下载字节数</label><input id="setSpeedBytes" type="number" min="4096" max="4194304" step="4096"></div>
<div class="field"><label>短名单数量</label><input id="setSpeedTopN" type="number" min="1" max="20" step="1"></div>
</div>
<div class="small">先按基础延迟、丢包、抖动和路由评分筛出短名单，再直连这些 IP 的 443 端口，SNI/Host 使用 speed.cloudflare.com，请求 /__down?bytes=N。</div>
</section>
<section id="settings-dns" class="settings-pane" style="display:none">
<label class="check-row"><input id="setDnsEnabled" type="checkbox"> 启用 Cloudflare DNS 动态解析</label>
<div class="form-grid">
<div class="field"><label>Zone Name</label><input id="setZoneName" placeholder="yeque.top"></div>
<div class="field"><label>Zone ID</label><input id="setZoneID" placeholder="可选，填了更快"></div>
<div class="field"><label>Token 环境变量</label><input id="setTokenEnv" placeholder="CLOUDFLARE_API_TOKEN"></div>
<div class="field"><label>TTL</label><input id="setTTL" type="number" min="60" step="60"></div>
</div>
<label class="check-row"><input id="setProxied" type="checkbox"> 开启 Cloudflare 代理（当前建议关闭）</label>
<div class="field"><label>按运营商和地区解析域名</label><div id="recordList" class="record-list"></div></div>
<button onclick="addRecordRow()">添加地区记录</button>
<div class="small">记录类型已支持 A / AAAA；当前扫描器主要产出 IPv4，IPv6 候选接入后可直接添加 AAAA 记录。</div>
</section>
<section id="settings-agent" class="settings-pane" style="display:none">
<div class="form-grid">
<div class="field"><label>母鸡地址</label><input id="agentServerURL" oninput="updateAgentInstallCommand()"></div>
<div class="field"><label>Agent ID</label><input id="agentInstallID" placeholder="hk-vps-01" oninput="updateAgentInstallCommand()"></div>
<div class="field"><label>运营商</label><select id="agentInstallCarrier" onchange="updateAgentInstallCommand()"><option value="auto">自动识别</option><option value="cu">联通</option><option value="ct">电信</option><option value="cm">移动</option><option value="unknown">未知</option></select></div>
<div class="field"><label>共享 Token</label><input id="agentInstallToken" placeholder="可选" oninput="updateAgentInstallCommand()"></div>
</div>
<div class="field"><label>一键安装命令</label><textarea id="agentInstallCommand" class="seedbox" readonly spellcheck="false"></textarea></div>
<div class="actions"><button class="primary" onclick="copyAgentInstallCommand()">复制命令</button><button onclick="resetAgentInstallCommand()">恢复默认</button></div>
<div id="agentInstallMsg" class="small">在 VPS 上用 root 或 sudo 执行；安装后会创建 systemd 服务并主动上报。</div>
</section>
<div id="settingsMsg" class="small"></div>
<div class="modal-actions"><button onclick="closeSettings()">取消</button><button class="primary" onclick="saveSettings()">保存设置</button></div>
</div>
</div>
<div class="section-title">最终区</div>
<section class="final-grid">
<div class="panel"><div class="k">DNS 解析最终区</div><div class="small">按 Agent 运营商和本地路由地区 route_region 选择，用于 cu-cf-hk / cu-cf-us 这类解析。</div>
<table class="final-table"><thead><tr><th class="col-region">地区</th><th class="col-ip">最终 IP</th><th class="col-domain">解析域名</th><th class="col-ping">Ping</th><th class="col-hint">路由依据</th></tr></thead><tbody id="routeFinalRows"><tr><td colspan="5">等待扫描数据</td></tr></tbody></table>
</div>
<div class="panel"><div class="k">CF 官方测速最终区</div><div class="small">按 Cloudflare 官方 __down 下载结果选择，用于观察服务面下载表现。</div>
<table class="final-table"><thead><tr><th class="col-region">地区</th><th class="col-ip">最终 IP</th><th class="col-entry">测速源</th><th class="col-ping">耗时</th><th class="col-loss">Mbps</th></tr></thead><tbody id="speedFinalRows"><tr><td colspan="5">等待扫描数据</td></tr></tbody></table>
</div>
</section>
<div class="section-title">探针上报</div>
<section class="panel">
<div class="k">Agent 列表</div>
<table class="final-table"><thead><tr><th>Agent</th><th>探测源</th><th>运营商</th><th>最后上报</th><th>候选</th><th>最优 IP</th><th>地区</th><th>得分</th></tr></thead><tbody id="agentRows"><tr><td colspan="8">等待 agent 上报</td></tr></tbody></table>
</section>
<div class="section-title">数据区 / 测试 IP 原始数据</div>
<div class="table-tools"><div class="segments" id="regionFilters">
<button class="seg active" data-region="ALL">全部</button>
<button class="seg" data-region="HK">HK</button>
<button class="seg" data-region="US">US</button>
<button class="seg" data-region="JP">JP</button>
<button class="seg" data-region="SG">SG</button>
<button class="seg" data-region="unknown">unknown</button>
</div><div id="filterInfo" class="hint">显示全部地区</div></div>
<table><thead><tr>
<th class="sortable" data-sort="ip">IP</th>
<th class="sortable" data-sort="stage">阶段</th>
<th class="sortable" data-sort="segment">段</th>
<th class="sortable" data-sort="region">判定地区</th>
<th class="sortable" data-sort="hint">判断依据</th>
<th class="sortable" data-sort="cf_speed">CF 官方测速</th>
<th class="sortable" data-sort="cf_mbps">估算 Mbps</th>
<th class="sortable" data-sort="colo">CF Colo</th>
<th class="sortable" data-sort="ping">Ping 延迟</th>
<th class="sortable" data-sort="pingloss">Ping 丢包</th>
<th class="sortable" data-sort="rtt">TLS 延迟</th>
<th class="sortable" data-sort="jitter">抖动</th>
<th class="sortable" data-sort="loss">TLS 丢包</th>
<th class="sortable" data-sort="spike">尖刺</th>
<th class="sortable active" data-sort="score">得分</th>
</tr></thead><tbody id="rows"></tbody></table>
</main>
<script>
function pct(v){ return (((v||0)*100).toFixed(0))+'%'; }
function fmt(v){ return Number.isFinite(v)?v.toFixed(1):'-'; }
let sortState={key:'score',dir:'asc'};
let regionFilter='ALL';
let seedDirty=false;
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
   case 'region': return c.region||c.route_region||'';
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
function sortCandidates(candidates){
 const arr=[...(candidates||[])].filter(c=>matchesRegion(c));
 arr.sort((a,b)=>{
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
function candidateRegion(c){ return c.region||c.route_region||'unknown'; }
function matchesRegion(c){
 if(regionFilter==='ALL'){ return true; }
 const region=candidateRegion(c);
 if(regionFilter==='unknown'){ return !region||region==='unknown'||region==='-'; }
 return region===regionFilter;
}
function filterSummary(candidates){
 const total=(candidates||[]).length;
 const shown=(candidates||[]).filter(c=>matchesRegion(c)).length;
 filterInfo.textContent=regionFilter==='ALL'?'显示全部地区，共 '+total+' 条':'仅显示 '+regionFilter+'，'+shown+' / '+total+' 条';
}
function attr(v){ return String(v??'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }
function rowAttrs(values){
 return Object.entries(values).map(([k,v])=>' data-'+k+'="'+attr(v)+'"').join('');
}
function isHealthy(c){ return c&&!c.error&&!c.quarantined&&Number.isFinite(c.score); }
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
 (candidates||[]).forEach(c=>{ const v=String(c[field]||'').toUpperCase(); if(v&&v!=='UNKNOWN'&&v!=='-'){ set.add(v); } });
 return [...set].sort((a,b)=>{
   const order={HK:1,US:2,JP:3,SG:4,EU:5};
   return (order[a]||99)-(order[b]||99)||a.localeCompare(b);
 });
}
function bestRouteForRegion(candidates,region){
 let best=null, bestScore=Number.POSITIVE_INFINITY;
 for(const c of candidates||[]){
   if(!isHealthy(c)||String(c.route_region||'').toUpperCase()!==region){ continue; }
   const score=routeDnsScore(c);
   if(score<bestScore){ best=c; bestScore=score; }
 }
 return best;
}
function bestSpeedForRegion(candidates,region){
 let best=null, bestScore=Number.POSITIVE_INFINITY;
 for(const c of candidates||[]){
   if(!isHealthy(c)||String(c.route_region||c.region||'').toUpperCase()!==region||!(c.cf_speed_rtt_ms>0)){ continue; }
   const score=(c.cf_speed_rtt_ms||9999)+(c.cf_speed_jitter_ms||0)*0.5+(c.cf_speed_loss_rate||0)*800;
   if(score<bestScore){ best=c; bestScore=score; }
 }
 return best;
}
function renderFinalAreas(candidates,settings,carrier){
 carrier=String(carrier||settings?.carrier||'unknown').toLowerCase();
 const routeRows=finalRegions(settings,candidates,'route_region',carrier).map(region=>{
   const c=bestRouteForRegion(candidates,region);
   if(!c){ return '<tr><td>'+region+'</td><td>-</td><td>'+domainForRegion(settings,carrier,region)+'</td><td>-</td><td>暂无 '+carrier.toUpperCase()+' '+region+' 路由候选</td></tr>'; }
   const hint=[c.route_hint_ip,c.route_city,c.route_isp].filter(Boolean).join(' ')||'-';
   return '<tr><td>'+region+'</td><td>'+c.ip+'</td><td>'+domainForRegion(settings,carrier,region)+'</td><td>'+fmt(c.ping_rtt_ms||0)+'</td><td>'+hint+'</td></tr>';
 }).join('');
 routeFinalRows.innerHTML=routeRows||'<tr><td colspan="5">等待扫描数据</td></tr>';
 const speedRows=finalRegions(settings,candidates,'route_region',carrier).map(region=>{
   const c=bestSpeedForRegion(candidates,region);
   if(!c){ return '<tr><td>'+region+'</td><td>-</td><td>speed.cloudflare.com</td><td>-</td><td>暂无官方测速结果</td></tr>'; }
   return '<tr><td>'+region+'</td><td>'+c.ip+'</td><td>__down</td><td>'+fmt(c.cf_speed_rtt_ms||0)+'</td><td>'+fmt(c.cf_speed_mbps||0)+'</td></tr>';
 }).join('');
 speedFinalRows.innerHTML=speedRows||'<tr><td colspan="5">等待扫描数据</td></tr>';
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
 const klass=c.error?'bad':(last&&last.best&&last.best.ip===c.ip?'best':'');
 const skipped=Boolean(c.error||c.quarantined);
 const score=skipped?'跳过':(Number.isFinite(c.score)?c.score.toFixed(1):'跳过');
 const colo=(c.observed_colo&&c.observed_pop&&c.observed_colo!==c.observed_pop)?(c.observed_colo+' / '+c.observed_pop):(c.observed_colo||c.observed_pop||'-');
 const region=(c.region||c.route_region||'-');
 const routeRegion=(c.route_region||'-');
 const hint=[c.route_hint_ip,c.route_city,c.route_isp].filter(Boolean).join(' ');
 const source=regionSourceLabel(c.region_source);
 const speedText=c.cf_speed_rtt_ms>0?(fmt(c.cf_speed_rtt_ms)+'ms'):(c.cf_speed_error?'失败':'-');
 const speedMbps=c.cf_speed_mbps>0?fmt(c.cf_speed_mbps):'-';
 const reason=(c.region_source==='cf-colo-tls')
   ? (source+'：'+colo+'，TLS '+fmt(c.avg_rtt_ms||0)+'ms；ICMP '+routeRegion+(hint?'，'+hint:''))
   : ((source&&source!=='-'?source+'：':'')+(hint||decisionLabel(c.route_error||c.error)||'-'));
 const pingText=skipped?'-':(c.ping_rtt_ms>0?fmt(c.ping_rtt_ms):(c.ping_error?'失败':'-'));
 const attrs=rowAttrs({ip:ipValue(c.ip),stage:stageLabel(c.stage),segment:c.segment||'',region,hint:reason,speedok:(c.cf_speed_rtt_ms>0&&!c.cf_speed_error)?1:0,cf_speed:skipped?999999:(c.cf_speed_rtt_ms||999999),cf_mbps:skipped?0:(c.cf_speed_mbps||0),colo,ping:skipped?999999:(c.ping_rtt_ms>0?c.ping_rtt_ms:999999),pingloss:skipped?999999:(c.ping_loss_rate||0),rtt:skipped?999999:(c.avg_rtt_ms||0),jitter:skipped?999999:(c.jitter_ms||0),loss:skipped?999999:(c.loss_rate||0),spike:skipped?999999:(c.spike_rate||0),score:skipped?999999:(Number.isFinite(c.score)?c.score:999999)});
 return '<tr class="'+klass+'"'+attrs+' title="'+attr(c.ping_error||c.cf_speed_error||'')+'"><td>'+c.ip+'</td><td>'+stageLabel(c.stage)+'</td><td>'+(c.segment||'-')+'</td><td>'+region+'</td><td>'+reason+'</td><td>'+speedText+'</td><td>'+speedMbps+'</td><td>'+colo+'</td><td>'+pingText+'</td><td>'+(skipped?'-':pct(c.ping_loss_rate))+'</td><td>'+(skipped?'-':fmt(c.avg_rtt_ms||0))+'</td><td>'+(skipped?'-':fmt(c.jitter_ms||0))+'</td><td>'+(skipped?'-':pct(c.loss_rate))+'</td><td>'+(skipped?'-':pct(c.spike_rate))+'</td><td>'+score+'</td></tr>';
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
function switchSettingsTab(tab){
 document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===tab));
 document.querySelectorAll('.settings-pane').forEach(x=>x.style.display=x.id==='settings-'+tab?'block':'none');
}
async function openSettings(){
 settingsModal.classList.add('open');
 settingsMsg.textContent='正在加载设置...';
 const res=await fetch('/api/settings?ts='+Date.now()).then(r=>r.json()).catch(e=>({error:e.message}));
 if(res.error){ settingsMsg.textContent=res.error; return; }
 settingsCache=res;
 fillSettings(res);
 settingsMsg.textContent='';
}
function closeSettings(){ settingsModal.classList.remove('open'); }
function shellQuote(v){
 v=String(v||'');
 if(/^[A-Za-z0-9_./:@-]+$/.test(v)){ return v; }
 return "'"+v.replace(/'/g,"'\\''")+"'";
}
function defaultAgentServerURL(){
 return window.location.origin||'http://10.0.0.234:19199';
}
function resetAgentInstallCommand(){
 agentServerURL.value=defaultAgentServerURL();
 agentInstallID.value='vps-01';
 agentInstallCarrier.value='auto';
 agentInstallToken.value='';
 updateAgentInstallCommand();
}
function updateAgentInstallCommand(){
 const server=(agentServerURL.value||defaultAgentServerURL()).trim().replace(/\/+$/,'');
 const id=(agentInstallID.value||'vps-01').trim();
 const carrier=(agentInstallCarrier.value||'auto').trim();
 const token=(agentInstallToken.value||'').trim();
 const fallbackInstall='https://raw.githubusercontent.com/kuaichu/CFAnycastRouter/main/install.sh';
 const parts=[
   '(curl -fsSL '+shellQuote(server+'/install.sh')+' || curl -fsSL '+shellQuote(fallbackInstall)+')',
   '| sudo bash -s --',
   '--server '+shellQuote(server),
   '--id '+shellQuote(id),
   '--carrier '+shellQuote(carrier)
 ];
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
 setInterval.value=s.check_interval_seconds||300;
 setTraceBudget.value=s.max_route_traces_per_cycle||96;
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
   addRecordRow({enabled:true,carrier:'cu',region:'HK',type:'A',domain:'cu-cf-hk.ziher.eu.org'});
   addRecordRow({enabled:true,carrier:'cu',region:'US',type:'A',domain:'cu-cf-us.ziher.eu.org'});
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
   check_interval_seconds:Number(setInterval.value)||300,
   max_route_traces_per_cycle:Number(setTraceBudget.value)||96,
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
function renderAgents(payload){
 const list=(payload&&payload.agents)||[];
 if(!list.length){
   agentRows.innerHTML='<tr><td colspan="8">等待 agent 上报</td></tr>';
   return;
 }
 agentRows.innerHTML=list.map(a=>{
   const best=a.best||{};
   const seen=a.last_seen?new Date(a.last_seen).toLocaleString():'-';
   const id=[a.agent_id,a.hostname&&a.hostname!==a.agent_id?a.hostname:''].filter(Boolean).join(' / ');
   return '<tr><td>'+id+'</td><td>'+(a.probe_source||'-')+'</td><td>'+(a.carrier||'-')+'</td><td>'+seen+'</td><td>'+(a.candidate_count||0)+'</td><td>'+(best.ip||'-')+'</td><td>'+(best.region||best.route_region||'-')+'</td><td>'+(Number.isFinite(best.score)?best.score.toFixed(1):'-')+'</td></tr>';
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
 renderAgents(agents);
 if(settings&&!settings.error){ settingsCache=settings; }
 if(control&&!control.error){ controlCache=control; applyControl(control); }
 if(seeds&&seeds.text&&!seedDirty&&document.activeElement!==seedInput){ seedInput.value=seeds.text; }
if(last&&last.candidates){
   mode.textContent=controlModeText(controlCache,'实时探测');
   current.textContent=last.current_ip||state?.current_ip||'-';
   best.textContent=last.best?.ip||'-';
   pop.textContent=last.best?.region||last.best?.route_region||'-';
   decision.textContent=decisionLabel(last.decision);
   renderFinalAreas(last.candidates||[],settingsCache,last.carrier);
   filterSummary(last.candidates||[]);
   rows.innerHTML=sortCandidates(last.candidates||[]).map(c=>candidateRow(c,last)).join('');
   sortRenderedRows();
   return;
 }
 mode.textContent=controlModeText(controlCache,'状态快照');
 current.textContent=state?.current_ip||'-';
 best.textContent='-';
 pop.textContent='-';
 decision.textContent=decisionLabel(state?.last_decision)||'等待首次探测';
 renderFinalAreas([],settingsCache,settingsCache?.carrier);
 if(!fullStateCache){
   fullStateCache=await fetch('/api/state?full=1&ts='+Date.now()).then(r=>r.json()).catch(()=>null);
 }
 rows.innerHTML=stateRows(fullStateCache||{})||'<tr><td colspan="15">暂无扫描状态。请运行 cf-router once config.yaml 或 cf-router run config.yaml。</td></tr>';
 sortRenderedRows();
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
refreshLoop();
seedInput.addEventListener('input',()=>{ seedDirty=true; });
document.querySelectorAll('#regionFilters .seg').forEach(btn=>{
 btn.addEventListener('click',()=>{
   regionFilter=btn.dataset.region;
   document.querySelectorAll('#regionFilters .seg').forEach(x=>x.classList.toggle('active',x===btn));
   refresh();
 });
});
document.querySelectorAll('th.sortable').forEach(th=>{
 th.addEventListener('click',()=>{
   const key=th.dataset.sort;
   if(sortState.key===key){ sortState.dir=sortState.dir==='asc'?'desc':'asc'; }
   else { sortState={key,dir:['cf_speed','cf_mbps','ping','pingloss','rtt','jitter','loss','spike','score'].includes(key)?'asc':'asc'}; }
   sortRenderedRows();
 });
});
</script>
</body></html>`))
