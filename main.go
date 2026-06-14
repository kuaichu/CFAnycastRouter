package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"cf-anycast-router/internal/config"
	"cf-anycast-router/internal/dashboard"
	"cf-anycast-router/internal/discover"
	"cf-anycast-router/internal/history"
	"cf-anycast-router/internal/output"
	"cf-anycast-router/internal/router"
)

func main() {
	log.SetFlags(log.Ltime)
	cmd, cfgPath := parseArgs(os.Args[1:])
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	st, err := history.Load(cfg.StatePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}
	if err := st.Save(cfg.StatePath); err != nil {
		log.Fatalf("save state: %v", err)
	}
	rt := router.New(cfg, st)

	switch cmd {
	case "run":
		runLoop(cfgPath, cfg, st, rt)
	case "once", "switch":
		result, err := rt.Cycle()
		if err != nil {
			log.Fatalf("cycle: %v", err)
		}
		mustSave(st, cfg.StatePath)
		printResult(result)
	case "probe", "trace", "score":
		candidates := rt.Evaluate()
		mustSave(st, cfg.StatePath)
		printCandidates(candidates)
	case "discover":
		printDiscovery(cfg, st)
	case "render":
		if err := renderCurrent(cfg, st); err != nil {
			log.Fatalf("render: %v", err)
		}
	case "history":
		writeJSON(st)
	case "dashboard":
		pausePath := autoScanPausePath(cfg)
		control := newRunControl(loadAutoScanPaused(pausePath))
		var d *dashboard.Server
		d = dashboard.New(cfg.WebPort, cfg.StatePath, cfgPath, scanCallback(rt, st, cfg, func() {
			d.BeginScan(st.CurrentIP, cfg.Carrier)
		}, func(result *router.CycleResult) {
			d.SetLast(result)
		}), seedsCallback(cfg), lookupCallback(cfgPath, cfg, rt, st), settingsCallback(cfg), controlCallback(control, pausePath))
		rt.SetProgress(func(candidate router.Candidate) {
			d.UpsertCandidate(candidate)
		})
		d.Start()
		waitForInterrupt()
	default:
		usage()
		os.Exit(2)
	}
}

func parseArgs(args []string) (cmd string, cfgPath string) {
	cmd = "run"
	cfgPath = "config.yaml"
	if len(args) > 0 {
		switch args[0] {
		case "run", "once", "switch", "probe", "trace", "score", "discover", "render", "history", "dashboard":
			cmd = args[0]
			if len(args) > 1 {
				cfgPath = args[1]
			}
		default:
			cfgPath = args[0]
		}
	}
	return cmd, cfgPath
}

func runLoop(cfgPath string, cfg *config.Config, st *history.State, rt *router.Router) {
	pausePath := autoScanPausePath(cfg)
	control := newRunControl(loadAutoScanPaused(pausePath))
	exitCh := make(chan struct{})
	var d *dashboard.Server
	d = dashboard.New(cfg.WebPort, cfg.StatePath, cfgPath, scanCallback(rt, st, cfg, func() {
		d.BeginScan(st.CurrentIP, cfg.Carrier)
	}, func(result *router.CycleResult) {
		d.SetLast(result)
	}), seedsCallback(cfg), lookupCallback(cfgPath, cfg, rt, st), settingsCallback(cfg), controlCallback(control, pausePath))
	rt.SetProgress(func(candidate router.Candidate) {
		d.UpsertCandidate(candidate)
	})
	d.Start()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		log.Printf("received interrupt, exiting after current cycle")
		requestExit(exitCh)
	}()

	for {
		if !waitIfPaused(control, exitCh) {
			return
		}
		d.BeginScan(st.CurrentIP, cfg.Carrier)
		result, err := rt.Cycle()
		if err != nil {
			d.EndScan()
			log.Printf("[error] cycle failed: %v", err)
		} else {
			d.SetLast(result)
			log.Printf("[decision] %s", result.Decision)
			if result.Best != nil {
				pingNote := ""
				if result.Best.PingError != "" {
					pingNote = " ping_error=" + result.Best.PingError
				}
				log.Printf("[best] %s route=%s cf_colo=%s/%s score=%.2f ping=%.1fms ping_loss=%.1f%% tls=%.1fms tls_loss=%.1f%% spike=%.1f%%%s",
					result.Best.IP, result.Best.Region, result.Best.ObservedColo, result.Best.ObservedPOP, result.Best.Score, result.Best.PingRTTMs, result.Best.PingLossRate*100, result.Best.AvgRTTMs, result.Best.LossRate*100, result.Best.SpikeRate*100, pingNote)
			}
			for _, item := range result.Outputs {
				if strings.HasPrefix(item, "cloudflare_dns ") {
					log.Printf("[dns] %s", item)
				}
			}
			mustSave(st, cfg.StatePath)
		}
		if !waitForNextCycle(cfg.CheckInterval, control, exitCh) {
			return
		}
	}
}

type runControl struct {
	mu       sync.RWMutex
	paused   bool
	pauseCh  chan struct{}
	resumeCh chan struct{}
}

func newRunControl(paused bool) *runControl {
	return &runControl{
		paused:   paused,
		pauseCh:  make(chan struct{}, 1),
		resumeCh: make(chan struct{}, 1),
	}
}

func controlCallback(control *runControl, pausePath string) dashboard.ControlFunc {
	return func(action string) (dashboard.ControlStatus, error) {
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "", "status":
		case "stop", "pause":
			control.stop()
			if err := setAutoScanPaused(pausePath, true); err != nil {
				return control.status(""), err
			}
			log.Printf("[control] automatic scanning paused from dashboard")
		case "start", "resume":
			control.start()
			if err := setAutoScanPaused(pausePath, false); err != nil {
				return control.status(""), err
			}
			log.Printf("[control] automatic scanning resumed from dashboard")
		default:
			return control.status(""), fmt.Errorf("unknown control action %q", action)
		}
		return control.status(""), nil
	}
}

func autoScanPausePath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.StatePath), "auto-scan-paused")
}

func loadAutoScanPaused(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func setAutoScanPaused(path string, paused bool) error {
	if paused {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("paused\n"), 0644)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *runControl) stop() {
	c.mu.Lock()
	changed := !c.paused
	c.paused = true
	c.mu.Unlock()
	if changed {
		drain(c.resumeCh)
		notify(c.pauseCh)
	}
}

func (c *runControl) start() {
	c.mu.Lock()
	changed := c.paused
	c.paused = false
	c.mu.Unlock()
	if changed {
		drain(c.pauseCh)
		notify(c.resumeCh)
	}
}

func (c *runControl) isPaused() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.paused
}

func (c *runControl) status(message string) dashboard.ControlStatus {
	if message == "" {
		if c.isPaused() {
			message = "automatic scanning is paused"
		} else {
			message = "automatic scanning is running"
		}
	}
	return dashboard.ControlStatus{Paused: c.isPaused(), Message: message}
}

func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func drain(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func requestExit(exitCh chan<- struct{}) {
	notify(exitCh)
}

func waitIfPaused(control *runControl, exitCh <-chan struct{}) bool {
	if !control.isPaused() {
		return true
	}
	log.Printf("[paused] automatic scanning is paused")
	for control.isPaused() {
		select {
		case <-control.resumeCh:
		case <-exitCh:
			log.Printf("exit requested, exiting")
			return false
		}
	}
	log.Printf("[control] automatic scanning resumed")
	return true
}

func waitForNextCycle(interval time.Duration, control *runControl, exitCh <-chan struct{}) bool {
	if interval <= 0 {
		interval = time.Second
	}
	log.Printf("[sleep] next scan in %s", interval)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-control.pauseCh:
		return waitIfPaused(control, exitCh)
	case <-exitCh:
		log.Printf("exit requested, exiting")
		return false
	}
}

func scanCallback(rt *router.Router, st *history.State, cfg *config.Config, before func(), after func(*router.CycleResult)) dashboard.ScanFunc {
	return func() (*router.CycleResult, error) {
		if before != nil {
			before()
		}
		result, err := rt.Cycle()
		if err != nil {
			return result, err
		}
		if err := st.Save(cfg.StatePath); err != nil {
			return result, err
		}
		if after != nil {
			after(result)
		}
		return result, nil
	}
}

func seedsCallback(cfg *config.Config) dashboard.SeedsFunc {
	return func(ips, cidrs []string) error {
		cfg.SeedIPs = ips
		cfg.SeedCIDRs = cidrs
		return nil
	}
}

func settingsCallback(cfg *config.Config) dashboard.SettingsFunc {
	return func(next *config.Config) error {
		cfg.ProbeSource = next.ProbeSource
		cfg.Carrier = next.Carrier
		cfg.CheckIntervalSec = next.CheckIntervalSec
		cfg.CheckInterval = next.CheckInterval
		cfg.MaxRouteTracesPerCycle = next.MaxRouteTracesPerCycle
		cfg.CloudflareDNS = next.CloudflareDNS
		cfg.AnchorProbes = next.AnchorProbes
		return nil
	}
}

func lookupCallback(cfgPath string, cfg *config.Config, rt *router.Router, st *history.State) dashboard.LookupFunc {
	return func(ip string) (*router.RangeValidation, error) {
		result, err := rt.ValidateIPRange(ip, cfg.MaxSamplesPerSegmentPerCycle, cfg.PromotePOPProbability)
		if err != nil {
			return nil, err
		}
		if result.AcceptedCIDR != "" {
			ips, cidrs, err := config.MergeSeeds(cfgPath, []string{result.InputIP}, []string{result.AcceptedCIDR})
			if err != nil {
				return nil, err
			}
			cfg.SeedIPs = ips
			cfg.SeedCIDRs = cidrs
		}
		if err := st.Save(cfg.StatePath); err != nil {
			return nil, err
		}
		return result, nil
	}
}

func printResult(result *router.CycleResult) {
	printCandidates(result.Candidates)
	fmt.Println()
	fmt.Printf("decision: %s\n", result.Decision)
	if len(result.Outputs) > 0 {
		fmt.Printf("outputs: %s\n", strings.Join(result.Outputs, ", "))
	}
}

func printCandidates(candidates []router.Candidate) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tSTAGE\tSEGMENT\tROUTE\tHINT\tCF_COLO\tPING_RTT\tPING_LOSS\tTLS_RTT\tJITTER\tTLS_LOSS\tSPIKE\tSCORE\tNOTE")
	for _, c := range candidates {
		note := c.Error
		if c.Quarantined {
			note = "quarantined"
		}
		score := fmt.Sprintf("%.1f", c.Score)
		if c.Error != "" {
			score = "-"
		}
		cfColo := c.ObservedColo
		if cfColo != "" && c.ObservedPOP != "" && cfColo != c.ObservedPOP {
			cfColo += "/" + c.ObservedPOP
		}
		hint := c.RouteHintIP
		if c.RouteCity != "" {
			hint += " " + c.RouteCity
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%.0f%%\t%.1f\t%.1f\t%.0f%%\t%.0f%%\t%s\t%s\n",
			c.IP, c.Stage, c.Segment, emptyDash(c.Region), emptyDash(hint), emptyDash(cfColo), c.PingRTTMs, c.PingLossRate*100, c.AvgRTTMs, c.JitterMs, c.LossRate*100, c.SpikeRate*100, score, note)
	}
	_ = tw.Flush()
}

func printDiscovery(cfg *config.Config, st *history.State) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STAGE\tCARRIER\tSEGMENT\tIP/INFO\tWEIGHT")
	for _, target := range discover.Targets(cfg, st) {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%.1f\n", target.Stage, target.Carrier, target.Segment, target.IP, target.Weight)
	}
	for _, seg := range st.Segments {
		status := "learning"
		if seg.Promoted {
			status = "learned"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\tpreferred=%.0f%% samples=%d hot=%d\t%.1f\n", status, seg.Carrier, seg.CIDR, seg.PreferredRate*100, seg.Samples, len(seg.HotIPs), seg.Weight)
	}
	_ = tw.Flush()
}

func renderCurrent(cfg *config.Config, st *history.State) error {
	if st.CurrentIP == "" {
		return fmt.Errorf("no current IP in state; run `cf-router once` first")
	}
	pop := ""
	if p := st.Profiles[st.CurrentIP]; p != nil {
		pop = p.LastPOPByCarrier[cfg.Carrier]
	}
	written, err := output.RenderAll(cfg.Outputs, output.ActiveRoute{
		IP:        st.CurrentIP,
		Domain:    cfg.TraceHost,
		Name:      "cf-anycast-active",
		Port:      cfg.ProbePort,
		SNI:       cfg.TraceHost,
		Score:     st.CurrentScore,
		Carrier:   cfg.Carrier,
		POP:       pop,
		TraceHost: cfg.TraceHost,
	})
	if err != nil {
		return err
	}
	fmt.Printf("rendered: %s\n", strings.Join(written, ", "))
	return nil
}

func mustSave(st *history.State, path string) {
	if err := st.Save(path); err != nil {
		log.Fatalf("save state: %v", err)
	}
}

func waitForInterrupt() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	<-sigCh
	log.Printf("received interrupt, exiting")
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func emptyDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func usage() {
	fmt.Println(`CF Anycast Router

Usage:
  cf-router [run|once|switch|discover|probe|trace|score|render|history|dashboard] [config.yaml]

Commands:
  run        continuous local-agent routing loop
  once       run one probe/score/switch cycle
  probe      evaluate candidates without switching outputs
  trace      alias of probe, includes Cloudflare POP trace
  score      alias of probe, shows final score
  switch     alias of once
  discover   list configured carrier + POP pools
  render     render outputs from saved active route
  history    dump state and POP drift history
  dashboard  serve the local dashboard only`)
}
