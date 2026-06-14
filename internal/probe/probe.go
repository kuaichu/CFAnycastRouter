package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	IP        string
	Attempts  int
	Successes int
	AvgRTTMs  float64
	JitterMs  float64
	LossRate  float64
	SpikeRate float64
	LastError string
}

func TCP(ip string, port int, attempts int, timeout time.Duration, spikeThresholdMs, spikeMultiplier float64) Result {
	return run(ip, attempts, func() (time.Duration, error) {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
		if err != nil {
			return 0, err
		}
		_ = conn.Close()
		return time.Since(start), nil
	}, spikeThresholdMs, spikeMultiplier)
}

func TLS(ip, serverName string, port int, attempts int, timeout time.Duration, spikeThresholdMs, spikeMultiplier float64) Result {
	return run(ip, attempts, func() (time.Duration, error) {
		dialer := &net.Dialer{Timeout: timeout}
		start := time.Now()
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return 0, err
		}
		_ = conn.Close()
		return time.Since(start), nil
	}, spikeThresholdMs, spikeMultiplier)
}

func HTTPS(ip, host, path string, port int, attempts int, timeout time.Duration, spikeThresholdMs, spikeMultiplier float64) Result {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return run(ip, attempts, func() (time.Duration, error) {
		dialer := &net.Dialer{Timeout: timeout}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
			},
			ForceAttemptHTTP2: false,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: timeout}
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		url := "https://" + host + path + separator + "_cfar_probe=" + strconv.FormatInt(time.Now().UnixNano(), 10)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return 0, err
		}
		req.Host = host
		req.Header.Set("User-Agent", "cf-anycast-router/http-probe")
		req.Header.Set("Cache-Control", "no-cache")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.CopyN(io.Discard, resp.Body, 512)
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return time.Since(start), nil
	}, spikeThresholdMs, spikeMultiplier)
}

func CloudflareDownload(ip, host, path string, bytes int64, attempts int, timeout time.Duration, spikeThresholdMs, spikeMultiplier float64) Result {
	if host == "" {
		host = "speed.cloudflare.com"
	}
	if path == "" {
		path = "/__down"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if bytes <= 0 {
		bytes = 262144
	}
	return run(ip, attempts, func() (time.Duration, error) {
		dialer := &net.Dialer{Timeout: timeout}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
			},
			ForceAttemptHTTP2: false,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: timeout}
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		url := fmt.Sprintf("https://%s%s%sbytes=%d&_cfar_probe=%d", host, path, separator, bytes, time.Now().UnixNano())
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return 0, err
		}
		req.Host = host
		req.Header.Set("User-Agent", "cf-anycast-router/cf-speed-probe")
		req.Header.Set("Cache-Control", "no-cache")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			return 0, err
		}
		if n <= 0 {
			return 0, fmt.Errorf("empty speed response")
		}
		return time.Since(start), nil
	}, spikeThresholdMs, spikeMultiplier)
}

func ICMP(ip string, attempts int, timeout time.Duration) Result {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 5 {
		attempts = 5
	}
	if timeout <= 0 || timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	out := Result{IP: ip, Attempts: attempts}
	ctxTimeout := time.Duration(attempts)*timeout + time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		pingPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "ping.exe")
		if _, err := os.Stat(pingPath); err != nil {
			pingPath = "ping"
		}
		cmd = exec.CommandContext(ctx, pingPath, "-n", fmt.Sprintf("%d", attempts), "-w", fmt.Sprintf("%d", timeout.Milliseconds()), ip)
	} else {
		waitSeconds := int(math.Ceil(timeout.Seconds()))
		if waitSeconds < 1 {
			waitSeconds = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", fmt.Sprintf("%d", attempts), "-W", fmt.Sprintf("%d", waitSeconds), ip)
	}
	data, err := cmd.CombinedOutput()
	out.LastError = ""
	if err != nil {
		out.LastError = err.Error()
	}
	if ctx.Err() == context.DeadlineExceeded {
		out.LastError = "ping timed out"
	}
	latencies := parsePingLatencies(string(data))
	out.Successes = len(latencies)
	out.LossRate = float64(attempts-out.Successes) / float64(attempts)
	if len(latencies) == 0 {
		if out.LastError == "" {
			out.LastError = "no ping replies parsed"
		}
		return out
	}
	for _, ms := range latencies {
		out.AvgRTTMs += ms
	}
	out.AvgRTTMs /= float64(len(latencies))
	return out
}

func run(ip string, attempts int, fn func() (time.Duration, error), spikeThresholdMs, spikeMultiplier float64) Result {
	if attempts < 1 {
		attempts = 1
	}
	out := Result{IP: ip, Attempts: attempts}
	latencies := make([]float64, 0, attempts)
	for i := 0; i < attempts; i++ {
		d, err := fn()
		if err != nil {
			out.LastError = err.Error()
			continue
		}
		out.Successes++
		latencies = append(latencies, float64(d.Microseconds())/1000.0)
	}
	out.LossRate = float64(attempts-out.Successes) / float64(attempts)
	if len(latencies) == 0 {
		return out
	}
	for _, ms := range latencies {
		out.AvgRTTMs += ms
	}
	out.AvgRTTMs /= float64(len(latencies))
	if len(latencies) > 1 {
		for i := 1; i < len(latencies); i++ {
			out.JitterMs += math.Abs(latencies[i] - latencies[i-1])
		}
		out.JitterMs /= float64(len(latencies) - 1)
	}
	spikeLimit := math.Max(spikeThresholdMs, out.AvgRTTMs*spikeMultiplier)
	spikes := 0
	for _, ms := range latencies {
		if ms >= spikeLimit {
			spikes++
		}
	}
	out.SpikeRate = float64(spikes) / float64(attempts)
	return out
}

var pingTimePattern = regexp.MustCompile(`(?i)(?:time|时间)[=<]\s*(\d+(?:\.\d+)?)\s*ms`)
var pingReplyTTLPattern = regexp.MustCompile(`(?i)[=<]\s*(\d+(?:\.\d+)?)\s*ms\s+TTL\s*=`)
var pingAveragePattern = regexp.MustCompile(`(?i)(?:average|平均)\s*=\s*(\d+(?:\.\d+)?)\s*ms`)

func parsePingLatencies(raw string) []float64 {
	raw = strings.ReplaceAll(raw, "＜", "<")
	raw = strings.ReplaceAll(raw, "＝", "=")
	var out []float64
	for _, match := range pingTimePattern.FindAllStringSubmatch(raw, -1) {
		ms, err := strconv.ParseFloat(match[1], 64)
		if err == nil {
			out = append(out, ms)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, match := range pingReplyTTLPattern.FindAllStringSubmatch(raw, -1) {
		ms, err := strconv.ParseFloat(match[1], 64)
		if err == nil {
			out = append(out, ms)
		}
	}
	if len(out) > 0 {
		return out
	}
	match := pingAveragePattern.FindStringSubmatch(raw)
	if len(match) == 2 {
		if ms, err := strconv.ParseFloat(match[1], 64); err == nil {
			out = append(out, ms)
		}
	}
	return out
}

func Sort(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		ri, rj := results[i], results[j]
		if ri.Successes == 0 && rj.Successes == 0 {
			return ri.IP < rj.IP
		}
		if ri.Successes == 0 {
			return false
		}
		if rj.Successes == 0 {
			return true
		}
		return ri.AvgRTTMs < rj.AvgRTTMs
	})
}
