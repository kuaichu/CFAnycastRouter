package trace

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	IP   string
	POP  string
	Raw  map[string]string
	Err  string
	OK   bool
	CFID string
}

func CloudflareTrace(ip, host, path string, port int, timeout time.Duration) Result {
	out := Result{IP: ip, Raw: map[string]string{}}
	if path == "" {
		path = "/cdn-cgi/trace"
	}
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
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequest("GET", "https://"+host+path, nil)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	req.Host = host
	req.Header.Set("User-Agent", "cf-anycast-router/0.1")
	resp, err := client.Do(req)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		out.Err = err.Error()
		return out
	}
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			out.Raw[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	out.POP = NormalizePOP(out.Raw["colo"])
	out.CFID = resp.Header.Get("Cf-Ray")
	if out.POP == "" && out.CFID != "" {
		if parts := strings.Split(out.CFID, "-"); len(parts) > 1 {
			out.POP = NormalizePOP(parts[len(parts)-1])
		}
	}
	out.OK = out.POP != ""
	if !out.OK && out.Err == "" {
		out.Err = "colo not found in trace response"
	}
	return out
}

func NormalizePOP(value string) string {
	v := strings.ToUpper(strings.TrimSpace(value))
	switch v {
	case "HKG":
		return "HK"
	case "NRT", "KIX", "FUK":
		return "JP"
	case "SIN":
		return "SG"
	}
	return v
}

func POPRegion(pop string) string {
	switch NormalizePOP(pop) {
	case "HK":
		return "HK"
	case "JP":
		return "JP"
	case "SG":
		return "SG"
	case "LAX", "SJC", "SEA", "DFW", "IAD", "EWR", "ORD", "MIA", "ATL", "DEN", "PHX", "BOS", "YUL", "YYZ":
		return "US"
	case "FRA", "AMS", "LHR", "CDG", "MAD", "MXP", "MRS", "ARN", "WAW", "VIE", "ZRH", "DUB":
		return "EU"
	case "":
		return "unknown"
	default:
		return NormalizePOP(pop)
	}
}
