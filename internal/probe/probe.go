package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
		req.Header.Set("User-Agent", "cf-anycast-router/anchor-probe")
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

func WebSocket(ip, host, path string, port int, attempts int, timeout time.Duration, spikeThresholdMs, spikeMultiplier float64) Result {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return run(ip, attempts, func() (time.Duration, error) {
		dialer := &net.Dialer{Timeout: timeout}
		start := time.Now()
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		key, err := websocketKey()
		if err != nil {
			return 0, err
		}
		req := "GET " + path + " HTTP/1.1\r\n" +
			"Host: " + host + "\r\n" +
			"User-Agent: cf-anycast-router/anchor-probe\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Key: " + key + "\r\n" +
			"Sec-WebSocket-Version: 13\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return 0, err
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return 0, err
		}
		if !strings.HasPrefix(line, "HTTP/") {
			return 0, fmt.Errorf("invalid websocket response")
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("invalid websocket status")
		}
		status, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, err
		}
		if status >= 500 {
			return 0, fmt.Errorf("HTTP %d", status)
		}
		return time.Since(start), nil
	}, spikeThresholdMs, spikeMultiplier)
}

func VLESSWebSocketHTTPS(ip, host, path string, port int, uuid, targetHost, targetPath string, attempts int, timeout time.Duration, spikeThresholdMs, spikeMultiplier float64) Result {
	if targetHost == "" {
		targetHost = "www.gstatic.com"
	}
	if targetPath == "" {
		targetPath = "/generate_204"
	}
	if !strings.HasPrefix(targetPath, "/") {
		targetPath = "/" + targetPath
	}
	return run(ip, attempts, func() (time.Duration, error) {
		uuidBytes, err := parseUUID(uuid)
		if err != nil {
			return 0, err
		}
		start := time.Now()
		ws, err := dialWebSocket(ip, host, path, port, timeout)
		if err != nil {
			return 0, err
		}
		defer ws.Close()
		_ = ws.SetDeadline(time.Now().Add(timeout))
		if err := ws.WriteFrame(vlessRequest(uuidBytes, targetHost, 443)); err != nil {
			return 0, err
		}
		tunnel := &vlessWSConn{wsConn: ws}
		tlsConn := tls.Client(tunnel, &tls.Config{ServerName: targetHost, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			return 0, err
		}
		req := "GET " + targetPath + " HTTP/1.1\r\nHost: " + targetHost + "\r\nUser-Agent: cf-anycast-router/vless-probe\r\nConnection: close\r\n\r\n"
		if _, err := tlsConn.Write([]byte(req)); err != nil {
			_ = tlsConn.Close()
			return 0, err
		}
		line, err := bufio.NewReader(tlsConn).ReadString('\n')
		_ = tlsConn.Close()
		if err != nil {
			return 0, err
		}
		if !strings.HasPrefix(line, "HTTP/") {
			return 0, fmt.Errorf("invalid target HTTP response")
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("invalid target HTTP status")
		}
		status, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, err
		}
		if status >= 500 {
			return 0, fmt.Errorf("target HTTP %d", status)
		}
		return time.Since(start), nil
	}, spikeThresholdMs, spikeMultiplier)
}

func dialWebSocket(ip, host, path string, port int, timeout time.Duration) (*wsConn, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	key, err := websocketKey()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: cf-anycast-router/anchor-probe\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	reader := bufio.NewReader(conn)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[1] != "101" {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket status %s", strings.TrimSpace(line))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	return &wsConn{conn: conn, reader: reader}, nil
}

type wsConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (c *wsConn) Close() error                  { return c.conn.Close() }
func (c *wsConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *wsConn) WriteFrame(payload []byte) error {
	header := []byte{0x82}
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(0x80|n))
	case n <= 65535:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(n))
		header = append(header, size[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(masked)
	return err
}

func (c *wsConn) ReadFrame() ([]byte, error) {
	for {
		b0, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		b1, err := c.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		opcode := b0 & 0x0f
		masked := b1&0x80 != 0
		n := uint64(b1 & 0x7f)
		if n == 126 {
			var buf [2]byte
			if _, err := io.ReadFull(c.reader, buf[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(buf[:]))
		} else if n == 127 {
			var buf [8]byte
			if _, err := io.ReadFull(c.reader, buf[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(buf[:])
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
				return nil, err
			}
		}
		if n > 1<<20 {
			return nil, fmt.Errorf("websocket frame too large")
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 0x1, 0x2, 0x0:
			return payload, nil
		case 0x8:
			return nil, io.EOF
		case 0x9:
			_ = c.WriteFrame(payload)
		}
	}
}

type vlessWSConn struct {
	wsConn *wsConn
	buf    []byte
	seen   bool
}

func (c *vlessWSConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		frame, err := c.wsConn.ReadFrame()
		if err != nil {
			return 0, err
		}
		if !c.seen {
			c.seen = true
			if len(frame) < 2 {
				continue
			}
			skip := 2 + int(frame[1])
			if skip > len(frame) {
				continue
			}
			frame = frame[skip:]
		}
		c.buf = frame
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *vlessWSConn) Write(p []byte) (int, error) {
	if err := c.wsConn.WriteFrame(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *vlessWSConn) Close() error                       { return c.wsConn.Close() }
func (c *vlessWSConn) LocalAddr() net.Addr                { return c.wsConn.conn.LocalAddr() }
func (c *vlessWSConn) RemoteAddr() net.Addr               { return c.wsConn.conn.RemoteAddr() }
func (c *vlessWSConn) SetDeadline(t time.Time) error      { return c.wsConn.conn.SetDeadline(t) }
func (c *vlessWSConn) SetReadDeadline(t time.Time) error  { return c.wsConn.conn.SetReadDeadline(t) }
func (c *vlessWSConn) SetWriteDeadline(t time.Time) error { return c.wsConn.conn.SetWriteDeadline(t) }

func parseUUID(value string) ([]byte, error) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(cleaned) != 32 {
		return nil, fmt.Errorf("invalid UUID")
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		n, err := strconv.ParseUint(cleaned[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID")
		}
		out[i] = byte(n)
	}
	return out, nil
}

func vlessRequest(uuid []byte, host string, port int) []byte {
	out := make([]byte, 0, 22+len(host))
	out = append(out, 0x00)
	out = append(out, uuid...)
	out = append(out, 0x00)
	out = append(out, 0x01)
	out = append(out, byte(port>>8), byte(port))
	out = append(out, 0x02, byte(len(host)))
	out = append(out, []byte(host)...)
	return out
}

func websocketKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
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
