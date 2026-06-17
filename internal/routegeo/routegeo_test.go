package routegeo

import (
	"strings"
	"testing"
)

func TestParseNTRRawHopsSortsByHop(t *testing.T) {
	raw := `14|129.250.3.187||115.94||||||||
9|219.158.3.174||30.68||||||||
16|103.22.203.227||117.87||||||||
17|172.67.73.197||117.30||||||||
2|10.0.0.1||0.51||||||||`
	got := parseNTRRawHops(raw)
	want := []string{"10.0.0.1", "219.158.3.174", "129.250.3.187", "103.22.203.227", "172.67.73.197"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hop %d=%s want %s; all=%#v", i, got[i], want[i], got)
		}
	}
}

func TestParseEmbeddedGeoInfos(t *testing.T) {
	raw := `14. AS2914 ae-32.a01.newthk04.hk.bb.gin.ntt.net (129.250.3.187) China Hong Kong NTT America, Inc.
15 103.22.203.227 AS13335 [CLOUDFLARE-AP] 中国 香港 cloudflare.com
8 141.101.72.123 AS13335 [CLOUDFLARENET] United States Los Angeles Cloudflare, Inc.`
	infos := parseEmbeddedGeoInfos(raw)
	cases := map[string]string{
		"129.250.3.187":  "HK",
		"103.22.203.227": "HK",
		"141.101.72.123": "US",
	}
	for ip, want := range cases {
		info, ok := infos[ip]
		if !ok {
			t.Fatalf("missing embedded geo for %s", ip)
		}
		if got := regionFromGeo(info); got != want {
			t.Fatalf("%s region=%s want %s; info=%#v", ip, got, want, info)
		}
	}
}

func TestNextTraceRawReportPicksJapanCloudflareHop(t *testing.T) {
	target := "108.162.198.237"
	raw := `1|192.168.1.1||0.24||||||||
2|60.178.228.1||2.26|4134|中国|浙江省|宁波市||chinatelecom.com.cn  电信|29.8683|121.5440
3|61.175.31.181||3.15|4134|中国|浙江|宁波||chinatelecom.com.cn|29.8683|121.5440
8|202.97.42.166||52.06|4134|日本|东京都|东京|CT-POP|chinatelecom.com.cn  电信|35.6804|139.7690
9|203.215.237.102||50.87||日本|东京都|东京||电信|35.6804|139.7690
10|103.22.201.21||61.14|13335|日本|东京都|东京||cloudflare.com|35.6804|139.7690
11|108.162.198.237||39.64|13335|Anycast||||cloudflare.com||`

	hops := parseHops(raw)
	infos := parseEmbeddedGeoInfos(raw)
	pick := pickRouteHint(target, hops, infos)
	if pick == nil {
		t.Fatal("expected route hint from NextTrace raw report")
	}
	if pick.Query != "103.22.201.21" {
		t.Fatalf("hint IP=%s want 103.22.201.21", pick.Query)
	}
	if got := regionFromGeo(*pick); got != "JP" {
		t.Fatalf("route hint region=%s want JP; info=%#v", got, *pick)
	}
}

func TestNextTraceReportPrefersCloudflareUSHopAfterHKTransit(t *testing.T) {
	target := "104.17.151.135"
	raw := `1   10.0.0.1        *                         RFC1918
                                              0.53 ms / 0.37 ms / 0.33 ms
2   101.64.132.1    AS4837                    中国 浙江省 宁波市 海曙 中国联通
                                              6.75 ms / 6.89 ms / 8.64 ms
3   *
4   221.12.177.9    AS4837                    中国 浙江省 宁波市  中国联通
                                              11.58 ms / 11.74 ms / * ms
5   *
6   219.158.113.102 AS4837                    中国 北京市   中国联通/骨干网
                                              10.59 ms / 10.50 ms / * ms
7   *
8   219.158.97.182  AS4837                    中国 香港   中国联通/骨干网
                                              133.24 ms / 134.05 ms / 133.36 ms
9   152.179.48.217  AS701                     美国    Verizon
    xe-0-1-0.gw8.sjc7.alter.net               160.35 ms / 160.51 ms / 159.83 ms
10  *
11  *
12  172.68.188.20   AS13335                   美国    Cloudflare
                                              148.31 ms / 150.72 ms / 149.24 ms
13  104.17.151.135  AS13335                   美国    Cloudflare
                                              147.50 ms / 149.71 ms / 148.89 ms`

	hops := parseHops(raw)
	infos := parseEmbeddedGeoInfos(raw)
	pick := pickRouteHint(target, hops, infos)
	if pick == nil {
		t.Fatal("expected route hint from complete NextTrace report")
	}
	if pick.Query != "172.68.188.20" {
		t.Fatalf("hint IP=%s want 172.68.188.20", pick.Query)
	}
	if got := regionFromGeo(*pick); got != "US" {
		t.Fatalf("route hint region=%s want US; info=%#v", got, *pick)
	}
}

func TestNTRReportArgsFromRaw(t *testing.T) {
	got, ok := ntrReportArgs([]string{"-4", "--raw", "--icmp-mode", "2", "-d", "disable-geoip", "-q", "1", "{ip}"})
	if !ok {
		t.Fatal("expected raw args to be convertible")
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"--report", "--wide", "--show-ips", "disable-geoip", "-q 3", "{ip}"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("converted args %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "--raw") || strings.Contains(joined, "ip-api.com") {
		t.Fatalf("converted args still contain raw or forced geo API: %q", joined)
	}
}

func TestEmbeddedFallbackCanOverrideMiddleNTTHop(t *testing.T) {
	primary := geoInfo{
		Status:      "success",
		Query:       "203.131.240.78",
		Country:     "Japan",
		CountryCode: "JP",
		City:        "Chiyoda City",
		ISP:         "NTT America, Inc.",
		AS:          "AS2914 NTT America, Inc.",
	}
	fallback := geoInfo{
		Status:      "success",
		Query:       "103.22.203.27",
		Country:     "Hong Kong",
		CountryCode: "HK",
		City:        "Hong Kong",
		ISP:         "Cloudflare, Inc.",
		AS:          "AS13335 Cloudflare, Inc.",
	}
	if !shouldUseEmbeddedFallback(
		"172.67.64.104",
		[]string{"219.158.3.174", "203.131.240.78", "172.67.64.104"},
		&primary,
		[]string{"219.158.3.174", "203.131.240.78", "103.22.203.27", "172.67.64.104"},
		&fallback,
	) {
		t.Fatal("expected Cloudflare HK fallback to override middle NTT JP lookup")
	}
}

func TestStaticRouteGeo(t *testing.T) {
	cases := map[string]string{
		"103.22.203.71":   "HK",
		"129.250.3.187":   "HK",
		"203.131.240.78":  "HK",
		"203.131.241.220": "HK",
		"202.77.23.30":    "HK",
		"141.101.72.123":  "US",
	}
	for ip, want := range cases {
		info, ok := staticRouteGeo(ip)
		if !ok {
			t.Fatalf("staticRouteGeo(%s) not found", ip)
		}
		if got := regionFromGeo(info); got != want {
			t.Fatalf("staticRouteGeo(%s)=%s want %s", ip, got, want)
		}
	}
}

func TestPickRouteHintUsesKnownHKHandoffWhenCloudflareHopIsMissing(t *testing.T) {
	target := "172.67.64.82"
	hops := []string{
		"10.0.0.1",
		"219.158.103.34",
		"219.158.3.106",
		"203.131.241.220",
		"129.250.3.187",
		target,
	}
	infos := map[string]geoInfo{}
	for _, hop := range hops {
		if info, ok := staticRouteGeo(hop); ok {
			infos[hop] = info
		}
	}
	pick := pickRouteHint(target, hops, infos)
	if pick == nil {
		t.Fatal("expected HK route hint")
	}
	if got := regionFromGeo(*pick); got != "HK" {
		t.Fatalf("route hint region=%s want HK; info=%#v", got, *pick)
	}
	if pick.Query != "129.250.3.187" {
		t.Fatalf("route hint IP=%s want 129.250.3.187", pick.Query)
	}
}
