package netinfo

import (
	"fmt"
	"net"
	"strings"
)

type PrefixInfo struct {
	IP       string `json:"ip"`
	ASN      string `json:"asn"`
	Prefix   string `json:"prefix"`
	CC       string `json:"cc"`
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Raw      string `json:"raw"`
}

func LookupPrefix(ip string) (*PrefixInfo, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return nil, fmt.Errorf("only IPv4 is supported")
	}
	q := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", parsed[3], parsed[2], parsed[1], parsed[0])
	txts, err := net.LookupTXT(q)
	if err != nil {
		return nil, fmt.Errorf("lookup BGP prefix: %w", err)
	}
	for _, txt := range txts {
		parts := strings.Split(txt, "|")
		if len(parts) < 5 {
			continue
		}
		info := &PrefixInfo{
			IP:       parsed.String(),
			ASN:      strings.TrimSpace(parts[0]),
			Prefix:   strings.TrimSpace(parts[1]),
			CC:       strings.TrimSpace(parts[2]),
			Registry: strings.TrimSpace(parts[3]),
			Raw:      txt,
		}
		if len(parts) > 4 {
			info.Name = strings.TrimSpace(parts[len(parts)-1])
		}
		if _, _, err := net.ParseCIDR(info.Prefix); err != nil {
			continue
		}
		return info, nil
	}
	return nil, fmt.Errorf("no usable prefix returned for %s", ip)
}
