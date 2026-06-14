package cloudflaredns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cf-anycast-router/internal/config"
)

const apiBase = "https://api.cloudflare.com/client/v4"

type Client struct {
	cfg    config.CloudflareDNSConfig
	token  string
	client *http.Client
	zoneID string
}

type Update struct {
	Region string
	Type   string
	Domain string
	IP     string
	Action string
}

type apiResponse[T any] struct {
	Success bool       `json:"success"`
	Result  T          `json:"result"`
	Errors  []apiError `json:"errors"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func New(cfg config.CloudflareDNSConfig) (*Client, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	token := strings.TrimSpace(os.Getenv(cfg.TokenEnv))
	if token == "" {
		return nil, fmt.Errorf("cloudflare dns is enabled but %s is empty", cfg.TokenEnv)
	}
	if cfg.ZoneID == "" && cfg.ZoneName == "" {
		return nil, fmt.Errorf("cloudflare_dns.zone_id or cloudflare_dns.zone_name is required")
	}
	if len(cfg.RegionRecords()) == 0 {
		return nil, fmt.Errorf("cloudflare_dns.record_sets is empty")
	}
	return &Client{
		cfg:    cfg,
		token:  token,
		client: &http.Client{Timeout: 15 * time.Second},
		zoneID: cfg.ZoneID,
	}, nil
}

func (c *Client) UpsertA(ctx context.Context, region, domain, ip string) (Update, error) {
	return c.UpsertRecord(ctx, region, "A", domain, ip)
}

func (c *Client) UpsertRecord(ctx context.Context, region, recordType, domain, ip string) (Update, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		recordType = "A"
	}
	update := Update{Region: region, Type: recordType, Domain: domain, IP: ip}
	if c == nil {
		return update, nil
	}
	zoneID, err := c.resolveZoneID(ctx)
	if err != nil {
		return update, err
	}
	existing, err := c.findRecord(ctx, zoneID, recordType, domain)
	if err != nil {
		return update, err
	}
	payload := dnsRecord{
		Type:    recordType,
		Name:    domain,
		Content: ip,
		TTL:     c.cfg.TTL,
		Proxied: c.cfg.Proxied,
	}
	if existing != nil {
		if existing.Content == ip && existing.TTL == payload.TTL && existing.Proxied == payload.Proxied {
			update.Action = "unchanged"
			return update, nil
		}
		if err := c.doJSON(ctx, http.MethodPut, fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existing.ID), payload, &apiResponse[dnsRecord]{}); err != nil {
			return update, err
		}
		update.Action = "updated"
		return update, nil
	}
	if err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", zoneID), payload, &apiResponse[dnsRecord]{}); err != nil {
		return update, err
	}
	update.Action = "created"
	return update, nil
}

func (c *Client) resolveZoneID(ctx context.Context) (string, error) {
	if c.zoneID != "" {
		return c.zoneID, nil
	}
	var resp apiResponse[[]zone]
	path := "/zones?name=" + url.QueryEscape(c.cfg.ZoneName)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", err
	}
	if len(resp.Result) == 0 {
		return "", fmt.Errorf("cloudflare zone %q not found", c.cfg.ZoneName)
	}
	c.zoneID = resp.Result[0].ID
	return c.zoneID, nil
}

func (c *Client) findRecord(ctx context.Context, zoneID, recordType, domain string) (*dnsRecord, error) {
	var resp apiResponse[[]dnsRecord]
	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, url.QueryEscape(recordType), url.QueryEscape(domain))
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.Result) == 0 {
		return nil, nil
	}
	return &resp.Result[0], nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare api %s %s failed: %s", method, path, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	success, errors := responseStatus(out)
	if !success {
		return fmt.Errorf("cloudflare api %s %s failed: %s", method, path, errors)
	}
	return nil
}

func responseStatus(v any) (bool, string) {
	data, err := json.Marshal(v)
	if err != nil {
		return false, err.Error()
	}
	var status struct {
		Success bool       `json:"success"`
		Errors  []apiError `json:"errors"`
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return false, err.Error()
	}
	if status.Success {
		return true, ""
	}
	parts := make([]string, 0, len(status.Errors))
	for _, item := range status.Errors {
		parts = append(parts, item.Message)
	}
	return false, strings.Join(parts, "; ")
}
