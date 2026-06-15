package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCarrierRegionRecordsFiltersCarrier(t *testing.T) {
	cfg := CloudflareDNSConfig{RecordSets: []DNSRecordConfig{
		{Enabled: true, Carrier: "cu", Region: "US", Type: "A", Domain: "cu-cf-us.example.com"},
		{Enabled: true, Carrier: "ct", Region: "US", Type: "A", Domain: "ct-cf-us.example.com"},
		{Enabled: false, Carrier: "cu", Region: "HK", Type: "A", Domain: "cu-cf-hk.example.com"},
	}}

	records := cfg.CarrierRegionRecords("cu")
	if len(records) != 1 || records[0].Domain != "cu-cf-us.example.com" {
		t.Fatalf("unexpected CU records: %#v", records)
	}
}

func TestLoadFillsDefaultCloudflareDNSRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("probe_source: test\ncarrier: cu\ntrace_host: cloudflare.com\nprobe_port: 443\nseed_cidrs:\n  - 104.16.0.0/24\ncloudflare_dns:\n  enabled: true\n  zone_name: ziher.eu.org\n  record_sets:\n    - enabled: true\n      carrier: cu\n      region: US\n      type: A\n      domain: custom-us.example.com\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CloudflareDNS.RecordSets) != 12 {
		t.Fatalf("expected 12 generated record sets, got %d: %#v", len(cfg.CloudflareDNS.RecordSets), cfg.CloudflareDNS.RecordSets)
	}
	records := cfg.CloudflareDNS.CarrierRegionRecords("cu")
	foundCustom := false
	for _, record := range records {
		if record.Region == "US" {
			foundCustom = true
			if record.Domain != "custom-us.example.com" {
				t.Fatalf("custom CU US record was overwritten: %#v", record)
			}
		}
	}
	if !foundCustom {
		t.Fatal("custom CU US record not found")
	}
	ctRecords := cfg.CloudflareDNS.CarrierRegionRecords("ct")
	if len(ctRecords) != 4 {
		t.Fatalf("expected 4 CT records, got %#v", ctRecords)
	}
	for _, record := range ctRecords {
		want := "ct-cf-" + strings.ToLower(record.Region) + ".ziher.eu.org"
		if record.Domain != want {
			t.Fatalf("unexpected generated CT domain: got %s want %s", record.Domain, want)
		}
	}
}

func TestSaveManageSettingsPersistsAgentBudgets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("probe_source: test\ncarrier: cu\ntrace_host: cloudflare.com\nprobe_port: 443\nseed_cidrs:\n  - 104.16.0.0/24\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	settings := cfg.ManageSettings()
	settings.ProbeAttempts = 7
	settings.ProbeTimeoutSec = 5
	settings.MaxRouteTracesPerCycle = 18
	settings.SeedPreflightMaxPerCycle = 30
	settings.MaxSeedSegmentsPerCycle = 9
	settings.MaxLearnedSegmentsPerCycle = 11
	settings.MaxSamplesPerSegmentPerCycle = 6
	settings.PromoteMinSamples = 8
	settings.PromotePOPProbability = 0.8
	settings.HotMaxPerSegment = 10
	settings.HotMaxScore = 88

	if _, err := SaveManageSettings(path, settings); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProbeAttempts != 7 || got.ProbeTimeoutSec != 5 || got.MaxRouteTracesPerCycle != 18 ||
		got.SeedPreflightMaxPerCycle != 30 || got.MaxSeedSegmentsPerCycle != 9 ||
		got.MaxLearnedSegmentsPerCycle != 11 || got.MaxSamplesPerSegmentPerCycle != 6 ||
		got.PromoteMinSamples != 8 || got.PromotePOPProbability != 0.8 ||
		got.HotMaxPerSegment != 10 || got.HotMaxScore != 88 {
		t.Fatalf("management budgets were not persisted: %#v", got.ManageSettings())
	}
}
