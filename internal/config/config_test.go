package config

import "testing"

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
