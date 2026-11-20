package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

func TestStealthPresetAndOverrides(t *testing.T) {
	cfg := config.Default()
	applyScanOverrides(&cfg, ScanOptions{Stealth: true})
	scan := cfg.Scan
	if !scan.Stealth || scan.WorkerCount != 1 || scan.FileDelay != "500ms-2s" || scan.HostDelay != "10s-60s" ||
		!scan.SkipReachabilityCheck || scan.MaxFileSize != config.StealthMaxFileSize || cfg.WIM.Enabled || scan.StealthMaxDeniedShares != 5 {
		t.Errorf("stealth preset not applied: %+v wim=%v", scan, cfg.WIM.Enabled)
	}

	// Explicit options override the preset.
	workers := 4
	wim := true
	cfg = config.Default()
	applyScanOverrides(&cfg, ScanOptions{Stealth: true, WorkerCount: &workers, FileDelay: "100ms", HostDelay: "1s-2s", MaxFileSize: 8 << 20, WIMEnabled: &wim, Workstation: "WS-0142", LowMemory: true})
	scan = cfg.Scan
	if scan.WorkerCount != 4 || scan.FileDelay != "100ms" || scan.HostDelay != "1s-2s" || scan.MaxFileSize != 8<<20 || !cfg.WIM.Enabled || scan.Workstation != "WS-0142" {
		t.Errorf("explicit options lost under stealth: %+v wim=%v", scan, cfg.WIM.Enabled)
	}
	cfg = config.Default()
	applyScanOverrides(&cfg, ScanOptions{Stealth: true, LowMemory: true})
	if cfg.Scan.WorkerCount != 1 {
		t.Errorf("--low-memory raised stealth workers to %d", cfg.Scan.WorkerCount)
	}

	// Without --stealth nothing changes.
	before := config.Default()
	after := config.Default()
	applyScanOverrides(&after, ScanOptions{})
	if before.Scan.WorkerCount != after.Scan.WorkerCount || after.Scan.Stealth || after.Scan.FileDelay != "" ||
		after.Scan.HostDelay != "" || after.Scan.SkipReachabilityCheck != before.Scan.SkipReachabilityCheck ||
		after.Scan.MaxFileSize != before.Scan.MaxFileSize || after.WIM.Enabled != before.WIM.Enabled {
		t.Errorf("default scan changed: %+v", after.Scan)
	}
	after.Scan.Username, after.Scan.Password = "user", "x"
	if err := validateScanConfig(after); err != nil {
		t.Errorf("default config invalid: %v", err)
	}
}

func TestDelayValidation(t *testing.T) {
	cfg := config.Default()
	cfg.Scan.FileDelay = "2s-500ms"
	if err := validateScanConfig(cfg); err == nil || !strings.Contains(err.Error(), "--file-delay") {
		t.Errorf("reversed range accepted: %v", err)
	}
	cfg.Scan.FileDelay = ""
	cfg.Scan.HostDelay = "soon"
	if err := validateScanConfig(cfg); err == nil || !strings.Contains(err.Error(), "--host-delay") {
		t.Errorf("bad host delay accepted: %v", err)
	}
}

// Runs without stealth keep the resume fingerprint they had before, so an
// existing database resumes without rescanning.
func TestResumeFingerprintUnchangedWithoutStealth(t *testing.T) {
	data, err := json.Marshal(scanSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "WithheldContent") {
		t.Errorf("non-stealth semantics carry the stealth field: %s", data)
	}
	cfg := config.Default()
	plain := scanSemanticsFingerprint(cfg, nil)
	cfg.Scan.Stealth = true
	if scanSemanticsFingerprint(cfg, nil) == plain {
		t.Error("stealth run shares the fingerprint of a full run")
	}
}

func TestPauseBetweenHosts(t *testing.T) {
	var slept []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	cfg := config.ScanConfig{HostDelay: "10s-60s"}
	for i := 0; i < 50; i++ {
		_ = pauseBetweenHosts(context.Background(), cfg, sleep)
	}
	for _, d := range slept {
		if d < 10*time.Second || d > 60*time.Second {
			t.Fatalf("host delay %v outside 10s-60s", d)
		}
	}
	slept = nil
	_ = pauseBetweenHosts(context.Background(), config.ScanConfig{}, sleep)
	if len(slept) != 0 {
		t.Errorf("paused without a host delay: %v", slept)
	}
}

func TestWorkstationReachesSMBAuth(t *testing.T) {
	auth, err := smbAuthForHost("fs01", config.ScanConfig{Username: "user", Password: "x", Workstation: "WS-0142"})
	if err != nil || auth.Workstation != "WS-0142" {
		t.Errorf("auth %+v %v", auth, err)
	}
}

// pathQueryClient counts administrative share-path queries.
type pathQueryClient struct {
	aliasClient
	pathQueries int
}

func (c *pathQueryClient) SharePaths() (map[string]string, error) {
	c.pathQueries++
	return c.aliasClient.SharePaths()
}

// Stealth does not send the administrative share-path query; normal scans do.
func TestStealthSkipsSharePathQuery(t *testing.T) {
	for _, stealth := range []bool{false, true} {
		client := &pathQueryClient{aliasClient: aliasClient{excludes: map[string][]string{}}}
		oldClient := newScanClientFunc
		newScanClientFunc = func() scanClient { return client }
		cfg := config.Default()
		cfg.Scan.Username, cfg.Scan.Password = "user", "password"
		cfg.Scan.Stealth = stealth
		cfg.Scan.Share = []string{"software_dist"}
		manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		sink := &appCaptureSink{}
		recorder := metrics.NewCollector()
		engine := scanner.NewEngine(scanner.Options{Recorder: recorder}, manager, sink, logx.New("error"))
		err = scanHost(context.Background(), "site.example.test", "test", nil, nil, nil, "ctx", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error"))
		newScanClientFunc = oldClient
		if err != nil {
			t.Fatalf("stealth=%v: %v", stealth, err)
		}
		if want := map[bool]int{false: 1, true: 0}[stealth]; client.pathQueries != want {
			t.Errorf("stealth=%v: %d share-path queries, want %d", stealth, client.pathQueries, want)
		}
		if _, walked := client.excludes["software_dist"]; !walked {
			t.Errorf("stealth=%v: named share not scanned", stealth)
		}
	}
}
