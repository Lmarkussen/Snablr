package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"snablr/internal/config"
	"snablr/internal/metrics"
)

type PipelineResult struct {
	AllTargets       []Target
	ReachableTargets []Target
	DiscoveredHosts  []DiscoveredHost
	DFSTargets       []DFSTarget
	Stats            TargetStats
}

func Resolve(ctx context.Context, cfg config.ScanConfig, logger Logger, recorder metrics.Recorder) (PipelineResult, error) {
	var result PipelineResult
	var collectTimer *metrics.Timer
	if recorder != nil {
		collectTimer = recorder.StartPhase("target_collection")
	}

	collected, err := collectTargets(ctx, cfg, logger)
	if collectTimer != nil {
		collectTimer.Stop()
	}
	if err != nil {
		return PipelineResult{}, err
	}
	result.DiscoveredHosts = collected.discoveredHosts
	result.DFSTargets = collected.dfsTargets
	result.Stats.Loaded = len(collected.targets)
	if recorder != nil {
		recorder.AddTargetsLoaded(result.Stats.Loaded)
	}

	unique := deduplicateTargets(collected.targets)
	result.Stats.Unique = len(unique)

	var reachabilityTimer *metrics.Timer
	if recorder != nil {
		reachabilityTimer = recorder.StartPhase("reachability_check")
	}
	checked, reachable, err := FilterReachable(ctx, unique, ReachabilityOptions{
		SkipCheck: cfg.SkipReachabilityCheck,
		Timeout:   cfg.ReachabilityTimeout(),
		Workers:   cfg.WorkerCount,
	}, logger, recorder)
	if reachabilityTimer != nil {
		reachabilityTimer.Stop()
	}
	if err != nil {
		return PipelineResult{}, err
	}

	result.AllTargets = checked
	result.ReachableTargets = reachable
	result.Stats.Reachable = len(reachable)
	if recorder != nil {
		recorder.AddTargetsReachable(result.Stats.Reachable)
	}
	result.Stats.Unreachable = len(unique) - len(reachable)
	result.Stats.Skipped = result.Stats.Loaded - result.Stats.Reachable

	return result, nil
}

type collectedTargets struct {
	targets         []Target
	discoveredHosts []DiscoveredHost
	dfsTargets      []DFSTarget
}

func collectTargets(ctx context.Context, cfg config.ScanConfig, logger Logger) (collectedTargets, error) {
	var result collectedTargets

	for _, host := range cfg.Targets {
		if target := newTarget(host, "cli"); target.Input != "" {
			result.targets = append(result.targets, target)
		}
	}

	if strings.TrimSpace(cfg.TargetsFile) != "" {
		file, err := os.Open(cfg.TargetsFile)
		if err != nil {
			return collectedTargets{}, fmt.Errorf("open host file %s: %w", cfg.TargetsFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if target := newTarget(line, "file"); target.Input != "" {
				result.targets = append(result.targets, target)
			}
		}
		if err := scanner.Err(); err != nil {
			return collectedTargets{}, fmt.Errorf("read host file %s: %w", cfg.TargetsFile, err)
		}
	}

	if len(result.targets) == 0 && !cfg.NoLDAP {
		if logger != nil {
			logger.Infof("no explicit targets supplied, starting ldap discovery")
		}

		discovered, err := DiscoverLDAP(ctx, LDAPOptions{
			Username:         cfg.Username,
			Password:         cfg.Password,
			Domain:           cfg.Domain,
			DomainController: cfg.DomainController,
			BaseDN:           cfg.BaseDN,
		}, logger)
		if err != nil {
			return collectedTargets{}, err
		}

		result.discoveredHosts = append(result.discoveredHosts, discovered...)
		for _, host := range discovered {
			target := newLDAPTarget(host)
			if target.Input == "" {
				continue
			}
			result.targets = append(result.targets, target)
		}
	}

	if cfg.DiscoverDFS {
		if logger != nil {
			logger.Infof("dfs discovery enabled, starting dfs discovery")
		}

		discoveredDFS, err := DiscoverDFS(ctx, LDAPOptions{
			Username:         cfg.Username,
			Password:         cfg.Password,
			Domain:           cfg.Domain,
			DomainController: cfg.DomainController,
			BaseDN:           cfg.BaseDN,
		}, logger)
		if err != nil {
			if logger != nil {
				logger.Warnf("dfs discovery failed: %v", err)
			}
		} else {
			result.dfsTargets = append(result.dfsTargets, discoveredDFS...)
			for _, target := range discoveredDFS {
				hostTarget := newTarget(target.TargetServer, "dfs")
				if hostTarget.Input == "" {
					continue
				}
				result.targets = append(result.targets, hostTarget)
			}
		}
	}

	return result, nil
}

func newTarget(value, source string) Target {
	value = strings.TrimSpace(value)
	if value == "" {
		return Target{}
	}

	target := Target{
		Input:  value,
		Source: source,
	}

	host := normalizeEndpoint(value)
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip.String()
		target.Hostname = ip.String()
		return target
	}

	target.Hostname = host
	return target
}

func newLDAPTarget(host DiscoveredHost) Target {
	input := strings.TrimSpace(host.DNSHostname)
	if input == "" {
		input = strings.TrimSpace(host.Hostname)
	}
	target := newTarget(input, host.Source)
	if host.IP != "" {
		target.IP = host.IP
	}
	if target.Hostname == "" {
		target.Hostname = strings.TrimSpace(host.Hostname)
	}
	return target
}

func deduplicateTargets(targets []Target) []Target {
	seen := make(map[string]struct{}, len(targets))
	unique := make([]Target, 0, len(targets))

	for _, target := range targets {
		key := targetKey(target)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, target)
	}

	return unique
}

func targetKey(target Target) string {
	if target.IP != "" {
		return "ip:" + strings.ToLower(target.IP)
	}
	if target.Hostname != "" {
		return "host:" + strings.ToLower(target.Hostname)
	}
	if target.Input != "" {
		return "input:" + strings.ToLower(target.Input)
	}
	return ""
}

func normalizeEndpoint(value string) string {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return value
}
