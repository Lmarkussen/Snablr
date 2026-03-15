package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"snablr/internal/metrics"
)

const defaultReachabilityTimeout = 3 * time.Second

type ReachabilityOptions struct {
	SkipCheck bool
	Timeout   time.Duration
	Workers   int
}

func FilterReachable(ctx context.Context, targets []Target, opts ReachabilityOptions, logger Logger, recorder metrics.Recorder) ([]Target, []Target, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultReachabilityTimeout
	}
	if opts.Workers <= 0 {
		opts.Workers = 8
	}

	if opts.SkipCheck {
		out := make([]Target, 0, len(targets))
		for _, target := range targets {
			if enriched := enrichTarget(ctx, target, logger); enriched.Input != "" {
				enriched.Reachable445 = true
				out = append(out, enriched)
			}
		}
		return out, append([]Target{}, out...), nil
	}

	jobs := make(chan Target)
	results := make(chan Target, len(targets))
	errCh := make(chan error, 1)

	var workers sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runReachabilityWorker(ctx, jobs, results, opts.Timeout, logger)
		}()
	}

	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case jobs <- target:
			}
		}
		errCh <- nil
	}()

	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(results)
		close(workersDone)
	}()

	all := make([]Target, 0, len(targets))
	reachable := make([]Target, 0, len(targets))
	for result := range results {
		all = append(all, result)
		if result.Reachable445 {
			reachable = append(reachable, result)
		}
	}
	<-workersDone

	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return nil, nil, err
	}

	return all, reachable, nil
}

func runReachabilityWorker(ctx context.Context, jobs <-chan Target, results chan<- Target, timeout time.Duration, logger Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-jobs:
			if !ok {
				return
			}

			target = enrichTarget(ctx, target, logger)
			target.Reachable445 = testTCP445(ctx, target, timeout)

			select {
			case <-ctx.Done():
				return
			case results <- target:
			}
		}
	}
}

func enrichTarget(ctx context.Context, target Target, logger Logger) Target {
	if target.IP != "" {
		return target
	}

	host := strings.TrimSpace(target.Hostname)
	if host == "" {
		host = normalizeEndpoint(target.Input)
		target.Hostname = host
	}
	if host == "" {
		return target
	}

	addresses, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		if logger != nil {
			logger.Debugf("target resolution failed for %s: %v", host, err)
		}
		return target
	}
	for _, address := range addresses {
		if net.ParseIP(address) != nil {
			target.IP = address
			return target
		}
	}
	return target
}

func testTCP445(ctx context.Context, target Target, timeout time.Duration) bool {
	address := targetAddress(target)
	if address == "" {
		return false
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, "445"))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func targetAddress(target Target) string {
	if target.IP != "" {
		return target.IP
	}
	if target.Hostname != "" {
		return target.Hostname
	}
	return normalizeEndpoint(target.Input)
}

func formatTargetStats(stats TargetStats) string {
	return fmt.Sprintf("Targets loaded: %d\nUnique targets: %d\nReachable SMB hosts: %d\nSkipped hosts: %d", stats.Loaded, stats.Unique, stats.Reachable, stats.Skipped)
}
