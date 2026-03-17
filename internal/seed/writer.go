package seed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"snablr/internal/smb"
)

type smbWriter interface {
	Connect(host, user, pass string) error
	Close() error
	ListShares() ([]smb.ShareInfo, error)
	FileContentEquals(share, path string, expected []byte) (bool, error)
	WriteFile(share, path string, data []byte) error
	RemoveAll(share, path string) error
}

var newSMBWriter = func() smbWriter {
	return smb.NewClient()
}

type seedClientPool struct {
	opts    WriteOptions
	clients map[string]smbWriter
}

type seedRunStats struct {
	Candidates        int
	Written           int
	Skipped           int
	DryRun            int
	WrittenByCategory map[string]int
	WrittenByShare    map[string]int
}

func newSeedClientPool(opts WriteOptions) *seedClientPool {
	return &seedClientPool{
		opts:    opts,
		clients: make(map[string]smbWriter),
	}
}

func newSeedRunStats(candidates int) *seedRunStats {
	return &seedRunStats{
		Candidates:        candidates,
		WrittenByCategory: make(map[string]int),
		WrittenByShare:    make(map[string]int),
	}
}

func (s *seedRunStats) recordWritten(category, host, share string) {
	if s == nil {
		return
	}
	s.Written++
	category = strings.TrimSpace(category)
	if category != "" {
		s.WrittenByCategory[category]++
	}
	shareKey := shareSummaryKey(host, share)
	if shareKey != "" {
		s.WrittenByShare[shareKey]++
	}
}

func (s *seedRunStats) recordSkipped() {
	if s == nil {
		return
	}
	s.Skipped++
}

func (s *seedRunStats) recordDryRun() {
	if s == nil {
		return
	}
	s.DryRun++
}

func (p *seedClientPool) clientFor(host string) (smbWriter, error) {
	key := normalizeHostKey(host)
	if client, ok := p.clients[key]; ok {
		return client, nil
	}

	client := newSMBWriter()
	if err := client.Connect(host, p.opts.Username, p.opts.Password); err != nil {
		return nil, fmt.Errorf("%s: connect failed: %w", host, err)
	}
	p.clients[key] = client
	return client, nil
}

func (p *seedClientPool) Close() error {
	keys := make([]string, 0, len(p.clients))
	for key := range p.clients {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var errs []error
	for _, key := range keys {
		client := p.clients[key]
		delete(p.clients, key)
		if client == nil {
			continue
		}
		if err := client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

func Seed(ctx context.Context, opts WriteOptions) (Manifest, error) {
	prefix, err := safeCleanPrefix(opts.SeedPrefix)
	if err != nil {
		return Manifest{}, err
	}
	opts.SeedPrefix = prefix

	files, err := Generate(GenerateOptions{
		CountPerCategory:    opts.CountPerCat,
		MaxFiles:            opts.MaxFiles,
		Depth:               opts.Depth,
		SeedPrefix:          opts.SeedPrefix,
		RandomSeed:          opts.RandomSeed,
		LikelyHitRatio:      opts.LikelyHitRatio,
		FilenameOnlyRatio:   opts.FilenameOnlyRatio,
		HighSeverityRatio:   opts.HighSeverityRatio,
		MediumSeverityRatio: opts.MediumSeverityRatio,
	})
	if err != nil {
		return Manifest{}, err
	}

	destinations, err := discoverDestinations(ctx, opts)
	if err != nil {
		return Manifest{}, err
	}
	if len(destinations) == 0 {
		return Manifest{}, fmt.Errorf("no accessible SMB shares available for seeding")
	}

	manifest := NewManifest(opts.SeedPrefix)
	stats := newSeedRunStats(len(files))
	pool := newSeedClientPool(opts)
	defer func() {
		if err := pool.Close(); err != nil {
			logWarn(opts, "close warning: %v", err)
		}
	}()

	if opts.CleanPrefix {
		if err := cleanSeedPrefix(ctx, destinations, pool, opts); err != nil {
			return manifest, err
		}
	}

	logInfo(opts, "seed planning: candidates=%d eligible-share-targets=%d count-per-category=%d max-files=%d",
		stats.Candidates, len(destinations), opts.CountPerCat, opts.MaxFiles)

	for i, file := range files {
		select {
		case <-ctx.Done():
			return manifest, ctx.Err()
		default:
		}

		target := destinations[i%len(destinations)]
		fullPath := FullPath(file)
		entry := SeedManifestEntry{
			Host:                target.Host,
			Share:               target.Share,
			Path:                fullPath,
			Category:            file.Category,
			Format:              formatLabel(file),
			IntendedAs:          file.IntendedAs,
			ExpectedClass:       file.ExpectedClass,
			ExpectedTriageClass: file.ExpectedTriageClass,
			ExpectedConfidence:  file.ExpectedConfidence,
			ExpectedCorrelated:  file.ExpectedCorrelated,
			ExpectedSignalTypes: append([]string{}, file.ExpectedSignalTypes...),
			ExpectedTags:        append([]string{}, file.ExpectedTags...),
			ExpectedRuleThemes:  append([]string{}, file.ExpectedRuleThemes...),
			ExpectedSeverity:    file.ExpectedSeverity,
		}

		if opts.DryRun {
			entry.Status = "dry-run"
			stats.recordDryRun()
			logInfo(opts, "dry-run: would write %s/%s/%s [%s]", target.Host, target.Share, fullPath, file.Category)
			manifest.Add(entry)
			continue
		}

		client, err := pool.clientFor(target.Host)
		if err != nil {
			return manifest, err
		}

		same, err := client.FileContentEquals(target.Share, fullPath, file.Content)
		if err != nil {
			return manifest, fmt.Errorf("%s/%s/%s: compare failed: %w", target.Host, target.Share, fullPath, err)
		}
		if same {
			entry.Status = "unchanged"
			stats.recordSkipped()
			logInfo(opts, "unchanged: %s/%s/%s", target.Host, target.Share, fullPath)
			manifest.Add(entry)
			continue
		}
		if err := client.WriteFile(target.Share, fullPath, file.Content); err != nil {
			return manifest, fmt.Errorf("%s/%s/%s: write failed: %w", target.Host, target.Share, fullPath, err)
		}
		entry.Status = "written"
		stats.recordWritten(file.Category, target.Host, target.Share)
		logInfo(opts, "written: %s/%s/%s [%s]", target.Host, target.Share, fullPath, file.Category)
		manifest.Add(entry)
	}

	if err := manifest.Write(opts.ManifestOut); err != nil {
		return manifest, err
	}
	logSeedSummary(opts, stats, manifest)
	return manifest, nil
}

func discoverDestinations(ctx context.Context, opts WriteOptions) ([]ShareTarget, error) {
	shareAllow := buildShareAllowSet(opts.Shares)

	destinations := make([]ShareTarget, 0)
	seen := make(map[string]struct{})
	perHost := make(map[string]int)
	for _, host := range opts.Targets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		client := newSMBWriter()
		if err := client.Connect(host, opts.Username, opts.Password); err != nil {
			logWarn(opts, "connect failed for %s: %v", host, err)
			continue
		}

		shares, err := client.ListShares()
		if err != nil {
			_ = client.Close()
			logWarn(opts, "list shares failed for %s: %v", host, err)
			continue
		}
		sort.Slice(shares, func(i, j int) bool {
			return shares[i].Name < shares[j].Name
		})

		for _, share := range shares {
			hostKey := strings.ToLower(strings.TrimSpace(host))
			if opts.SharesPerTarget > 0 && perHost[hostKey] >= opts.SharesPerTarget {
				break
			}
			if !shouldIncludeSeedShare(share, shareAllow, opts.IncludeAdminShares) {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(host + "::" + share.Name))
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			perHost[hostKey]++
			destinations = append(destinations, ShareTarget{
				Host:  host,
				Share: share.Name,
			})
		}

		if err := client.Close(); err != nil {
			logWarn(opts, "close warning for %s: %v", host, err)
		}
	}

	sort.Slice(destinations, func(i, j int) bool {
		if destinations[i].Host == destinations[j].Host {
			return destinations[i].Share < destinations[j].Share
		}
		return destinations[i].Host < destinations[j].Host
	})

	return destinations, nil
}

func cleanSeedPrefix(ctx context.Context, destinations []ShareTarget, pool *seedClientPool, opts WriteOptions) error {
	prefix, err := safeCleanPrefix(opts.SeedPrefix)
	if err != nil {
		return err
	}

	for _, target := range destinations {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if opts.DryRun {
			logInfo(opts, "dry-run: would clean %s/%s/%s", target.Host, target.Share, prefix)
			continue
		}

		client, err := pool.clientFor(target.Host)
		if err != nil {
			return fmt.Errorf("connect failed during cleanup for %s: %w", target.Host, err)
		}
		if err := client.RemoveAll(target.Share, prefix); err != nil {
			return fmt.Errorf("%s/%s/%s: cleanup failed: %w", target.Host, target.Share, prefix, err)
		}
		logInfo(opts, "cleaned: %s/%s/%s", target.Host, target.Share, prefix)
	}
	return nil
}

func buildShareAllowSet(shares []string) map[string]struct{} {
	shareAllow := make(map[string]struct{}, len(shares))
	for _, share := range shares {
		share = normalizeShareName(share)
		if share != "" {
			shareAllow[share] = struct{}{}
		}
	}
	return shareAllow
}

func shouldIncludeSeedShare(share smb.ShareInfo, shareAllow map[string]struct{}, includeAdminShares bool) bool {
	name := normalizeShareName(share.Name)
	if name == "" {
		return false
	}
	if len(shareAllow) > 0 {
		_, ok := shareAllow[name]
		return ok
	}
	if !includeAdminShares && smb.IsAdministrativeShare(share.Name) {
		return false
	}
	return true
}

func normalizeShareName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeHostKey(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func shareSummaryKey(host, share string) string {
	host = strings.TrimSpace(host)
	share = strings.TrimSpace(share)
	switch {
	case host == "" && share == "":
		return ""
	case host == "":
		return share
	case share == "":
		return host
	default:
		return host + "/" + share
	}
}

func logSeedSummary(opts WriteOptions, stats *seedRunStats, manifest Manifest) {
	if stats == nil {
		return
	}
	logInfo(opts, "seed summary: candidates=%d written=%d skipped=%d dry-run=%d manifest-entries=%d",
		stats.Candidates, stats.Written, stats.Skipped, stats.DryRun, len(manifest.Entries))

	if len(stats.WrittenByCategory) > 0 {
		keys := make([]string, 0, len(stats.WrittenByCategory))
		for key := range stats.WrittenByCategory {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			logInfo(opts, "written by category: %s=%d", key, stats.WrittenByCategory[key])
		}
	}

	if len(stats.WrittenByShare) > 0 {
		keys := make([]string, 0, len(stats.WrittenByShare))
		for key := range stats.WrittenByShare {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			logInfo(opts, "written by share: %s=%d", key, stats.WrittenByShare[key])
		}
	}
}

func logInfo(opts WriteOptions, format string, args ...any) {
	if opts.Logf != nil {
		opts.Logf(format, args...)
	}
}

func logWarn(opts WriteOptions, format string, args ...any) {
	if opts.Warnf != nil {
		opts.Warnf(format, args...)
		return
	}
	if opts.Logf != nil {
		opts.Logf(format, args...)
	}
}
