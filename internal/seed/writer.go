package seed

import (
	"context"
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

func Seed(ctx context.Context, opts WriteOptions) (Manifest, error) {
	prefix, err := safeCleanPrefix(opts.SeedPrefix)
	if err != nil {
		return Manifest{}, err
	}
	opts.SeedPrefix = prefix

	files, err := Generate(GenerateOptions{
		CountPerCategory: opts.CountPerCat,
		MaxFiles:         opts.MaxFiles,
		SeedPrefix:       opts.SeedPrefix,
		RandomSeed:       opts.RandomSeed,
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
	if opts.CleanPrefix {
		if err := cleanSeedPrefix(ctx, destinations, opts); err != nil {
			return manifest, err
		}
	}

	for i, file := range files {
		select {
		case <-ctx.Done():
			return manifest, ctx.Err()
		default:
		}

		target := destinations[i%len(destinations)]
		fullPath := FullPath(file)
		entry := SeedManifestEntry{
			Host:               target.Host,
			Share:              target.Share,
			Path:               fullPath,
			Category:           file.Category,
			Format:             formatLabel(file),
			ExpectedTags:       append([]string{}, file.ExpectedTags...),
			ExpectedRuleThemes: append([]string{}, file.ExpectedRuleThemes...),
			ExpectedSeverity:   file.ExpectedSeverity,
		}

		if opts.DryRun {
			entry.Status = "dry-run"
			logInfo(opts, "dry-run: would write %s/%s/%s [%s]", target.Host, target.Share, fullPath, file.Category)
			manifest.Add(entry)
			continue
		}

		client := smb.NewClient()
		if err := client.Connect(target.Host, opts.Username, opts.Password); err != nil {
			return manifest, fmt.Errorf("%s: connect failed: %w", target.Host, err)
		}

		same, err := client.FileContentEquals(target.Share, fullPath, file.Content)
		if err != nil {
			_ = client.Close()
			return manifest, fmt.Errorf("%s/%s/%s: compare failed: %w", target.Host, target.Share, fullPath, err)
		}
		if same {
			entry.Status = "unchanged"
			logInfo(opts, "unchanged: %s/%s/%s", target.Host, target.Share, fullPath)
			manifest.Add(entry)
			_ = client.Close()
			continue
		}
		if err := client.WriteFile(target.Share, fullPath, file.Content); err != nil {
			_ = client.Close()
			return manifest, fmt.Errorf("%s/%s/%s: write failed: %w", target.Host, target.Share, fullPath, err)
		}
		entry.Status = "written"
		logInfo(opts, "written: %s/%s/%s [%s]", target.Host, target.Share, fullPath, file.Category)
		manifest.Add(entry)
		if err := client.Close(); err != nil {
			logWarn(opts, "close warning for %s: %v", target.Host, err)
		}
	}

	if err := manifest.Write(opts.ManifestOut); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func discoverDestinations(ctx context.Context, opts WriteOptions) ([]ShareTarget, error) {
	shareAllow := make(map[string]struct{}, len(opts.Shares))
	for _, share := range opts.Shares {
		share = strings.ToLower(strings.TrimSpace(share))
		if share != "" {
			shareAllow[share] = struct{}{}
		}
	}

	destinations := make([]ShareTarget, 0)
	seen := make(map[string]struct{})
	for _, host := range opts.Targets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		client := smb.NewClient()
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

		for _, share := range shares {
			key := strings.ToLower(strings.TrimSpace(host + "::" + share.Name))
			if key == "" {
				continue
			}
			if len(shareAllow) > 0 {
				if _, ok := shareAllow[strings.ToLower(strings.TrimSpace(share.Name))]; !ok {
					continue
				}
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
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

func cleanSeedPrefix(ctx context.Context, destinations []ShareTarget, opts WriteOptions) error {
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

		client := smb.NewClient()
		if err := client.Connect(target.Host, opts.Username, opts.Password); err != nil {
			return fmt.Errorf("%s: connect failed during cleanup: %w", target.Host, err)
		}
		if err := client.RemoveAll(target.Share, prefix); err != nil {
			_ = client.Close()
			return fmt.Errorf("%s/%s/%s: cleanup failed: %w", target.Host, target.Share, prefix, err)
		}
		logInfo(opts, "cleaned: %s/%s/%s", target.Host, target.Share, prefix)
		if err := client.Close(); err != nil {
			logWarn(opts, "close warning for %s: %v", target.Host, err)
		}
	}
	return nil
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
