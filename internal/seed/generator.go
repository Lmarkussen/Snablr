package seed

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
)

func Generate(opts GenerateOptions) ([]SeedFile, error) {
	if opts.CountPerCategory <= 0 {
		opts.CountPerCategory = 6
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 480
	}
	if opts.Depth < 0 {
		opts.Depth = 0
	}

	if opts.LikelyHitRatio == 0 && opts.FilenameOnlyRatio == 0 && opts.HighSeverityRatio == 0 && opts.MediumSeverityRatio == 0 {
		opts.LikelyHitRatio = 65
		opts.HighSeverityRatio = 35
		opts.MediumSeverityRatio = 45
	}
	if opts.LikelyHitRatio < 0 {
		opts.LikelyHitRatio = 0
	}
	if opts.LikelyHitRatio > 100 {
		opts.LikelyHitRatio = 100
	}
	if opts.FilenameOnlyRatio < 0 {
		opts.FilenameOnlyRatio = 0
	}
	if opts.FilenameOnlyRatio > 100 {
		opts.FilenameOnlyRatio = 100
	}
	if opts.HighSeverityRatio < 0 {
		opts.HighSeverityRatio = 0
	}
	if opts.HighSeverityRatio > 100 {
		opts.HighSeverityRatio = 100
	}
	if opts.MediumSeverityRatio < 0 {
		opts.MediumSeverityRatio = 0
	}
	if opts.MediumSeverityRatio > 100 {
		opts.MediumSeverityRatio = 100
	}
	opts.SeedPrefix = normalizeSeedPrefix(opts.SeedPrefix)

	rng := rand.New(rand.NewSource(opts.RandomSeed))
	specs := defaultTemplates()
	sort.Slice(specs, func(i, j int) bool { return specs[i].Category < specs[j].Category })
	out := make([]SeedFile, 0, opts.MaxFiles)

	for _, spec := range specs {
		if len(spec.Variants) == 0 {
			continue
		}
		for i := 0; i < opts.CountPerCategory; i++ {
			if len(out) >= opts.MaxFiles {
				return out, nil
			}
			dir := spec.Directories[i%len(spec.Directories)]
			token := fmt.Sprintf("%03d_%04d", i+1, rng.Intn(10000))
			persona := chooseValue(spec.Personas, i)
			label := chooseValue(spec.Labels, i)
			serviceAccount := chooseValue(spec.ServiceAccounts, i)
			fullDir := applyDepth(dir, opts.Depth, i, spec.Category, persona)
			variant := pickVariant(spec.Variants, opts, i)
			content := spec.Render(renderContext{
				Index:          i,
				Format:         variant.Format,
				Filename:       variant.Filename,
				Token:          token,
				Category:       spec.Category,
				Directory:      fullDir,
				Persona:        persona,
				PersonaDisplay: displayName(persona),
				ServiceAccount: serviceAccount,
				Label:          label,
				IntendedAs:     variant.IntendedAs,
				ContentStyle:   variant.ContentStyle,
			}, variant)

			out = append(out, SeedFile{
				Category:            spec.Category,
				Format:              variant.Format,
				RelativePath:        joinSeedPath(opts.SeedPrefix, fullDir),
				Filename:            variant.Filename,
				Content:             content,
				IntendedAs:          variant.IntendedAs,
				ExpectedSignalTypes: append([]string{}, variant.ExpectedSignalTypes...),
				ExpectedTags:        append([]string{}, variant.ExpectedTags...),
				ExpectedRuleThemes:  append([]string{}, variant.ExpectedRuleThemes...),
				ExpectedSeverity:    variant.ExpectedSeverity,
			})
		}
	}

	return out, nil
}

func FullPath(file SeedFile) string {
	return joinSeedPath(file.RelativePath, file.Filename)
}

func formatLabel(file SeedFile) string {
	format := strings.TrimSpace(file.Format)
	if format == "" {
		return "txt"
	}
	return format
}

func chooseValue(values []string, index int) string {
	if len(values) == 0 {
		return ""
	}
	return values[index%len(values)]
}

func pickVariant(variants []templateVariant, opts GenerateOptions, index int) templateVariant {
	intent := desiredIntent(opts, index)
	signalMode := desiredSignalMode(opts, index)
	severity := desiredSeverity(opts, index)

	if variant, ok := matchVariant(variants, intent, signalMode, severity, index); ok {
		return variant
	}
	if variant, ok := matchVariant(variants, intent, "", severity, index); ok {
		return variant
	}
	if variant, ok := matchVariant(variants, intent, signalMode, "", index); ok {
		return variant
	}
	if variant, ok := matchVariant(variants, intent, "", "", index); ok {
		return variant
	}
	return variants[index%len(variants)]
}

func matchVariant(variants []templateVariant, intent, signalMode, severity string, index int) (templateVariant, bool) {
	filtered := make([]templateVariant, 0, len(variants))
	for _, variant := range variants {
		if intent != "" && variant.IntendedAs != intent {
			continue
		}
		if severity != "" && variant.ExpectedSeverity != severity {
			continue
		}
		if signalMode != "" && !variantMatchesSignalMode(variant, signalMode) {
			continue
		}
		filtered = append(filtered, variant)
	}
	if len(filtered) == 0 {
		return templateVariant{}, false
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Filename == filtered[j].Filename {
			return filtered[i].Format < filtered[j].Format
		}
		return filtered[i].Filename < filtered[j].Filename
	})
	return filtered[index%len(filtered)], true
}

func variantMatchesSignalMode(variant templateVariant, signalMode string) bool {
	hasContent := false
	for _, signalType := range variant.ExpectedSignalTypes {
		if strings.EqualFold(signalType, "content") {
			hasContent = true
			break
		}
	}
	switch signalMode {
	case "filename-only":
		return !hasContent
	case "content-hit":
		return hasContent
	default:
		return true
	}
}

func desiredIntent(opts GenerateOptions, index int) string {
	bucket := index % 100
	likely := opts.LikelyHitRatio
	possible := 20
	if likely+possible > 100 {
		possible = max(0, 100-likely)
	}
	switch {
	case bucket < likely:
		return "likely-hit"
	case bucket < likely+possible:
		return "possible-hit"
	default:
		return "filler/noise"
	}
}

func desiredSignalMode(opts GenerateOptions, index int) string {
	if index%100 < opts.FilenameOnlyRatio {
		return "filename-only"
	}
	return "content-hit"
}

func desiredSeverity(opts GenerateOptions, index int) string {
	bucket := (index * 17) % 100
	switch {
	case bucket < opts.HighSeverityRatio:
		return "high"
	case bucket < opts.HighSeverityRatio+opts.MediumSeverityRatio:
		return "medium"
	default:
		return "low"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
