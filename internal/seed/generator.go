package seed

import (
	"fmt"
	"math/rand"
	"strings"
)

func Generate(opts GenerateOptions) ([]SeedFile, error) {
	if opts.CountPerCategory <= 0 {
		opts.CountPerCategory = 3
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 120
	}
	opts.SeedPrefix = normalizeSeedPrefix(opts.SeedPrefix)

	rng := rand.New(rand.NewSource(opts.RandomSeed))
	specs := defaultTemplates()
	out := make([]SeedFile, 0, opts.MaxFiles)

	for _, spec := range specs {
		for i := 0; i < opts.CountPerCategory; i++ {
			if len(out) >= opts.MaxFiles {
				return out, nil
			}
			format := spec.Formats[i%len(spec.Formats)]
			dir := spec.Directories[i%len(spec.Directories)]
			prefix := spec.FilenamePrefixes[i%len(spec.FilenamePrefixes)]
			filename := buildFilename(prefix, format, i)
			token := fmt.Sprintf("%03d_%04d", i+1, rng.Intn(10000))
			content := spec.Render(renderContext{
				Index:    i,
				Format:   format,
				Filename: filename,
				Token:    token,
			})

			out = append(out, SeedFile{
				Category:           spec.Category,
				Format:             format,
				RelativePath:       joinSeedPath(opts.SeedPrefix, dir),
				Filename:           filename,
				Content:            content,
				ExpectedTags:       append([]string{}, spec.ExpectedTags...),
				ExpectedRuleThemes: append([]string{}, spec.ExpectedRuleThemes...),
				ExpectedSeverity:   spec.ExpectedSeverity,
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
