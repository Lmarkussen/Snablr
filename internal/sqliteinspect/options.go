package sqliteinspect

import "fmt"

func New(opts Options) Inspector {
	opts = resolveOptions(opts)
	return Inspector{opts: opts}
}

func resolveOptions(opts Options) Options {
	if opts == (Options{}) {
		opts.Enabled = true
	}
	if opts.AutoDBMaxSize <= 0 {
		opts.AutoDBMaxSize = 5 * 1024 * 1024
	}
	if opts.MaxDBSize <= 0 {
		opts.MaxDBSize = opts.AutoDBMaxSize
	}
	if opts.MaxTables <= 0 {
		opts.MaxTables = 8
	}
	if opts.MaxRowsPerTable <= 0 {
		opts.MaxRowsPerTable = 5
	}
	if opts.MaxCellBytes <= 0 {
		opts.MaxCellBytes = 256
	}
	if opts.MaxTotalBytes <= 0 {
		opts.MaxTotalBytes = 16 * 1024
	}
	if opts.MaxInterestingCols <= 0 {
		opts.MaxInterestingCols = 4
	}
	return opts
}

func ShouldInspect(candidate Candidate, opts Options) (bool, string) {
	opts = resolveOptions(opts)
	ext := normalizedExtension(candidate.Extension)
	if !isSQLiteCandidateExtension(ext) {
		return false, ""
	}
	if !opts.Enabled {
		return false, "sqlite inspection disabled"
	}
	if opts.AutoDBMaxSize > 0 && candidate.Size <= opts.AutoDBMaxSize {
		return true, ""
	}
	if !opts.AllowLargeDBs {
		if opts.AutoDBMaxSize > 0 {
			return false, fmt.Sprintf("sqlite database exceeds automatic inspection limit of %d bytes", opts.AutoDBMaxSize)
		}
		return false, "sqlite inspection requires an explicit database size limit"
	}
	if opts.MaxDBSize > 0 && candidate.Size > opts.MaxDBSize {
		return false, fmt.Sprintf("sqlite database exceeds configured inspection limit of %d bytes", opts.MaxDBSize)
	}
	return true, ""
}
