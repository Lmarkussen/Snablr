package config

func Default() Config {
	cfg := Config{
		App: AppConfig{
			Name:       "snablr",
			LogLevel:   "info",
			BannerPath: "internal/ui/assets/snablr.txt",
		},
		Scan: ScanConfig{
			Share:                      nil,
			ExcludeShare:               nil,
			Path:                       nil,
			ExcludePath:                nil,
			MaxDepth:                   0,
			WorkerCount:                0,
			MaxFileSize:                10 * 1024 * 1024,
			NoLDAP:                     false,
			Domain:                     "",
			DomainController:           "",
			BaseDN:                     "",
			DiscoverDFS:                false,
			PrioritizeADShares:         true,
			OnlyADShares:               false,
			Baseline:                   "",
			MaxScanTime:                "",
			CheckpointFile:             "",
			Resume:                     false,
			SkipReachabilityCheck:      false,
			ReachabilityTimeoutSeconds: 3,
		},
		Archives: ArchiveConfig{
			Enabled:                  true,
			AutoZIPMaxSize:           10 * 1024 * 1024,
			AllowLargeZIPs:           false,
			MaxZIPSize:               10 * 1024 * 1024,
			MaxMembers:               64,
			MaxMemberBytes:           512 * 1024,
			MaxTotalUncompressed:     4 * 1024 * 1024,
			InspectExtensionlessText: true,
		},
		Rules: RulesConfig{
			Directory:     "",
			FailOnInvalid: false,
		},
		Output: OutputConfig{
			Format:  "console",
			JSONOut: "results.json",
			HTMLOut: "report.html",
			CSVOut:  "",
			MDOut:   "",
			Pretty:  true,
		},
	}
	applyPathContext(&cfg, "")
	return cfg
}
