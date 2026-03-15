package version

import (
	"fmt"
	"strings"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func Short() string {
	if strings.TrimSpace(Version) == "" {
		return "dev"
	}
	return Version
}

func String() string {
	return fmt.Sprintf("Snablr %s (commit: %s, built: %s)", Short(), valueOrUnknown(Commit), valueOrUnknown(BuildDate))
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}
