package output

import "snablr/internal/config"

type liveSinkMode string

const (
	liveSinkNone    liveSinkMode = "none"
	liveSinkConsole liveSinkMode = "console"
	liveSinkTUI     liveSinkMode = "tui"
)

func determineLiveSinkMode(format string, noTUI bool, interactive bool) liveSinkMode {
	selection, err := config.ParseOutputFormat(format)
	if err != nil {
		return liveSinkNone
	}
	if interactive && !noTUI {
		return liveSinkTUI
	}
	if noTUI {
		return liveSinkConsole
	}
	if selection.Console {
		return liveSinkConsole
	}
	return liveSinkNone
}
