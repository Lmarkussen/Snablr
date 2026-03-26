package config

import (
	"fmt"
	"strings"
)

type OutputFormatSelection struct {
	Console bool
	JSON    bool
	HTML    bool
}

func ParseOutputFormat(raw string) (OutputFormatSelection, error) {
	var selection OutputFormatSelection

	for _, part := range strings.Split(strings.TrimSpace(raw), ",") {
		token := strings.ToLower(strings.TrimSpace(part))
		if token == "" {
			continue
		}
		switch token {
		case "all":
			selection.Console = true
			selection.JSON = true
			selection.HTML = true
		case "console":
			selection.Console = true
		case "json":
			selection.JSON = true
		case "html":
			selection.HTML = true
		default:
			return OutputFormatSelection{}, fmt.Errorf("unsupported output format %q: use console, json, html, all, or a comma-separated combination like html,json", raw)
		}
	}

	if !selection.Console && !selection.JSON && !selection.HTML {
		return OutputFormatSelection{}, fmt.Errorf("unsupported output format %q: use console, json, html, all, or a comma-separated combination like html,json", raw)
	}

	return selection, nil
}
