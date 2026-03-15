package ui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"snablr/internal/version"
)

const (
	colorReset  = "\033[0m"
	colorBright = "\033[97m"
)

var bannerGradient = []int{157, 120, 84, 78, 42, 36}

func PrintBanner(w io.Writer) {
	banner, err := LoadBanner("")
	if err != nil {
		printFallbackBanner(w)
		return
	}

	for i, line := range strings.Split(strings.TrimRight(banner, "\n"), "\n") {
		fmt.Fprintf(w, "%s%s%s\n", ansi256(bannerGradient[i%len(bannerGradient)]), line, colorReset)
	}
	fmt.Fprintf(w, "%sVersion : %s%s\n", ansi256(bannerGradient[0]), version.Short(), colorReset)
	fmt.Fprintf(w, "\n%sSnablr - SMB Share Triage Tool (%s)%s\n\n", colorBright, version.Short(), colorReset)
}

func LoadBanner(path string) (string, error) {
	resolved := resolveBannerPath(path)
	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func resolveBannerPath(path string) string {
	candidates := make([]string, 0, 6)
	if strings.TrimSpace(path) != "" {
		candidates = append(candidates, path)
	}

	candidates = append(candidates,
		"internal/ui/assets/snablr.txt",
		"snablr.txt",
		filepath.Join("assets", "snablr.txt"),
	)

	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(base, "internal", "ui", "assets", "snablr.txt"),
			filepath.Join(base, "snablr.txt"),
			filepath.Join(base, "assets", "snablr.txt"),
		)
	}

	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return candidates[0]
}

func printFallbackBanner(w io.Writer) {
	fallback := []string{
		"  _____             __    __    ",
		" / ___/____  ____ _/ /_  / /____",
		" \\__ \\/ __ \\/ __ `/ __ \\/ / ___/",
		"___/ / / / / /_/ / /_/ / / /    ",
		"/____/_/ /_/\\__,_/_.___/_/_/     ",
	}

	for i, line := range fallback {
		fmt.Fprintf(w, "%s%s%s\n", ansi256(bannerGradient[i%len(bannerGradient)]), line, colorReset)
	}
	fmt.Fprintf(w, "%sVersion : %s%s\n", ansi256(bannerGradient[0]), version.Short(), colorReset)
	fmt.Fprintf(w, "\n%sSnablr - SMB Share Triage Tool (%s)%s\n\n", colorBright, version.Short(), colorReset)
}

func ansi256(code int) string {
	return fmt.Sprintf("\033[38;5;%dm", code)
}
