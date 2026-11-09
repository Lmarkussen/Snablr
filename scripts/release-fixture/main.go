// Command release-fixture creates a disposable SQLite database for release
// archive smoke tests. It only writes synthetic data to the requested path.
package main

import (
	"fmt"
	"os"
	"time"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: release-fixture PATH")
		os.Exit(2)
	}

	now := time.Now().UTC()
	state, err := store.Open(os.Args[1], store.Options{
		ScanID:        "synthetic-release-smoke",
		SnablrVersion: "synthetic",
	})
	if err != nil {
		fail(err)
	}
	defer state.Close()

	steps := []func() error{
		func() error { return state.RecordTarget("synthetic-host", "complete", now) },
		func() error { return state.RecordShare("synthetic-host", "SyntheticShare", "complete", now) },
		func() error {
			return state.RecordFile("synthetic-file", "synthetic-host", "SyntheticShare", "Synthetic/config.txt", "complete", "synthetic", 42, now, now, now, now)
		},
		func() error {
			return state.RecordFinding(scanner.Finding{
				Host:        "synthetic-host",
				Share:       "SyntheticShare",
				FilePath:    "Synthetic/config.txt",
				RuleID:      "synthetic.rule",
				Category:    "Synthetic",
				Severity:    "low",
				MatchedText: "synthetic fixture only",
			})
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			fail(err)
		}
	}
	if err := state.Close(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
