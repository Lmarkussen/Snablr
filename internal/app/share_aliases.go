package app

import (
	"sort"
	"strings"

	"snablr/internal/planner"
)

// nestedShare is a folder inside one scanned share that another scanned share
// exports.
type nestedShare struct {
	Folder string // path inside the outer share, slash separated
	Share  string // the share that exports it
}

// nestedShareFolders finds, for each planned share, the folders inside it
// that other planned shares export, using the local paths the server
// reported. Those folders are walked once, as the more specific share, so the
// same files are not reported under both names (C$\software_dist and software_dist).
// Shares outside the plan are ignored: their folders stay in the outer share.
func nestedShareFolders(planned []planner.PlannedTarget, paths map[string]string) map[string][]nestedShare {
	if len(paths) == 0 {
		return nil
	}
	type exported struct{ share, path, cmp string }
	var shares []exported
	for _, plan := range planned {
		local := strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(paths[strings.ToLower(plan.Share)]), "/", `\`), `\`)
		if local == "" {
			continue
		}
		shares = append(shares, exported{share: plan.Share, path: local, cmp: strings.ToLower(local)})
	}
	out := make(map[string][]nestedShare)
	for _, outer := range shares {
		for _, inner := range shares {
			if inner.share == outer.share || !strings.HasPrefix(inner.cmp, outer.cmp+`\`) {
				continue
			}
			folder := strings.ReplaceAll(inner.path[len(outer.path)+1:], `\`, "/")
			key := strings.ToLower(outer.share)
			out[key] = append(out[key], nestedShare{Folder: folder, Share: inner.share})
		}
	}
	for key := range out {
		sort.Slice(out[key], func(i, j int) bool { return out[key][i].Folder < out[key][j].Folder })
	}
	return out
}
