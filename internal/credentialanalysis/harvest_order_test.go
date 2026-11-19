package credentialanalysis

import (
	"fmt"
	"strings"
	"testing"
)

// Harvesting the same file gives the same candidates in the same order every
// time, so the finding that names the first confirmed credential, and every
// finding that cites it, stays the same across scans.
func TestHarvestOrderIsStableAcrossRuns(t *testing.T) {
	var ini, env strings.Builder
	var json []string
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&ini, "[service_%02d]\nuser = synthetic-user-%02d\npassword = Synthetic-Secret-%02d!\n\n", i, i, i)
		fmt.Fprintf(&env, "APP%02d_USERNAME=synthetic-env-%02d\nAPP%02d_PASSWORD=Synthetic-Env-%02d!\n", i, i, i, i)
		json = append(json, fmt.Sprintf(`"svc%02d": {"username": "synthetic-json-%02d", "password": "Synthetic-Json-%02d!"}`, i, i, i))
	}
	files := map[string]string{
		"settings.ini": ini.String(),
		"service.env":  env.String(),
		"config.json":  "{" + strings.Join(json, ",") + "}",
	}
	for name, content := range files {
		var first string
		for run := 0; run < 30; run++ {
			candidates := Harvest(HarvestInput{Content: []byte(content), Path: "share/" + name})
			var order []string
			for _, candidate := range candidates {
				order = append(order, candidate.Identity+"="+candidate.Value)
			}
			got := strings.Join(order, ",")
			if run == 0 {
				first = got
				if len(candidates) < 8 {
					t.Fatalf("%s: harvested %d candidates, want at least 8", name, len(candidates))
				}
				continue
			}
			if got != first {
				t.Fatalf("%s: candidate order changed between runs:\n%s\n%s", name, first, got)
			}
		}
	}
}
