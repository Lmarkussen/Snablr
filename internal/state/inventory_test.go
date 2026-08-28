package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var inventoryTestTime = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func inventoryTestObservation(name string) FileObservation {
	return FileObservation{
		Server:     "FS01.",
		Share:      "Finance",
		Path:       `reports\\` + name,
		Size:       10,
		ModifiedAt: inventoryTestTime,
	}
}

func prepareCompleted(t *testing.T, inventory *Inventory, observation FileObservation, contextID, semantics string) SkipDecision {
	t.Helper()
	decision, err := inventory.Prepare(observation, contextID, semantics, false)
	if err != nil {
		t.Fatalf("Prepare returned error: %v", err)
	}
	inventory.MarkScanning(decision.Key)
	inventory.MarkCompleted(decision.Key)
	return decision
}

func TestInventoryFirstAndUnchangedRuns(t *testing.T) {
	inventory, err := OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatalf("OpenInventory returned error: %v", err)
	}
	observation := inventoryTestObservation("file-a.txt")
	contextID := CredentialContextID("password", "user-a", "DOMAIN")
	semantics := SemanticsFingerprint(struct{ Profile string }{"default"})
	prepareCompleted(t, inventory, observation, contextID, semantics)
	if err := inventory.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := OpenInventory(inventory.Path())
	if err != nil {
		t.Fatalf("reload returned error: %v", err)
	}
	decision, err := loaded.Prepare(observation, contextID, semantics, false)
	if err != nil {
		t.Fatalf("second Prepare returned error: %v", err)
	}
	if !decision.Skip || decision.Reason != "unchanged completed object" {
		t.Fatalf("second run decision = %#v, want unchanged skip", decision)
	}
	stats := loaded.Stats()
	if stats.Discovered != 1 || stats.SkippedUnchanged != 1 || stats.Inspected != 0 {
		t.Fatalf("second run stats = %#v", stats)
	}
}

func TestInventoryPivotRecordsAccessButSkipsContent(t *testing.T) {
	inventory, err := OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	observation := inventoryTestObservation("common.txt")
	semantics := "same-semantics"
	prepareCompleted(t, inventory, observation, CredentialContextID("password", "user-a", "domain"), semantics)

	decision, err := inventory.Prepare(observation, CredentialContextID("ntlm-hash", "user-b", "domain"), semantics, false)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Skip || !decision.KnownObject || !decision.NewAccessObservation {
		t.Fatalf("pivot decision = %#v, want known object/new access/skip", decision)
	}
	if stats := inventory.Stats(); stats.NewAccessibleKnown != 1 {
		t.Fatalf("new access counter changed for skipped known object: %#v", stats)
	}

	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(inventory.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "user-a") || strings.Contains(string(data), "user-b") || strings.Contains(string(data), "domain") {
		t.Fatalf("inventory persisted principal metadata: %s", data)
	}
}

func TestInventoryRescansChangedFailedPartialAndSemanticMismatch(t *testing.T) {
	inventory, err := OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	contextID := CredentialContextID("password", "user", "domain")
	semantics := "semantics-a"
	observation := inventoryTestObservation("file.txt")
	decision := prepareCompleted(t, inventory, observation, contextID, semantics)

	changedSize := observation
	changedSize.Size++
	rescan, err := inventory.Prepare(changedSize, contextID, semantics, false)
	if err != nil || rescan.Skip || rescan.Reason != "object metadata changed" {
		t.Fatalf("size change decision = %#v, err=%v", rescan, err)
	}
	inventory.MarkFailed(decision.Key)
	retry, err := inventory.Prepare(changedSize, contextID, semantics, false)
	if err != nil || retry.Skip || retry.Reason != "retry failed object" {
		t.Fatalf("failed retry decision = %#v, err=%v", retry, err)
	}
	inventory.MarkPartial(retry.Key)
	partial, err := inventory.Prepare(changedSize, contextID, semantics, false)
	if err != nil || partial.Skip || partial.Reason != "retry partial object" {
		t.Fatalf("partial retry decision = %#v, err=%v", partial, err)
	}
	inventory.MarkCompleted(partial.Key)

	changedTime := changedSize
	changedTime.ModifiedAt = inventoryTestTime.Add(time.Minute)
	mtime, err := inventory.Prepare(changedTime, contextID, semantics, false)
	if err != nil || mtime.Skip || mtime.Reason != "object metadata changed" {
		t.Fatalf("mtime change decision = %#v, err=%v", mtime, err)
	}
	inventory.MarkCompleted(mtime.Key)
	semantic, err := inventory.Prepare(changedTime, contextID, "semantics-b", false)
	if err != nil || semantic.Skip || semantic.Reason != "scan semantics changed" {
		t.Fatalf("semantic change decision = %#v, err=%v", semantic, err)
	}
	forced, err := inventory.Prepare(changedTime, contextID, "semantics-b", true)
	if err != nil || forced.Skip || forced.Reason != "operator forced rescan" {
		t.Fatalf("forced decision = %#v, err=%v", forced, err)
	}
	if stats := inventory.Stats(); stats.RescannedChanged < 2 || stats.Retried < 2 {
		t.Fatalf("rescan stats = %#v", stats)
	}
}

func TestInventoryDoesNotSkipWhenTimestampUnknown(t *testing.T) {
	inventory, err := OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	observation := inventoryTestObservation("unknown-time.txt")
	contextID := CredentialContextID("password", "user", "domain")
	prepareCompleted(t, inventory, observation, contextID, "semantics")
	observation.ModifiedAt = time.Time{}
	decision, err := inventory.Prepare(observation, contextID, "semantics", false)
	if err != nil || decision.Skip {
		t.Fatalf("unknown timestamp decision = %#v, err=%v; expected fail-open rescan", decision, err)
	}
}

func TestInventoryNewShareAndChangedWIMRemainInspectable(t *testing.T) {
	inventory, err := OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	contextID := CredentialContextID("password", "user", "domain")
	wim := inventoryTestObservation("Images/Tier-01/valid-sam-system.wim")
	first := prepareCompleted(t, inventory, wim, contextID, "wim-semantics")
	unchanged, err := inventory.Prepare(wim, contextID, "wim-semantics", false)
	if err != nil || !unchanged.Skip {
		t.Fatalf("unchanged WIM decision = %#v, err=%v", unchanged, err)
	}
	changed := wim
	changed.Size++
	rescan, err := inventory.Prepare(changed, contextID, "wim-semantics", false)
	if err != nil || rescan.Skip {
		t.Fatalf("changed WIM decision = %#v, err=%v", rescan, err)
	}
	inventory.MarkCompleted(first.Key)
	otherShare := changed
	otherShare.Share = "Secret"
	other, err := inventory.Prepare(otherShare, contextID, "wim-semantics", false)
	if err != nil || other.Skip {
		t.Fatalf("new share decision = %#v, err=%v", other, err)
	}
}

func TestInventoryNormalizationPreservesPathCaseAndSeparatesTargets(t *testing.T) {
	if got := NormalizeServer("FS01."); got != "fs01" {
		t.Fatalf("NormalizeServer = %q", got)
	}
	if got := NormalizeShare(`\\Finance\\`); got != "finance" {
		t.Fatalf("NormalizeShare = %q", got)
	}
	if got := NormalizePath(`\\Reports\\.\\Quarterly\\..\\Payroll.XLSX\\`); got != "Reports/Payroll.XLSX" {
		t.Fatalf("NormalizePath = %q", got)
	}
	first := ObjectIdentity{Server: "fs01", Share: "share", Path: "a"}
	second := ObjectIdentity{Server: "fs02", Share: "share", Path: "a"}
	if first.Key() == second.Key() {
		t.Fatal("different servers must not share an object key")
	}
}

func TestInventoryCorruptAndUnknownStateFailsOpenToCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInventory(path); err == nil {
		t.Fatal("expected corrupt inventory error")
	}
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInventory(path); err == nil {
		t.Fatal("expected unknown inventory version error")
	}
}

func TestInventoryAtomicSnapshotSurvivesInterruptedTempWrite(t *testing.T) {
	dir := t.TempDir()
	inventory, err := OpenInventory(filepath.Join(dir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	prepareCompleted(t, inventory, inventoryTestObservation("stable.txt"), "ctx-a", "semantics")
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inventory.json.tmp"), []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenInventory(filepath.Join(dir, "inventory.json"))
	if err != nil {
		t.Fatalf("old atomic snapshot should remain readable: %v", err)
	}
	decision, err := loaded.Prepare(inventoryTestObservation("stable.txt"), "ctx-a", "semantics", false)
	if err != nil || !decision.Skip {
		t.Fatalf("atomic snapshot decision = %#v, err=%v", decision, err)
	}
}

func TestInventoryQueuedAndScanningObjectsAreRetriedAfterReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	inventory, err := OpenInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	observation := inventoryTestObservation("interrupted.txt")
	first, err := inventory.Prepare(observation, "ctx", "semantics", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	retryQueued, err := loaded.Prepare(observation, "ctx", "semantics", false)
	if err != nil || retryQueued.Skip || retryQueued.Reason != "retry interrupted object" {
		t.Fatalf("queued retry = %#v, err=%v", retryQueued, err)
	}
	loaded.MarkScanning(first.Key)
	if err := loaded.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err = OpenInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	retryScanning, err := loaded.Prepare(observation, "ctx", "semantics", false)
	if err != nil || retryScanning.Skip || retryScanning.Reason != "retry interrupted object" {
		t.Fatalf("scanning retry = %#v, err=%v", retryScanning, err)
	}
}

func TestInventoryConcurrentCompletions(t *testing.T) {
	inventory, err := OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			observation := inventoryTestObservation("file-" + string(rune('a'+i%26)) + "-" + formatTestInt(i))
			decision, err := inventory.Prepare(observation, "ctx", "semantics", false)
			if err != nil {
				t.Errorf("Prepare returned error: %v", err)
				return
			}
			inventory.MarkScanning(decision.Key)
			inventory.MarkCompleted(decision.Key)
		}()
	}
	wg.Wait()
	if stats := inventory.Stats(); stats.Discovered != 100 || stats.Inspected != 100 {
		t.Fatalf("concurrent stats = %#v", stats)
	}
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}
}

func formatTestInt(value int) string {
	return fmt.Sprintf("%03d", value)
}
