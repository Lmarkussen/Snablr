package app

import (
	"fmt"
	"strings"
	"sync"

	"snablr/internal/output"
	"snablr/internal/planner"
)

var errShareDeferred = fmt.Errorf("share deferred by operator")

type shareScheduler struct {
	mu         sync.Mutex
	entries    map[string]*shareScheduleEntry
	order      []string
	current    string
	deferNext  bool
	skipShare  func(planner.PlannedTarget) error
	skipFolder func(planner.PlannedTarget, string) error
	currentDir string
}

type shareScheduleEntry struct {
	plan      planner.PlannedTarget
	deferred  bool
	completed bool
	skipped   bool
}

func newShareScheduler(plans []planner.PlannedTarget) *shareScheduler {
	scheduler := &shareScheduler{entries: make(map[string]*shareScheduleEntry, len(plans))}
	for _, plan := range plans {
		key := shareScheduleKey(plan.Host, plan.Share)
		if _, exists := scheduler.entries[key]; exists {
			continue
		}
		scheduler.entries[key] = &shareScheduleEntry{plan: plan}
		scheduler.order = append(scheduler.order, key)
	}
	return scheduler
}

func shareScheduleKey(host, share string) string {
	return strings.ToLower(strings.TrimSpace(host)) + "\x00" + strings.ToLower(strings.TrimSpace(share))
}

func (s *shareScheduler) next() (planner.PlannedTarget, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != "" {
		return s.entries[s.current].plan, true
	}
	for _, key := range s.order {
		entry := s.entries[key]
		if entry == nil || entry.completed || entry.skipped {
			continue
		}
		s.current = key
		s.currentDir = ""
		return entry.plan, true
	}
	return planner.PlannedTarget{}, false
}

func (s *shareScheduler) begin(plan planner.PlannedTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = shareScheduleKey(plan.Host, plan.Share)
	s.currentDir = ""
}

func (s *shareScheduler) complete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.entries[s.current]; entry != nil {
		if !entry.skipped {
			entry.completed = true
		}
	}
	s.current = ""
	s.currentDir = ""
	s.deferNext = false
}

func (s *shareScheduler) setSkipHandlers(share func(planner.PlannedTarget) error, folder func(planner.PlannedTarget, string) error) {
	s.mu.Lock()
	s.skipShare, s.skipFolder = share, folder
	s.mu.Unlock()
}

func (s *shareScheduler) setCurrentDirectory(path string) {
	s.mu.Lock()
	s.currentDir = path
	s.mu.Unlock()
}

func (s *shareScheduler) shouldDescend(string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == "" {
		return true
	}
	entry := s.entries[s.current]
	return entry != nil && !entry.skipped
}

func (s *shareScheduler) isCurrentSkipped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[s.current]
	return entry != nil && entry.skipped
}

func (s *shareScheduler) requestSkipShare() string {
	s.mu.Lock()
	if s.current == "" || s.entries[s.current] == nil || s.entries[s.current].completed {
		s.mu.Unlock()
		return "No active share to skip"
	}
	key, plan, handler := s.current, s.entries[s.current].plan, s.skipShare
	s.mu.Unlock()
	if handler == nil {
		return "Persistent share skipping is unavailable"
	}
	if err := handler(plan); err != nil {
		return fmt.Sprintf("Could not skip \\\\%s\\%s: %v", plan.Host, plan.Share, err)
	}
	s.mu.Lock()
	if entry := s.entries[key]; entry != nil {
		entry.skipped = true
	}
	s.mu.Unlock()
	return fmt.Sprintf("Skipped share \\\\%s\\%s", plan.Host, plan.Share)
}

func (s *shareScheduler) requestSkipFolder() string {
	s.mu.Lock()
	if s.current == "" || s.entries[s.current] == nil || s.entries[s.current].completed {
		s.mu.Unlock()
		return "No active folder to skip"
	}
	plan, path, handler := s.entries[s.current].plan, s.currentDir, s.skipFolder
	s.mu.Unlock()
	if path == "" {
		return "No active traversal folder to skip"
	}
	if handler == nil {
		return "Persistent folder skipping is unavailable"
	}
	if err := handler(plan, path); err != nil {
		return fmt.Sprintf("Could not skip folder \\\\%s\\%s\\%s: %v", plan.Host, plan.Share, path, err)
	}
	return fmt.Sprintf("Skipped folder \\\\%s\\%s\\%s", plan.Host, plan.Share, path)
}

func (s *shareScheduler) requestDefer() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == "" {
		return "No active share to defer"
	}
	entry := s.entries[s.current]
	if entry == nil || entry.completed {
		return "No active share to defer"
	}
	if s.isLastRemainingLocked(s.current) {
		return fmt.Sprintf("%s is already the last remaining share", entry.plan.Share)
	}
	if entry.deferred && s.order[len(s.order)-1] == s.current {
		return fmt.Sprintf("%s is already last", entry.plan.Share)
	}
	entry.deferred = true
	for index, key := range s.order {
		if key != s.current {
			continue
		}
		s.order = append(append(s.order[:index], s.order[index+1:]...), key)
		break
	}
	s.deferNext = true
	return fmt.Sprintf("Deferred %s to end of queue", entry.plan.Share)
}

func (s *shareScheduler) isLastRemainingLocked(current string) bool {
	remaining := 0
	for _, key := range s.order {
		entry := s.entries[key]
		if entry != nil && !entry.completed {
			remaining++
			if key != current && remaining > 1 {
				return false
			}
		}
	}
	return remaining <= 1
}

func (s *shareScheduler) consumeDefer(plan planner.PlannedTarget) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != shareScheduleKey(plan.Host, plan.Share) || !s.deferNext {
		return false
	}
	s.deferNext = false
	s.current = ""
	s.currentDir = ""
	return true
}

func (s *shareScheduler) snapshot() output.ShareQueueSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := output.ShareQueueSnapshot{DeferredCount: 0, Items: make([]output.ShareQueueItem, 0, len(s.order))}
	if current := s.entries[s.current]; current != nil {
		snapshot.CurrentHost = current.plan.Host
		snapshot.CurrentShare = current.plan.Share
		snapshot.CurrentDirectory = s.currentDir
	}
	for _, key := range s.order {
		entry := s.entries[key]
		if entry == nil {
			continue
		}
		state := "pending"
		if entry.completed {
			state = "completed"
		} else if entry.skipped {
			state = "skipped"
		} else if key == s.current {
			state = "current"
		}
		if entry.deferred && !entry.completed {
			snapshot.DeferredCount++
			if key != s.current {
				state = "deferred"
			}
		}
		snapshot.Items = append(snapshot.Items, output.ShareQueueItem{Host: entry.plan.Host, Share: entry.plan.Share, State: state})
	}
	return snapshot
}

func (s *shareScheduler) hooks() output.ShareSchedulerHooks {
	return output.ShareSchedulerHooks{
		DeferCurrent: s.requestDefer,
		SkipFolder:   s.requestSkipFolder,
		SkipShare:    s.requestSkipShare,
		Snapshot:     s.snapshot,
	}
}
