package metrics

import "time"

type Timer struct {
	collector *Collector
	phase     string
	startedAt time.Time
	stopped   bool
}

func (c *Collector) StartPhase(phase string) *Timer {
	if c == nil {
		return &Timer{}
	}
	return &Timer{
		collector: c,
		phase:     phase,
		startedAt: time.Now().UTC(),
	}
}

func (t *Timer) Stop() {
	if t == nil || t.stopped || t.collector == nil || t.phase == "" {
		return
	}
	t.stopped = true
	t.collector.addPhaseDuration(t.phase, time.Since(t.startedAt))
}
