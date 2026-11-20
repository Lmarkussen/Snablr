package smb

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

// Pacing spaces the SMB operations that leave a trace on the server (share
// connections, directory listings and file opens) by a random delay between
// Min and Max. Paced walks list one directory at a time. The zero value
// disables pacing.
type Pacing struct {
	Min time.Duration
	Max time.Duration
}

// Enabled reports whether operations are paced.
func (p Pacing) Enabled() bool { return p.Max > 0 }

type pacer struct {
	mu     sync.Mutex
	pacing Pacing
	last   time.Time
	sleep  func(context.Context, time.Duration) error
	jitter func(min, max time.Duration) time.Duration
}

func newPacer() *pacer {
	return &pacer{sleep: sleepContext, jitter: randomBetween}
}

func (p *pacer) set(pacing Pacing) {
	if pacing.Min < 0 {
		pacing.Min = 0
	}
	if pacing.Max < pacing.Min {
		pacing.Max = pacing.Min
	}
	p.mu.Lock()
	p.pacing = pacing
	p.mu.Unlock()
}

func (p *pacer) enabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pacing.Enabled()
}

// wait blocks until a random delay has passed since the previous paced
// operation. Operations from concurrent goroutines (the walk and the file
// readers) are serialised, so the gap holds across all of them.
func (p *pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.pacing.Enabled() {
		return nil
	}
	delay := p.jitter(p.pacing.Min, p.pacing.Max)
	if !p.last.IsZero() {
		delay -= time.Since(p.last)
	}
	if delay > 0 {
		if err := p.sleep(ctx, delay); err != nil {
			return err
		}
	}
	p.last = time.Now()
	return nil
}

func randomBetween(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + rand.N(max-min+1)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SetPacing paces this client's share connections, directory listings and
// file opens. See Pacing.
func (c *Client) SetPacing(pacing Pacing) {
	c.pacerFor().set(pacing)
}

func (c *Client) pacerFor() *pacer {
	c.pacerOnce.Do(func() {
		if c.pacer == nil {
			c.pacer = newPacer()
		}
	})
	return c.pacer
}

// pace waits for this client's next paced operation slot. It returns early
// with the scan's error when the scan is interrupted.
func (c *Client) pace() error {
	c.mu.Lock()
	ctx := c.baseCtx
	c.mu.Unlock()
	return c.pacerFor().wait(ctx)
}

// walkPrefetch is the number of directory listings a walk runs ahead.
func (c *Client) walkPrefetch() int {
	if c.pacerFor().enabled() {
		return 0
	}
	return dirPrefetchInFlight
}
