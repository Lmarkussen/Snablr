package scanner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"snablr/internal/metrics"
)

type ContentLoader func(context.Context, FileMetadata) ([]byte, error)
type JobCallback func(FileMetadata, Evaluation, error)

type Evaluator interface {
	NeedsContent(FileMetadata) bool
	Evaluate(FileMetadata, []byte) Evaluation
}

type Logger interface {
	Debugf(string, ...any)
	Warnf(string, ...any)
}

type Job struct {
	Metadata    FileMetadata
	LoadContent ContentLoader
	OnComplete  JobCallback
}

type Result struct {
	Metadata   FileMetadata
	Evaluation Evaluation
	Err        error
}

type WorkerPool struct {
	processor Evaluator
	sink      FindingSink
	logger    Logger
	recorder  metrics.Recorder
	workers   int
}

func ResolveWorkerCount(requested int) int {
	if requested > 0 {
		return requested
	}
	workers := runtime.GOMAXPROCS(0) * 4
	switch {
	case workers < 4:
		return 4
	case workers > 64:
		return 64
	default:
		return workers
	}
}

func NewWorkerPool(processor Evaluator, sink FindingSink, logger Logger, recorder metrics.Recorder, workers int) *WorkerPool {
	workers = ResolveWorkerCount(workers)

	return &WorkerPool{
		processor: processor,
		sink:      sink,
		logger:    logger,
		recorder:  recorder,
		workers:   workers,
	}
}

func (p *WorkerPool) Scan(ctx context.Context, jobs <-chan Job) error {
	if p == nil || p.processor == nil {
		return fmt.Errorf("worker pool requires a file processor")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan Result, p.workers)
	var workerWG sync.WaitGroup

	for i := 0; i < p.workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			p.runWorker(runCtx, jobs, results)
		}()
	}

	done := make(chan struct{})
	var collectErr error
	go func() {
		defer close(done)
		collectErr = p.collectResults(runCtx, results)
		if collectErr != nil {
			cancel()
		}
	}()

	workerWG.Wait()
	close(results)
	<-done

	if collectErr != nil {
		return collectErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (p *WorkerPool) runWorker(ctx context.Context, jobs <-chan Job, results chan<- Result) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}

			result := p.processJob(ctx, job)
			select {
			case <-ctx.Done():
				return
			case results <- result:
			}
		}
	}
}

func (p *WorkerPool) processJob(ctx context.Context, job Job) (result Result) {
	meta := job.Metadata.Normalized()
	result = Result{Metadata: meta}
	callbackCalled := false
	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("scanner worker panic for %s: %v", meta.FilePath, recovered)
			p.logError("%v", err)
			p.recordReadError(meta, err)
			result.Evaluation = Evaluation{
				Skipped:    true,
				SkipReason: "worker panic recovered",
			}
			result.Err = err
			if job.OnComplete != nil && !callbackCalled {
				p.invokeCompletion(job.OnComplete, meta, result.Evaluation, err)
			}
		}
	}()

	var content []byte
	var err error

	p.recordFile(meta)

	if p.processor.NeedsContent(meta) {
		if job.LoadContent == nil {
			err = fmt.Errorf("content loader is required for %s", meta.FilePath)
			p.logError("%v", err)
			p.recordReadError(meta, err)
		} else {
			content, err = job.LoadContent(ctx, meta)
			if err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					p.logError("read failed for %s: %v", meta.FilePath, err)
					p.recordReadError(meta, err)
				}
			} else if p.recorder != nil {
				p.recorder.IncFilesRead()
			}
		}
	}

	evaluation := p.processor.Evaluate(meta, content)
	if evaluation.Skipped {
		p.logSkip(meta, evaluation.SkipReason)
	}
	if p.recorder != nil && len(evaluation.Findings) > 0 {
		p.recorder.AddMatchesFound(len(evaluation.Findings))
	}
	if job.OnComplete != nil {
		p.invokeCompletion(job.OnComplete, meta, evaluation, err)
		callbackCalled = true
	}

	result.Evaluation = evaluation
	result.Err = err
	return result
}

func (p *WorkerPool) collectResults(ctx context.Context, results <-chan Result) error {
	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		case result, ok := <-results:
			if !ok {
				return nil
			}
			if p.sink == nil {
				continue
			}
			for _, finding := range result.Evaluation.Findings {
				if err := p.sink.WriteFinding(finding); err != nil {
					return err
				}
			}
		}
	}
}

func (p *WorkerPool) logSkip(meta FileMetadata, reason string) {
	if p.recorder != nil {
		p.recorder.IncFilesSkipped()
	}
	if observer, ok := p.sink.(ScanObserver); ok {
		observer.RecordSkip(meta, reason)
	}
	if p.logger == nil {
		return
	}
	if reason == "" {
		p.logger.Debugf("skipped %s", meta.FilePath)
		return
	}
	p.logger.Debugf("skipped %s: %s", meta.FilePath, reason)
}

func (p *WorkerPool) logError(format string, args ...any) {
	if p.logger == nil {
		return
	}
	p.logger.Warnf(format, args...)
}

func (p *WorkerPool) recordFile(meta FileMetadata) {
	if p.recorder != nil {
		p.recorder.IncFilesVisited()
	}
	if observer, ok := p.sink.(ScanObserver); ok {
		observer.RecordFile(meta)
	}
}

func (p *WorkerPool) recordReadError(meta FileMetadata, err error) {
	if observer, ok := p.sink.(ScanObserver); ok {
		observer.RecordReadError(meta, err)
	}
}

func (p *WorkerPool) invokeCompletion(cb JobCallback, meta FileMetadata, evaluation Evaluation, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			p.logError("job completion callback panic for %s: %v", meta.FilePath, recovered)
		}
	}()
	cb(meta, evaluation, err)
}
