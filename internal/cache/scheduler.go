package cache

import (
	"context"
	"log/slog"
	"time"
)

// Job defines the function signature for a schedulable refresh task.
type Job = func(ctx context.Context) time.Duration

// Scheduler triggers a refresh job in a loop.
type Scheduler interface {
	// Dispatch starts the scheduling loop. The given job is executed immediately,
	// and then repeatedly after the duration it returns. The loop continues until
	// the context is cancelled. This method blocks meanwhile, so it should be run
	// in a separate goroutine.
	Dispatch(ctx context.Context, job Job)
}

// scheduler runs a job, then waits for the duration returned by the job.
type scheduler struct{ log *slog.Logger }

// NewScheduler creates the default implementation of the Scheduler interface.
func NewScheduler(log *slog.Logger) Scheduler { return &scheduler{log} }

// Dispatch implements the Scheduler interface.
func (s *scheduler) Dispatch(ctx context.Context, job Job) {
	s.log.Debug("Starting scheduler")
	defer s.log.Debug("Stopping scheduler")
	d := job(ctx)

	for {
		s.log.Debug("Scheduler waiting", "delay", d)
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			d = job(ctx)
		}
	}
}
