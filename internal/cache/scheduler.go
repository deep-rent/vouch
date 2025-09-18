package cache

import (
	"context"
	"log/slog"
	"time"
)

// Job defines the function signature for a schedulable refresh task.
type Job = func(ctx context.Context) time.Duration

// Scheduler defines the interface for running a refresh job.
type Scheduler interface {
	// Dispatch starts the scheduling loop.
	Dispatch(ctx context.Context, job Job)
}

// scheduler runs a job, then waits for the duration returned by the job.
type scheduler struct {
	logger *slog.Logger
}

// NewScheduler creates the default implementation of the Scheduler interface.
func NewScheduler(logger *slog.Logger) Scheduler {
	return &scheduler{logger: logger}
}

// Dispatch starts the scheduling loop, passing the context to the job.
func (s *scheduler) Dispatch(ctx context.Context, job Job) {
	s.logger.Debug("Starting scheduler")
	defer s.logger.Debug("Stopping scheduler")
	d := job(ctx)

	for {
		s.logger.Debug("Scheduler waiting", "delay", d)
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
