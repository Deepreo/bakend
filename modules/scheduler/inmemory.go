package scheduler

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Deepreo/bakend/core"
	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
)

type InMemoryScheduler struct {
	scheduler   gocron.Scheduler
	jobs        map[string]uuid.UUID
	middlewares []core.SchedulerMiddleware
	mu          sync.RWMutex
}

func NewInMemoryScheduler() (*InMemoryScheduler, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}
	return &InMemoryScheduler{
		scheduler: s,
		jobs:      make(map[string]uuid.UUID),
	}, nil
}

func (s *InMemoryScheduler) Start() {
	s.scheduler.Start()
}

func (s *InMemoryScheduler) Shutdown() error {
	return s.scheduler.Shutdown()
}

func (s *InMemoryScheduler) Use(middleware ...core.SchedulerMiddleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.middlewares = append(s.middlewares, middleware...)
}

func (s *InMemoryScheduler) applyMiddlewares(fn core.JobFunc) core.JobFunc {
	chain := fn
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		chain = s.middlewares[i](chain)
	}
	return chain
}

func (s *InMemoryScheduler) RegisterJob(name string, fn core.JobFunc, interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.jobs[name]; exists {
		return fmt.Errorf("job with name %s already exists", name)
	}

	// Apply middlewares
	wrappedFn := s.applyMiddlewares(fn)

	job, err := s.scheduler.NewJob(
		gocron.DurationJob(interval),
		gocron.NewTask(func() {
			// Create a background context for the job
			ctx := context.Background()
			_ = wrappedFn(ctx) // Log error if needed, but signature doesn't allow return
		}),
	)
	if err != nil {
		return err
	}

	s.jobs[name] = job.ID()
	return nil
}

func (s *InMemoryScheduler) RegisterCron(name string, cronExpr string, fn core.JobFunc) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.jobs[name]; exists {
		return fmt.Errorf("job with name %s already exists", name)
	}

	// Determine if the cron expression includes seconds (6 fields) or not (5 fields)
	fields := strings.Fields(cronExpr)
	withSeconds := len(fields) == 6

	// Apply middlewares
	wrappedFn := s.applyMiddlewares(fn)

	job, err := s.scheduler.NewJob(
		gocron.CronJob(cronExpr, withSeconds),
		gocron.NewTask(func() {
			ctx := context.Background()
			_ = wrappedFn(ctx)
		}),
	)
	if err != nil {
		return err
	}

	s.jobs[name] = job.ID()
	return nil
}

func (s *InMemoryScheduler) RemoveJob(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, exists := s.jobs[name]
	if !exists {
		return fmt.Errorf("job with name %s not found", name)
	}

	err := s.scheduler.RemoveJob(id)
	if err != nil {
		return err
	}

	delete(s.jobs, name)
	return nil
}

func (s *InMemoryScheduler) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop the scheduler first to prevent new runs during clear?
	// Or just remove all jobs. gocron doesn't have a ClearAll?
	// It has s.Jobs() which returns all jobs.

	for name, id := range s.jobs {
		if err := s.scheduler.RemoveJob(id); err != nil {
			// Continue removing others even if one fails?
			// Or return error?
			return fmt.Errorf("failed to remove job %s: %w", name, err)
		}
		delete(s.jobs, name)
	}

	// Alternatively, if gocron has a way to clear all.
	// Looking at docs, usually we iterate and remove.

	return nil
}
