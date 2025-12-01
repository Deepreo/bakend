package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/Deepreo/bakend/core"
)

// mockScheduler implements core.Scheduler for testing purposes
type mockScheduler struct {
	jobs map[string]core.JobFunc
}

func (s *mockScheduler) Start() {}

func (s *mockScheduler) Shutdown() error {
	return nil
}

func (s *mockScheduler) RegisterJob(name string, fn core.JobFunc, interval time.Duration) error {
	if s.jobs == nil {
		s.jobs = make(map[string]core.JobFunc)
	}
	s.jobs[name] = fn
	return nil
}

func (s *mockScheduler) RegisterCron(name string, cronExpr string, fn core.JobFunc) error {
	if s.jobs == nil {
		s.jobs = make(map[string]core.JobFunc)
	}
	s.jobs[name] = fn
	return nil
}

func (s *mockScheduler) RemoveJob(name string) error {
	delete(s.jobs, name)
	return nil
}

func (s *mockScheduler) Clear() error {
	s.jobs = make(map[string]core.JobFunc)
	return nil
}

func (s *mockScheduler) Use(middleware ...core.SchedulerMiddleware) {}

func TestSchedulerInterface(t *testing.T) {
	// Verify that mockScheduler implements core.Scheduler
	var _ core.Scheduler = (*mockScheduler)(nil)

	t.Run("RegisterJob", func(t *testing.T) {
		scheduler := &mockScheduler{}
		jobName := "test-job"
		err := scheduler.RegisterJob(jobName, func(ctx context.Context) error {
			return nil
		}, time.Minute)

		if err != nil {
			t.Errorf("RegisterJob failed: %v", err)
		}

		if _, ok := scheduler.jobs[jobName]; !ok {
			t.Error("Job was not registered")
		}
	})

	t.Run("Middleware Definition", func(t *testing.T) {
		// Verify Middleware type definition
		var _ core.SchedulerMiddleware = func(next core.JobFunc) core.JobFunc {
			return func(ctx context.Context) error {
				return next(ctx)
			}
		}
	})
}
