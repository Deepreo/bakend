package core

import (
	"context"
	"time"
)

// JobFunc is the function signature for scheduled jobs.
type JobFunc func(ctx context.Context) error

// SchedulerMiddleware wraps a JobFunc to add cross-cutting concerns.
type SchedulerMiddleware func(next JobFunc) JobFunc

// Scheduler defines the interface for scheduling jobs.
type Scheduler interface {
	Start()
	Shutdown() error
	RegisterJob(name string, fn JobFunc, interval time.Duration) error
	RegisterCron(name string, cronExpr string, fn JobFunc) error
	RemoveJob(name string) error
	Clear() error
	Use(middleware ...SchedulerMiddleware)
}
