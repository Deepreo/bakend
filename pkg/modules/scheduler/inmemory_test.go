package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/Deepreo/bakend/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryScheduler_RegisterJob(t *testing.T) {
	s, err := NewInMemoryScheduler()
	assert.NoError(t, err)
	s.Start()
	defer s.Shutdown()

	done := make(chan bool)
	err = s.RegisterJob("test-job", func(ctx context.Context) error {
		done <- true
		return nil
	}, 100*time.Millisecond)
	assert.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Job did not run in time")
	}
}

func TestInMemoryScheduler_RegisterCron(t *testing.T) {
	s, err := NewInMemoryScheduler()
	assert.NoError(t, err)
	s.Start()
	defer s.Shutdown()

	// Cron that runs every second
	done := make(chan bool)
	err = s.RegisterCron("cron-job", "* * * * * *", func(ctx context.Context) error {
		done <- true
		return nil
	})
	assert.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Cron job did not run in time")
	}
}

func TestInMemoryScheduler_RemoveJob(t *testing.T) {
	s, err := NewInMemoryScheduler()
	assert.NoError(t, err)
	s.Start()
	defer s.Shutdown()

	runCount := 0
	err = s.RegisterJob("remove-job", func(ctx context.Context) error {
		runCount++
		return nil
	}, 100*time.Millisecond)
	assert.NoError(t, err)

	// Let it run at least once
	time.Sleep(150 * time.Millisecond)
	assert.Greater(t, runCount, 0)

	err = s.RemoveJob("remove-job")
	assert.NoError(t, err)

	currentCount := runCount
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, currentCount, runCount, "Job should not run after removal")
}

func TestInMemoryScheduler_Clear(t *testing.T) {
	s, err := NewInMemoryScheduler()
	assert.NoError(t, err)
	s.Start()
	defer s.Shutdown()

	err = s.RegisterJob("job1", func(ctx context.Context) error { return nil }, 1*time.Second)
	assert.NoError(t, err)
	err = s.RegisterJob("job2", func(ctx context.Context) error { return nil }, 1*time.Second)
	assert.NoError(t, err)

	err = s.Clear()
	assert.NoError(t, err)

	err = s.RemoveJob("job1")
	assert.Error(t, err, "Job should be gone")
}

func TestInMemoryScheduler_Middleware(t *testing.T) {
	s, err := NewInMemoryScheduler()
	assert.NoError(t, err)
	s.Start()
	defer s.Shutdown()

	middlewareCalled := false
	middleware := func(next core.JobFunc) core.JobFunc {
		return func(ctx context.Context) error {
			middlewareCalled = true
			return next(ctx)
		}
	}

	s.Use(middleware)

	done := make(chan bool)
	err = s.RegisterJob("middleware-job", func(ctx context.Context) error {
		done <- true
		return nil
	}, 100*time.Millisecond)
	assert.NoError(t, err)

	select {
	case <-done:
		assert.True(t, middlewareCalled, "Middleware should have been called")
	case <-time.After(1 * time.Second):
		t.Fatal("Job did not run in time")
	}
}
