package command

import (
	"context"
	"errors"
	"testing"

	"github.com/Deepreo/bakend/core"
	"github.com/stretchr/testify/assert"
)

// Mock Command
type TestCommand struct {
	ID    string
	Value string
}

func (c TestCommand) CommandID() string {
	return c.ID
}

// Mock Handler
type TestCommandHandler struct {
	handled bool
	lastCmd TestCommand
	err     error
}

func (h *TestCommandHandler) Handle(ctx context.Context, cmd TestCommand) error {
	h.handled = true
	h.lastCmd = cmd
	return h.err
}

func TestInMemory_Register(t *testing.T) {
	bus := NewInMemory()
	handler := &TestCommandHandler{}

	// Helper to register
	core.RegisterCommand(bus, handler)

	// Verify registration by checking internal map (using reflection or just dispatching)
	// Since we can't access private fields easily in black-box test, we'll rely on Dispatch to verify.
	// But we can test panic on duplicate registration.

	err := core.RegisterCommand(bus, handler)
	assert.Error(t, err, "Should return error on duplicate registration")
	assert.Contains(t, err.Error(), "handler already registered")
}

func TestInMemory_Dispatch(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		bus := NewInMemory()
		handler := &TestCommandHandler{}
		core.RegisterCommand(bus, handler)

		cmd := TestCommand{ID: "1", Value: "test"}
		err := bus.Dispatch(context.Background(), cmd)

		assert.NoError(t, err)
		assert.True(t, handler.handled)
		assert.Equal(t, cmd, handler.lastCmd)
	})

	t.Run("Handler Error", func(t *testing.T) {
		bus := NewInMemory()
		expectedErr := errors.New("handler error")
		handler := &TestCommandHandler{err: expectedErr}
		core.RegisterCommand(bus, handler)

		cmd := TestCommand{ID: "2", Value: "error"}
		err := bus.Dispatch(context.Background(), cmd)

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("No Handler Found", func(t *testing.T) {
		bus := NewInMemory()
		cmd := TestCommand{ID: "3", Value: "no handler"}

		err := bus.Dispatch(context.Background(), cmd)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no handler found")
	})
}

func TestInMemory_Use(t *testing.T) {
	bus := NewInMemory()
	handler := &TestCommandHandler{}
	core.RegisterCommand(bus, handler)

	callOrder := []string{}

	mw1 := func(next core.CommandHandlerFunc) core.CommandHandlerFunc {
		return func(ctx context.Context, cmd any) error {
			callOrder = append(callOrder, "mw1 start")
			err := next(ctx, cmd)
			callOrder = append(callOrder, "mw1 end")
			return err
		}
	}

	mw2 := func(next core.CommandHandlerFunc) core.CommandHandlerFunc {
		return func(ctx context.Context, cmd any) error {
			callOrder = append(callOrder, "mw2 start")
			err := next(ctx, cmd)
			callOrder = append(callOrder, "mw2 end")
			return err
		}
	}

	bus.Use(mw1, mw2)

	cmd := TestCommand{ID: "1", Value: "middleware"}
	err := bus.Dispatch(context.Background(), cmd)

	assert.NoError(t, err)

	expectedOrder := []string{
		"mw1 start",
		"mw2 start",
		"mw2 end",
		"mw1 end",
	}

	assert.Equal(t, expectedOrder, callOrder)
}
