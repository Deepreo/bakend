package core_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Deepreo/bakend/pkg/core"
)

// --- Mocks for Command Bus ---

type mockCommand struct {
	ID string
}

func (c *mockCommand) CommandID() string {
	return c.ID
}

type mockCommandHandler struct {
	handled bool
}

func (h *mockCommandHandler) Handle(ctx context.Context, cmd *mockCommand) error {
	h.handled = true
	return nil
}

type mockCommandBus struct {
	handlers map[reflect.Type]core.CommandHandlerFunc
}

func (b *mockCommandBus) Dispatch(ctx context.Context, cmd core.Command) error {
	handler, ok := b.handlers[reflect.TypeOf(cmd)]
	if !ok {
		return nil
	}
	return handler(ctx, cmd)
}

func (b *mockCommandBus) Register(cmdType reflect.Type, handler core.CommandHandlerFunc) error {
	if b.handlers == nil {
		b.handlers = make(map[reflect.Type]core.CommandHandlerFunc)
	}
	b.handlers[cmdType] = handler
	return nil
}

func (b *mockCommandBus) Use(middleware ...core.CommandMiddleware) {}

// --- Mocks for Query Bus ---

type mockQuery struct {
	ID string
}

func (q *mockQuery) QueryID() string {
	return q.ID
}

type mockQueryHandler struct{}

func (h *mockQueryHandler) Handle(ctx context.Context, query *mockQuery) (string, error) {
	return "result", nil
}

type mockQueryBus struct {
	handlers map[reflect.Type]core.QueryHandlerFunc
}

func (b *mockQueryBus) Execute(ctx context.Context, query core.Query) (core.QueryResponse, error) {
	handler, ok := b.handlers[reflect.TypeOf(query)]
	if !ok {
		return nil, nil
	}
	return handler(ctx, query)
}

func (b *mockQueryBus) Register(queryType reflect.Type, handler core.QueryHandlerFunc) error {
	if b.handlers == nil {
		b.handlers = make(map[reflect.Type]core.QueryHandlerFunc)
	}
	b.handlers[queryType] = handler
	return nil
}

func (b *mockQueryBus) Use(middleware ...core.QueryMiddleware) {}

// --- Mocks for Event Bus ---

type mockEvent struct {
	ID string
}

func (e *mockEvent) EventID() string {
	return e.ID
}

func (e *mockEvent) EventName() string {
	return "mock.event"
}

func (e *mockEvent) OccurredOn() time.Time {
	return time.Now()
}

type mockEventHandler struct {
	handled bool
}

func (h *mockEventHandler) Handle(ctx context.Context, event *mockEvent) error {
	h.handled = true
	return nil
}

type mockEventBus struct {
	handlers map[reflect.Type]core.EventHandlerFunc
}

func (b *mockEventBus) Publish(ctx context.Context, event core.Event) error {
	// Simple mock: just call the handler if registered for this type
	// In reality, event bus might handle multiple subscribers
	handler, ok := b.handlers[reflect.TypeOf(event)]
	if !ok {
		return nil
	}
	return handler(ctx, event)
}

func (b *mockEventBus) Subscribe(prototype core.Event, handler core.EventHandler[core.Event]) error {
	// This mock is simplified and doesn't fully replicate Subscribe logic
	// because SubscribeEvent helper wraps the handler.
	// We will test SubscribeEvent helper by checking if it calls Subscribe on the bus.
	return nil
}

func (b *mockEventBus) Run(ctx context.Context) error {
	return nil
}

// Custom mock for SubscribeEvent testing
type mockEventBusForSubscribe struct {
	subscribedType reflect.Type
}

func (b *mockEventBusForSubscribe) Publish(ctx context.Context, event core.Event) error { return nil }
func (b *mockEventBusForSubscribe) Subscribe(prototype core.Event, handler core.EventHandler[core.Event]) error {
	b.subscribedType = reflect.TypeOf(prototype)
	return nil
}
func (b *mockEventBusForSubscribe) Run(ctx context.Context) error { return nil }

// --- Tests ---

func TestRegisterCommand(t *testing.T) {
	bus := &mockCommandBus{}
	handler := &mockCommandHandler{}

	err := core.RegisterCommand[*mockCommand](bus, handler)
	if err != nil {
		t.Errorf("RegisterCommand failed: %v", err)
	}

	cmd := &mockCommand{ID: "1"}
	err = bus.Dispatch(context.Background(), cmd)
	if err != nil {
		t.Errorf("Dispatch failed: %v", err)
	}

	if !handler.handled {
		t.Error("Handler was not called")
	}
}

func TestRegisterAndExecuteQuery(t *testing.T) {
	bus := &mockQueryBus{}
	handler := &mockQueryHandler{}

	err := core.RegisterQuery[*mockQuery, string](bus, handler)
	if err != nil {
		t.Errorf("RegisterQuery failed: %v", err)
	}

	query := &mockQuery{ID: "1"}
	res, err := core.ExecuteQuery[*mockQuery, string](context.Background(), bus, query)
	if err != nil {
		t.Errorf("ExecuteQuery failed: %v", err)
	}

	if res != "result" {
		t.Errorf("Expected result 'result', got '%s'", res)
	}
}

func TestSubscribeEvent(t *testing.T) {
	bus := &mockEventBusForSubscribe{}
	handler := &mockEventHandler{}

	err := core.SubscribeEvent[*mockEvent](bus, handler)
	if err != nil {
		t.Errorf("SubscribeEvent failed: %v", err)
	}

	expectedType := reflect.TypeOf(&mockEvent{})
	if bus.subscribedType != expectedType {
		t.Errorf("Expected subscribed type %v, got %v", expectedType, bus.subscribedType)
	}
}
