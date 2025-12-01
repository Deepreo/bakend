package event_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Deepreo/bakend/core"
	"github.com/Deepreo/bakend/modules/event"
)

type TestEvent struct {
	ID        string
	Name      string
	Timestamp time.Time
	Payload   string
}

func (e TestEvent) EventID() string {
	return e.ID
}

func (e TestEvent) EventName() string {
	return "test.event"
}

func (e TestEvent) OccurredOn() time.Time {
	return e.Timestamp
}

type TestEventHandler struct {
	ReceivedEvent *TestEvent
	Done          chan struct{}
}

func (h *TestEventHandler) Handle(ctx context.Context, event *TestEvent) error {
	h.ReceivedEvent = event
	close(h.Done)
	return nil
}

func TestWatermillEventBus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	bus, err := event.NewInMemory(logger)
	if err != nil {
		t.Fatalf("Failed to create event bus: %v", err)
	}

	handler := &TestEventHandler{
		Done: make(chan struct{}),
	}

	// Subscribe
	err = core.SubscribeEvent[*TestEvent](bus, handler)
	if err != nil {
		t.Fatalf("Failed to subscribe: %v", err)
	}

	// Run bus in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := bus.Run(ctx); err != nil {
			t.Logf("Bus stopped: %v", err)
		}
	}()

	// Wait for router to start (simple sleep for test)
	time.Sleep(100 * time.Millisecond)

	// Publish
	eventToSend := &TestEvent{
		ID:        "123",
		Name:      "test.event",
		Timestamp: time.Now(),
		Payload:   "Hello Watermill",
	}

	err = bus.Publish(ctx, eventToSend)
	if err != nil {
		t.Fatalf("Failed to publish: %v", err)
	}

	// Wait for event
	select {
	case <-handler.Done:
		if handler.ReceivedEvent.Payload != eventToSend.Payload {
			t.Errorf("Expected payload %s, got %s", eventToSend.Payload, handler.ReceivedEvent.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}
