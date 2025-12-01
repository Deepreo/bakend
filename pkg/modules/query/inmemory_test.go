package query

import (
	"context"
	"testing"

	"github.com/Deepreo/bakend/pkg/core"
)

type TestQuery struct {
	ID string
}

func (q TestQuery) QueryID() string {
	return q.ID
}

type TestResponse struct {
	Result string
}

type TestQueryHandler struct{}

func (h *TestQueryHandler) Handle(ctx context.Context, q *TestQuery) (*TestResponse, error) {
	return &TestResponse{Result: "Processed " + q.ID}, nil
}

func TestInMemoryQueryBus(t *testing.T) {
	bus := NewInMemory()

	handler := &TestQueryHandler{}
	core.RegisterQuery[*TestQuery, *TestResponse](bus, handler)

	ctx := context.Background()
	q := &TestQuery{ID: "123"}

	res, err := core.ExecuteQuery[*TestQuery, *TestResponse](ctx, bus, q)
	if err != nil {
		t.Fatalf("Failed to execute query: %v", err)
	}

	if res.Result != "Processed 123" {
		t.Errorf("Expected result 'Processed 123', got '%s'", res.Result)
	}
}

func TestInMemoryQueryBus_NoHandler(t *testing.T) {
	bus := NewInMemory()
	ctx := context.Background()
	q := &TestQuery{ID: "456"}

	_, err := core.ExecuteQuery[*TestQuery, *TestResponse](ctx, bus, q)
	if err == nil {
		t.Error("Expected error for missing handler, got nil")
	}
}

func TestInMemoryQueryBus_Middleware(t *testing.T) {
	bus := NewInMemory()
	handler := &TestQueryHandler{}
	core.RegisterQuery[*TestQuery, *TestResponse](bus, handler)

	callOrder := []string{}

	mw1 := func(next core.QueryHandlerFunc) core.QueryHandlerFunc {
		return func(ctx context.Context, q core.Query) (core.QueryResponse, error) {
			callOrder = append(callOrder, "mw1 start")
			res, err := next(ctx, q)
			callOrder = append(callOrder, "mw1 end")
			return res, err
		}
	}

	mw2 := func(next core.QueryHandlerFunc) core.QueryHandlerFunc {
		return func(ctx context.Context, q core.Query) (core.QueryResponse, error) {
			callOrder = append(callOrder, "mw2 start")
			res, err := next(ctx, q)
			callOrder = append(callOrder, "mw2 end")
			return res, err
		}
	}

	bus.Use(mw1, mw2)

	ctx := context.Background()
	q := &TestQuery{ID: "789"}

	_, err := core.ExecuteQuery[*TestQuery, *TestResponse](ctx, bus, q)
	if err != nil {
		t.Fatalf("Failed to execute query: %v", err)
	}

	expectedOrder := []string{
		"mw1 start",
		"mw2 start",
		"mw2 end",
		"mw1 end",
	}

	if len(callOrder) != len(expectedOrder) {
		t.Fatalf("Expected %d middleware calls, got %d", len(expectedOrder), len(callOrder))
	}

	for i, v := range expectedOrder {
		if callOrder[i] != v {
			t.Errorf("Expected call order %d to be %s, got %s", i, v, callOrder[i])
		}
	}
}
