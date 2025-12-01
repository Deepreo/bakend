package core_test

import (
	"context"
	"testing"

	"github.com/Deepreo/bakend/pkg/core"
)

// mockServer implements core.ServerInterface for testing purposes
type mockServer struct {
	middlewares []core.Middleware
	routes      map[string]core.HandlerFunc
}

func (m *mockServer) Run() error {
	return nil
}

func (m *mockServer) Shutdown(ctx context.Context) error {
	return nil
}

func (m *mockServer) Use(middleware ...core.Middleware) {
	m.middlewares = append(m.middlewares, middleware...)
}

func (m *mockServer) Register(method, path string, handler core.HandlerFunc, reqFactory func() any) {
	if m.routes == nil {
		m.routes = make(map[string]core.HandlerFunc)
	}
	m.routes[method+":"+path] = handler
}

type mockRequest struct {
	Val string
}

func (m *mockRequest) Validate() error {
	return nil
}

type mockHandler struct{}

func (h *mockHandler) Handle(ctx context.Context, req *mockRequest) (*string, error) {
	res := "ok"
	return &res, nil
}

func TestServerInterface(t *testing.T) {
	// Verify that mockServer implements core.ServerInterface
	var _ core.Server = (*mockServer)(nil)

	t.Run("Interface Implementation", func(t *testing.T) {
		server := &mockServer{}
		if err := server.Run(); err != nil {
			t.Errorf("Run() error = %v, want nil", err)
		}
		if err := server.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown() error = %v, want nil", err)
		}
	})

	t.Run("RegisterEndpoint", func(t *testing.T) {
		server := &mockServer{}
		handler := &mockHandler{}
		core.RegisterEndpoint[*mockRequest, *string](server, "GET", "/test", handler)

		if len(server.routes) != 1 {
			t.Errorf("Expected 1 route, got %d", len(server.routes))
		}
	})

	t.Run("BaseResponse TraceID", func(t *testing.T) {
		resp := core.BaseResponse[string]{
			Success: false,
			Error: &core.APIError{
				TraceID: "trace-123",
			},
		}
		if resp.Error.TraceID != "trace-123" {
			t.Errorf("Expected TraceID 'trace-123', got %s", resp.Error.TraceID)
		}
	})

	t.Run("BaseResponse APIError", func(t *testing.T) {
		resp := core.BaseResponse[string]{
			Success: false,
			Error: &core.APIError{
				Message: "something went wrong",
				Code:    "ERR_UNKNOWN",
			},
		}
		if resp.Error.Message != "something went wrong" {
			t.Errorf("Expected Error Message 'something went wrong', got %s", resp.Error.Message)
		}
		if resp.Error.Code != "ERR_UNKNOWN" {
			t.Errorf("Expected Error Code 'ERR_UNKNOWN', got %s", resp.Error.Code)
		}
	})
}

func TestHandlerInterface(t *testing.T) {
	handler := &mockHandler{}

	// Verify implementation
	var _ core.HandlerInterface[*mockRequest, *string] = handler

	t.Run("Direct Call", func(t *testing.T) {
		req := &mockRequest{Val: "test"}
		res, err := handler.Handle(context.Background(), req)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}
		if *res != "ok" {
			t.Errorf("Handle() result = %s, want 'ok'", *res)
		}
	})
}
