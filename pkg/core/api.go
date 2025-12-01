package core

import (
	"context"
	"reflect"
)

// Request interface now requires validation
type Request interface {
	Validate() error
}

type Response any

// HandlerInterface, tüm iş mantığı handler'larımızın uygulayacağı jenerik arayüzdür.
type HandlerInterface[R Request, Res Response] interface {
	Handle(ctx context.Context, req R) (Res, error)
}

// Middleware, handler'ı sarmalayan fonksiyon tipidir.
type Middleware func(next HandlerFunc) HandlerFunc

// HandlerFunc, tip silinmiş (Type-Erased) handler fonksiyonu.
type HandlerFunc func(ctx context.Context, req any) (any, error)

// ServerInterface, API sunucusunun uygulayacağı arayüzdür.
type Server interface {
	Run() error
	Shutdown(ctx context.Context) error
	Use(middleware ...Middleware)
	Register(method, path string, handler HandlerFunc, reqFactory func() any)
}

type APIError struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
	Details any    `json:"details,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

type BaseResponse[T any] struct {
	Success bool      `json:"success"`
	Data    T         `json:"data,omitempty"`
	Error   *APIError `json:"error,omitempty"`
}

// RegisterEndpoint, tip güvenli bir endpoint kaydetmek için kullanılan jenerik bir yardımcı fonksiyondur.
func RegisterEndpoint[R Request, Res Response](server Server, method, path string, handler HandlerInterface[R, Res]) {
	adapter := func(ctx context.Context, req any) (any, error) {
		return handler.Handle(ctx, req.(R))
	}

	reqFactory := func() any {
		var r R
		t := reflect.TypeOf(r)
		if t.Kind() == reflect.Ptr {
			return reflect.New(t.Elem()).Interface()
		}
		return reflect.New(t).Interface()
	}

	server.Register(method, path, adapter, reqFactory)
}
