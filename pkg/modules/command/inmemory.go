package command

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/Deepreo/bakend/pkg/core"
)

type inMemory struct {
	handlers    map[reflect.Type]core.CommandHandlerFunc
	middlewares []core.CommandMiddleware
	mu          sync.RWMutex
}

func NewInMemory() *inMemory {
	return &inMemory{
		handlers: make(map[reflect.Type]core.CommandHandlerFunc),
	}
}

func (b *inMemory) Use(middleware ...core.CommandMiddleware) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.middlewares = append(b.middlewares, middleware...)
}

func (b *inMemory) Dispatch(ctx context.Context, cmd core.Command) error {

	cmdType := reflect.TypeOf(cmd)
	b.mu.RLock()
	handler, ok := b.handlers[cmdType]
	b.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no handler found for command: %v", cmdType)
	}

	// Middleware Zincirini Kur (Chain Construction)
	// En son çalışacak olan: Asıl Handler
	chain := handler

	// Listeyi tersten dönerek handler'ı katman katman sarmalıyoruz.
	// Örnek: Tracing( Logging( Validation( Handler ) ) )
	b.mu.RLock()
	middlewares := b.middlewares
	b.mu.RUnlock()
	for i := len(middlewares) - 1; i >= 0; i-- {
		chain = middlewares[i](chain)
	}

	// Zinciri tetikle
	return chain(ctx, cmd)
}

// Don't use this method directly, use RegisterCommand helper function instead.
func (b *inMemory) Register(cmdType reflect.Type, handler core.CommandHandlerFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.handlers[cmdType]; exists {
		return fmt.Errorf("handler already registered for command: %v", cmdType)
	}
	b.handlers[cmdType] = handler
	return nil
}
