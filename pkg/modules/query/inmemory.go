package query

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/Deepreo/bakend/pkg/core"
)

type inMemory struct {
	handlers    map[reflect.Type]core.QueryHandlerFunc
	middlewares []core.QueryMiddleware
	mu          sync.RWMutex
}

func NewInMemory() *inMemory {
	return &inMemory{
		handlers: make(map[reflect.Type]core.QueryHandlerFunc),
	}
}

func (b *inMemory) Register(queryType reflect.Type, handler core.QueryHandlerFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.handlers[queryType]; exists {
		return fmt.Errorf("handler already registered for query type: %v", queryType)
	}
	b.handlers[queryType] = handler
	return nil
}

func (b *inMemory) Use(middleware ...core.QueryMiddleware) {
	b.middlewares = append(b.middlewares, middleware...)
}

func (b *inMemory) Execute(ctx context.Context, query core.Query) (core.QueryResponse, error) {
	queryType := reflect.TypeOf(query)

	b.mu.RLock()
	handler, ok := b.handlers[queryType]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no handler registered for query type: %v", queryType)
	}
	chain := handler
	// Örnek: Tracing( Logging( Validation( Handler ) ) )
	b.mu.RLock()
	middlewares := b.middlewares
	b.mu.RUnlock()
	for i := len(middlewares) - 1; i >= 0; i-- {
		chain = middlewares[i](chain)
	}

	// Zinciri tetikle
	return chain(ctx, query)
}
