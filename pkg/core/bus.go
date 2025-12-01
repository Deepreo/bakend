package core

import (
	"context"
	"fmt"
	"reflect"
	"time"
)

/**--------------------------------------------
 *               COMMAND BUS
 *---------------------------------------------**/

// Command, bir eylemi gerçekleştirmek için verilen bir talimatı temsil eder.
// İzlenebilirlik ve idempotency (tekrarlanabilirlik) için benzersiz bir ID'ye sahip olmalıdır.
type Command interface {
	CommandID() string
}

type CommandHandler[C Command] interface {
	Handle(ctx context.Context, cmd C) error
}

// HandlerFunc: Bus'ın içeride sakladığı, tipi silinmiş (Type-Erased) fonksiyon.
// Middleware'ler bu imzayı kullanır.
type CommandHandlerFunc func(ctx context.Context, cmd any) error

// Middleware: Handler'ı sarmalayan fonksiyon tipi.
type CommandMiddleware func(next CommandHandlerFunc) CommandHandlerFunc

// CommandBus, komutları dağıtmak (dispatch) için arayüzü tanımlar.
type CommandBus interface {
	Dispatch(ctx context.Context, cmd Command) error
	Register(cmdType reflect.Type, handler CommandHandlerFunc) error
	Use(middleware ...CommandMiddleware)
}

// RegisterCommand, tip güvenli bir komut işleyicisini kaydetmek için kullanılan jenerik bir yardımcı fonksiyondur.
func RegisterCommand[C Command, H CommandHandler[C]](bus CommandBus, handler H) error {
	// Tipi almak için pointer kullanılır, ardından interface/nil durumlarını yönetmek için Elem() çağrılır.
	// Ancak somut tipler için reflect.TypeOf(zero) genellikle yeterlidir.
	// Yine de güvenli ve tutarlı olmak adına:
	cmdType := reflect.TypeOf((*C)(nil)).Elem()
	adapter := func(ctx context.Context, c any) error {
		// Type Assertion: Burası güvenlidir çünkü Register sırasında tip kontrolü yaptık.
		return handler.Handle(ctx, c.(C))
	}
	return bus.Register(cmdType, adapter)
}

/**--------------------------------------------
 *               QUERY BUS
 *---------------------------------------------**/

// Query, bilgi almak için yapılan bir isteği temsil eder.
type Query interface {
	QueryID() string
}
type QueryResponse interface{}

// QueryHandler, belirli bir sorgunun nasıl işleneceğini tanımlar.
type QueryHandler[Q Query, R QueryResponse] interface {
	Handle(ctx context.Context, query Q) (R, error)
}

// QueryHandlerFunc, sorgu işleyicileri için ham fonksiyon imzasıdır.
type QueryHandlerFunc func(context.Context, Query) (QueryResponse, error)

// QueryMiddleware, sorgu işleyicilerini sarmalayan fonksiyon tipidir.
type QueryMiddleware func(next QueryHandlerFunc) QueryHandlerFunc

// QueryBus, sorguları çalıştırmak için arayüzü tanımlar.
// Jenerik bir implementasyona izin vermek için 'any' döner,
// ancak tip güvenliği için Ask yardımcısı ile kullanılmalıdır.
type QueryBus interface {
	Execute(ctx context.Context, query Query) (QueryResponse, error)
	Register(queryType reflect.Type, handler QueryHandlerFunc) error
	Use(middleware ...QueryMiddleware)
}

// RegisterQuery, tip güvenli bir sorgu işleyicisini kaydetmek için kullanılan jenerik bir yardımcı fonksiyondur.
func RegisterQuery[Q Query, R QueryResponse](bus QueryBus, handler QueryHandler[Q, R]) error {
	queryType := reflect.TypeOf((*Q)(nil)).Elem()
	adapter := func(ctx context.Context, q Query) (QueryResponse, error) {
		return handler.Handle(ctx, q.(Q))
	}
	return bus.Register(queryType, adapter)
}

// ExecuteQuery, bir sorguyu çalıştırmak ve sonucu QueryResponse tipine dönüştürmek için kullanılan jenerik bir yardımcı fonksiyondur.
func ExecuteQuery[Q Query, R QueryResponse](ctx context.Context, bus QueryBus, q Q) (R, error) {
	res, err := bus.Execute(ctx, q)
	if err != nil {
		var zero R
		return zero, err
	}
	if res == nil {
		var zero R
		return zero, nil
	}
	typedRes, ok := res.(R)
	if !ok {
		var zero R
		return zero, fmt.Errorf("unexpected response type: got %T, want %T", res, zero)
	}
	return typedRes, nil
}

/**--------------------------------------------
 *               EVENT BUS
 *---------------------------------------------**/

// Event, geçmişte gerçekleşmiş bir olayı (gerçeği) temsil eder.
type Event interface {
	EventID() string
	EventName() string
	OccurredOn() time.Time
}

// EventHandler, belirli bir olayın nasıl işleneceğini tanımlar.
type EventHandler[E Event] interface {
	Handle(ctx context.Context, event E) error
}

// EventHandlerFunc, olay işleyicileri için ham fonksiyon imzasıdır.
type EventHandlerFunc func(context.Context, Event) error

// EventMiddlewareFunc, olay işleyicilerini sarmalayan fonksiyon tipidir.
type EventMiddlewareFunc func(next EventHandlerFunc) EventHandlerFunc

// EventBus, olayları yayınlamak (publish) ve abone olmak (subscribe) için arayüzü tanımlar.
type EventBus interface {
	Publish(ctx context.Context, event Event) error
	Subscribe(prototype Event, handler EventHandler[Event]) error
	Run(ctx context.Context) error
}

// SubscribeEvent, tip güvenli bir olay abonesi kaydetmek için kullanılan jenerik bir yardımcı fonksiyondur.
func SubscribeEvent[E Event](bus EventBus, handler EventHandler[E]) error {
	var zero E
	// Eğer E bir pointer ise ve nil ise, metodu çağırabilmek için yeni bir instance oluştur.
	val := reflect.ValueOf(zero)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		val = reflect.New(val.Type().Elem())
		zero = val.Interface().(E)
	}

	return bus.Subscribe(zero, &eventHandlerWrapper[E]{handler: handler})
}

type eventHandlerWrapper[E Event] struct {
	handler EventHandler[E]
}

func (w *eventHandlerWrapper[E]) Handle(ctx context.Context, event Event) error {
	return w.handler.Handle(ctx, event.(E))
}
