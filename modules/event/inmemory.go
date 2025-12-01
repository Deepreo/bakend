package event

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/Deepreo/bakend/core"
	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
)

type inMemory struct {
	router *message.Router
	pubSub *gochannel.GoChannel
	logger watermill.LoggerAdapter
}

func NewInMemory(sl *slog.Logger) (*inMemory, error) {
	logger := watermill.NewSlogLogger(sl)
	router, err := message.NewRouter(message.RouterConfig{}, logger)
	if err != nil {
		return nil, err
	}
	//Not: PreserveContext true yaparak context'in event handler'lara geçmesini sağlıyoruz. bunu trace vb. işlemler için kullanmak için yapıyoruz.
	pubSub := gochannel.NewGoChannel(gochannel.Config{PreserveContext: true}, logger)
	router.AddPlugin(plugin.SignalsHandler)
	return &inMemory{router: router, pubSub: pubSub, logger: logger}, nil
}
func (b *inMemory) Use(middleware ...message.HandlerMiddleware) {
	b.router.AddMiddleware(middleware...)
}

func (b *inMemory) AddPublisherDecorator(decorators ...message.PublisherDecorator) {
	b.router.AddPublisherDecorators(decorators...)
}

func (b *inMemory) Publish(ctx context.Context, event core.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	msg := message.NewMessageWithContext(ctx, watermill.NewUUID(), payload)
	return b.pubSub.Publish(event.EventName(), msg)
}

func (b *inMemory) Subscribe(prototype core.Event, handler core.EventHandler[core.Event]) error {
	eventName := prototype.EventName()
	// Tipin yansımasını (reflection) alarak yeni instance oluşturmak için saklıyoruz.
	// Ancak burada handler zaten generic olduğu için ve prototype elimizde olduğu için
	// her mesaj geldiğinde prototype'in tipinden yeni bir instance oluşturup unmarshal edeceğiz.
	eventType := reflect.TypeOf(prototype)
	if eventType.Kind() == reflect.Ptr {
		eventType = eventType.Elem()
	}

	b.router.AddNoPublisherHandler(
		eventName,
		eventName,
		b.pubSub,
		func(msg *message.Message) error {
			// Yeni bir event instance'ı oluştur
			newEvent := reflect.New(eventType).Interface()

			if err := json.Unmarshal(msg.Payload, newEvent); err != nil {
				return err
			}

			// Event interface'ine cast et
			evt, ok := newEvent.(core.Event)
			if !ok {
				return fmt.Errorf("failed to cast to core.Event")
			}

			// Handler'ı çalıştıracak fonksiyon
			handlerFunc := func(ctx context.Context, e core.Event) error {
				return handler.Handle(ctx, e)
			}

			return handlerFunc(msg.Context(), evt)
		},
	)
	return nil
}

func (b *inMemory) Run(ctx context.Context) error {
	poisonQueueMiddleware, err := middleware.PoisonQueue(b.pubSub, "poison_queue")
	if err != nil {
		return err
	}

	retryMiddleware := middleware.Retry{
		MaxRetries:      3,
		InitialInterval: time.Millisecond * 100,
		MaxInterval:     time.Second * 1,
		Multiplier:      2.0,
		Logger:          b.logger,
	}

	b.router.AddMiddleware(
		retryMiddleware.Middleware,
		poisonQueueMiddleware,
	)
	b.AddPublisherDecorator(TraceContextDecorator)

	return b.router.Run(ctx)
}
