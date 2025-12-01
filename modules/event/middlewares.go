package event

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func OTelMiddleware(h message.HandlerFunc) message.HandlerFunc {
	return func(msg *message.Message) ([]*message.Message, error) {
		ctx := msg.Context()
		tracer := otel.Tracer("watermill-event-bus")

		ctx, span := tracer.Start(ctx, "handle_event",
			trace.WithAttributes(
				attribute.String("messaging.system", "watermill"),
				attribute.String("messaging.message_id", msg.UUID),
			),
			trace.WithSpanKind(trace.SpanKindConsumer),
		)
		defer span.End()

		// Inject context back into message
		msg.SetContext(ctx)

		msgs, err := h(msg)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}

		return msgs, err
	}
}
func TraceContextDecorator(pub message.Publisher) (message.Publisher, error) {
	return &traceContextPublisher{pub}, nil
}

type traceContextPublisher struct {
	message.Publisher
}

func (t *traceContextPublisher) Publish(topic string, messages ...*message.Message) error {
	for _, msg := range messages {
		otel.GetTextMapPropagator().Inject(msg.Context(), propagation.MapCarrier(msg.Metadata))
	}
	return t.Publisher.Publish(topic, messages...)
}
