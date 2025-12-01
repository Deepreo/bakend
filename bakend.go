package bakend

import (
	"context"
	"log/slog"

	"github.com/Deepreo/bakend/core"
)

type Application struct {
	server     core.Server
	commandBus core.CommandBus
	queryBus   core.QueryBus
	eventBus   core.EventBus
	scheduler  core.Scheduler
	logger     slog.Logger
}

func New(server core.Server, commandBus core.CommandBus, queryBus core.QueryBus, eventBus core.EventBus, scheduler core.Scheduler, logger slog.Logger) (*Application, error) {
	return &Application{
		server:     server,
		commandBus: commandBus,
		queryBus:   queryBus,
		eventBus:   eventBus,
		scheduler:  scheduler,
	}, nil
}

func (app *Application) Run(ctx context.Context) error {
	// Start Event Bus
	go func() {
		if err := app.eventBus.Run(ctx); err != nil {
			app.logger.Error("Event bus failed", "error", err)
		}
	}()
	return app.server.Run()
}

func (app *Application) Shutdown(ctx context.Context) error {
	if app.scheduler != nil {
		app.scheduler.Shutdown()
	}
	return app.server.Shutdown(ctx)
}
