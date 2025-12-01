package bakend

import (
	"context"
	"log/slog"
	"os"

	"github.com/Deepreo/bakend/pkg/core"
	"github.com/Deepreo/bakend/pkg/modules/command"
	"github.com/Deepreo/bakend/pkg/modules/event"
	"github.com/Deepreo/bakend/pkg/modules/query"
	"github.com/Deepreo/bakend/pkg/modules/servers"
)

type Application struct {
	server     core.Server
	commandBus core.CommandBus
	queryBus   core.QueryBus
	eventBus   core.EventBus
	scheduler  core.Scheduler
	logger     slog.Logger
}

func New() (*Application, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	httpServer, err := servers.NewServer()
	if err != nil {
		return nil, err
	}
	cBus := command.NewInMemory()
	qBus := query.NewInMemory()
	eBus, err := event.NewInMemory(logger)
	if err != nil {
		return nil, err
	}
	return &Application{
		server:     server,
		commandBus: cBus,
		queryBus:   qBus,
		eventBus:   eBus,
		scheduler:  scheduler,
		logger:     logger,
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
