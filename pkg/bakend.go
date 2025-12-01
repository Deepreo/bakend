package bakend

import (
	"context"
	"log/slog"
	"os"

	"github.com/Deepreo/bakend/pkg/core"
	"github.com/Deepreo/bakend/pkg/modules/command"
	"github.com/Deepreo/bakend/pkg/modules/event"
	"github.com/Deepreo/bakend/pkg/modules/query"
	"github.com/Deepreo/bakend/pkg/modules/scheduler"
	"github.com/Deepreo/bakend/pkg/modules/servers"
)

type Application struct {
	server     core.Server
	commandBus core.CommandBus
	queryBus   core.QueryBus
	eventBus   core.EventBus
	scheduler  core.Scheduler
	logger     *slog.Logger
}

func New() (*Application, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	httpServer, err := servers.NewHttpServer()
	if err != nil {
		return nil, err
	}
	cBus := command.NewInMemory()
	qBus := query.NewInMemory()
	eBus, err := event.NewInMemory(logger)
	if err != nil {
		return nil, err
	}
	sC, err := scheduler.NewInMemoryScheduler()
	if err != nil {
		return nil, err
	}
	return &Application{
		server:     httpServer,
		commandBus: cBus,
		queryBus:   qBus,
		eventBus:   eBus,
		scheduler:  sC,
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

func RegisterCommand[C core.Command, H core.CommandHandler[C]](app *Application, handler H) error {
	return core.RegisterCommand(app.commandBus, handler)
}

func RegisterQuery[Q core.Query, R core.QueryResponse](app *Application, handler core.QueryHandler[Q, R]) error {
	return core.RegisterQuery(app.queryBus, handler)
}

func RegisterEvent[E core.Event](app *Application, handler core.EventHandler[E]) error {
	return core.SubscribeEvent(app.eventBus, handler)
}

func RegisterEndpoint[R core.Request, Res core.Response](app *Application, method, path string, handler core.HandlerInterface[R, Res]) {
	core.RegisterEndpoint(app.server, method, path, handler)
}

func (app *Application) GetCommandBus() core.CommandBus {
	return app.commandBus
}

func (app *Application) GetQueryBus() core.QueryBus {
	return app.queryBus
}

func (app *Application) GetEventBus() core.EventBus {
	return app.eventBus
}

func (app *Application) GetScheduler() core.Scheduler {
	return app.scheduler
}
