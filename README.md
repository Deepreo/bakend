# Bakend Framework

[![Read in Turkish](https://img.shields.io/badge/Lang-Türkçe-red)](README.tr.md)

`bakend-framework` is a powerful framework developed in Go, designed for building modular, scalable, and modern backend applications. By adopting CQRS (Command Query Responsibility Segregation), Event-Driven Architecture, and Clean Architecture principles, it provides a solid foundation for developers.

## Features

- **Modular Structure:** Increases manageability and testability by separating your application into independent modules.
- **CQRS Support:** Ensures performance and scalability by separating Command and Query responsibilities.
- **Event-Driven Architecture:** Provides loose coupling by enabling communication between modules via events.
- **Built-in Server:** Start developing APIs quickly with HTTP server integration.
- **Scheduler:** Built-in scheduler support for managing background tasks and scheduled jobs.
- **Extensible:** Easily integrate your own modules and components.

## Installation

To add `bakend-framework` to your project, use the following command:

```bash
go get github.com/Deepreo/bakend
```

## Usage

You can follow these steps to create a simple `bakend` application:

```go
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/Deepreo/bakend"
	"github.com/Deepreo/bakend/pkg/core"
	// ... other imports
)

func main() {
    // Create Logger
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    // Initialize necessary components (Server, Buses, etc.)
    // Note: Implementations of these components must be provided within the framework or externally.
    // For example, mock or in-memory implementations can be used.
    
    // Create the application
    app, err := bakend.New(
        server,
        commandBus,
        queryBus,
        eventBus,
        scheduler,
        *logger,
    )
    if err != nil {
        logger.Error("Failed to create application", "error", err)
        os.Exit(1)
    }

    // Run the application
    if err := app.Run(context.Background()); err != nil {
        logger.Error("Application error", "error", err)
        os.Exit(1)
    }
}
```

## Modules

The framework offers (or aims to offer) ready-made modules for various functions:

- **Auth:** Authentication and authorization.
- **Database:** Database connection and management operations.
- **Cache:** Caching mechanisms.
- **Event:** Event management and distribution.
- **Scheduler:** Scheduled tasks.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE). See the `LICENSE` file for more details.
