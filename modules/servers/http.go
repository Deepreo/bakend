package servers

import (
	"context"
	"fmt"
	"html/template"
	"time"

	"github.com/Deepreo/bakend/core"
	"github.com/Deepreo/bakend/errors"
	"github.com/Deepreo/bakend/modules/auth"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/healthcheck"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/gofiber/swagger"

	"go.elastic.co/apm/module/apmfiber/v2"
	"go.elastic.co/apm/v2"
)

const (
	DefaultReadTimeout     = 3 * time.Second
	DefaultWriteTimeout    = 3 * time.Second
	DefaultServerHeader    = "Fiber"
	DefaultBodyLimit       = 4 * 1024 * 1024 // 4 MB
	DefaultPort            = "8080"
	DefaultAllowedOrigins  = "*"
	DefaultShutdownTimeout = 5 * time.Second
	DefaultSwaggerUIPath   = "/api/swagger/*"
	DefaultHost            = "localhost"
)

type HttpServer struct {
	app *fiber.App
	cfg *HttpServerConfig
}

type HttpServerConfig struct {
	ReadTimeout    string `mapstructure:"read_timeout"`
	WriteTimeout   string `mapstructure:"write_timeout"`
	ServerHeader   string `mapstructure:"server_header"`
	BodyLimit      int    `mapstructure:"body_limit"`
	ErrorHandler   fiber.ErrorHandler
	Port           string   `mapstructure:"port"`
	Host           string   `mapstructure:"host"`
	AllowedOrigins string   `mapstructure:"allowed_origins"`
	Features       Features `mapstructure:"features"`
}

type Features struct {
	RequestID   RequestID   `mapstructure:"request_id"`
	Proxy       Proxy       `mapstructure:"proxy"`
	RateLimit   RateLimit   `mapstructure:"rate_limit"`
	HealthCheck HealthCheck `mapstructure:"health_check"`
	Etag        Etag        `mapstructure:"etag"`
	ElasticAPM  ElasticAPM  `mapstructure:"elastic_apm"`
	SwaggerUI   SwaggerUI   `mapstructure:"swagger_ui"`
}
type Etag struct {
	Enabled bool `mapstructure:"enabled"`
}

type ElasticAPM struct {
	Enabled bool `mapstructure:"enabled"`
}

type RequestID struct {
	Enabled bool `mapstructure:"enabled"`
}

type Proxy struct {
	Enabled        bool     `mapstructure:"enabled"`
	ProxyHeader    string   `mapstructure:"proxy_header"`
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

type RateLimit struct {
	Enabled    bool   `mapstructure:"enabled"`
	Max        int    `mapstructure:"max"`
	Expiration string `mapstructure:"expiration"`
}

type HealthCheck struct {
	Enabled bool `mapstructure:"enabled"`
}

type SwaggerUI struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

func WithConfig(cfg *HttpServerConfig) func(*HttpServerConfig) {
	return func(s *HttpServerConfig) {
		if cfg.ReadTimeout != "" {
			s.ReadTimeout = cfg.ReadTimeout
		}
		if cfg.WriteTimeout != "" {
			s.WriteTimeout = cfg.WriteTimeout
		}
		if cfg.ServerHeader != "" {
			s.ServerHeader = cfg.ServerHeader
		}
		if cfg.BodyLimit != 0 {
			s.BodyLimit = cfg.BodyLimit
		}
		if cfg.ErrorHandler != nil {
			s.ErrorHandler = cfg.ErrorHandler
		}
		if cfg.Port != "" {
			s.Port = cfg.Port
		}
		if cfg.AllowedOrigins != "" {
			s.AllowedOrigins = cfg.AllowedOrigins
		}
		s.Features.RequestID.Enabled = cfg.Features.RequestID.Enabled
		s.Features.Proxy.Enabled = cfg.Features.Proxy.Enabled
		s.Features.Proxy.TrustedProxies = cfg.Features.Proxy.TrustedProxies
		s.Features.Proxy.ProxyHeader = cfg.Features.Proxy.ProxyHeader
		s.Features.RateLimit.Enabled = cfg.Features.RateLimit.Enabled
		s.Features.RateLimit.Max = cfg.Features.RateLimit.Max
		s.Features.RateLimit.Expiration = cfg.Features.RateLimit.Expiration
		s.Features.HealthCheck.Enabled = cfg.Features.HealthCheck.Enabled
		s.Features.Etag.Enabled = cfg.Features.Etag.Enabled
		s.Features.ElasticAPM.Enabled = cfg.Features.ElasticAPM.Enabled
		s.Features.SwaggerUI.Enabled = cfg.Features.SwaggerUI.Enabled
		if cfg.Features.SwaggerUI.Path != "" {
			s.Features.SwaggerUI.Path = cfg.Features.SwaggerUI.Path
		}
		if cfg.Host != "" {
			s.Host = cfg.Host
		}
	}
}

var token string

func NewHttpServer(options ...func(*HttpServerConfig)) (*HttpServer, error) {
	cfg := &HttpServerConfig{
		ReadTimeout:    DefaultReadTimeout.String(),
		WriteTimeout:   DefaultWriteTimeout.String(),
		ServerHeader:   DefaultServerHeader,
		BodyLimit:      DefaultBodyLimit,
		Port:           DefaultPort,
		AllowedOrigins: DefaultAllowedOrigins,
		Host:           DefaultHost,
	}
	for _, option := range options {
		option(cfg)
	}
	// Yapılandırma doğrulamasını burada yapıp hata dönebiliriz.
	fiberConfig, err := buildFiberConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid server configuration: %w", err)
	}

	app := fiber.New(fiberConfig)

	server := &HttpServer{
		app: app,
		cfg: cfg,
	}
	// Middleware'leri burada uygula
	server.applyMiddlewares()
	return server, nil
}
func (s *HttpServer) applyMiddlewares() {
	s.app.Use(recover.New())
	s.app.Use(helmet.New())
	s.app.Use(cors.New(cors.Config{
		AllowOrigins:  s.cfg.AllowedOrigins,
		AllowMethods:  "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:  "Accept, Authorization, Content-Type, X-CSRF-Token",
		ExposeHeaders: "Content-Length, X-Request-ID, Link",
		AllowCredentials: func() bool {
			return s.cfg.AllowedOrigins != "*"
		}(),
		MaxAge: 300, // 5 minutes
	}))
	if s.cfg.Features.RequestID.Enabled {
		s.app.Use(requestid.New())
	}
	if s.cfg.Features.RateLimit.Enabled {
		s.app.Use(limiter.New(limiter.Config{
			Max: s.cfg.Features.RateLimit.Max,
			Expiration: func() time.Duration {
				if s.cfg.Features.RateLimit.Expiration != "" {
					d, err := time.ParseDuration(s.cfg.Features.RateLimit.Expiration)
					if err != nil {
						// Log invalid duration
						return 60 * time.Second // Default to 1 minute
					}
					return d
				}
				return 60 * time.Second // Default to 1 minute
			}(),
		}))
	}
	if s.cfg.Features.HealthCheck.Enabled {
		s.app.Use(healthcheck.New())
	}
	if s.cfg.Features.Etag.Enabled {
		s.app.Use(etag.New())
	}
	if s.cfg.Features.ElasticAPM.Enabled {
		s.app.Use(apmfiber.Middleware())
	}
	if s.cfg.Features.SwaggerUI.Enabled {
		// swaggui.SwaggerInfo.Host = func() string {
		// 	if s.cfg.Features.Proxy.Enabled {
		// 		return s.cfg.Host
		// 	} else {
		// 		return fmt.Sprintf("%s:%s", s.cfg.Host, s.cfg.Port)
		// 	}
		// }()
		s.app.Get(func() string {
			if s.cfg.Features.SwaggerUI.Path != "" {
				return s.cfg.Features.SwaggerUI.Path
			} else {
				return DefaultSwaggerUIPath
			}
		}(), swagger.New(
			swagger.Config{
				TryItOutEnabled: true,
				OnComplete: template.JS(`
				function() {
      				// Artık 'ui' nesnesinin tamamen hazır olduğundan eminiz.
     				 window.ui.preauthorizeApiKey("BearerAuth", "` + token + `");
   				 }`),
			},
		))
	}
}
func (s *HttpServer) GetApp() *fiber.App {
	return s.app
}

func (s *HttpServer) Run() error {
	return s.app.Listen(func() string {
		if s.cfg.Features.Proxy.Enabled {
			return fmt.Sprintf(":%s", s.cfg.Port)
		}
		return fmt.Sprintf("%s:%s", s.cfg.Host, s.cfg.Port)
	}())
}

// Shutdown, artık Server nesnesinin bir metodudur ve global değişkene ihtiyaç duymaz.
func (s *HttpServer) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}

func buildFiberConfig(cfg *HttpServerConfig) (fiber.Config, error) {
	var config fiber.Config
	if cfg.ReadTimeout != "" {
		readTimeout, err := time.ParseDuration(cfg.ReadTimeout)
		if err != nil {
			return fiber.Config{}, fmt.Errorf("invalid read_timeout: %s", cfg.ReadTimeout)
		}
		config.ReadTimeout = readTimeout
	} else {
		config.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout != "" {
		writeTimeout, err := time.ParseDuration(cfg.WriteTimeout)
		if err != nil {
			return fiber.Config{}, fmt.Errorf("invalid write_timeout: %s", cfg.WriteTimeout)
		}
		config.WriteTimeout = writeTimeout
	} else {
		config.WriteTimeout = DefaultWriteTimeout
	}
	if cfg.ServerHeader != "" {
		config.ServerHeader = cfg.ServerHeader
	} else {
		config.ServerHeader = DefaultServerHeader
	}
	if cfg.BodyLimit != 0 {
		config.BodyLimit = cfg.BodyLimit
	} else {
		config.BodyLimit = DefaultBodyLimit
	}
	if cfg.Features.Proxy.Enabled {
		if cfg.Features.Proxy.ProxyHeader != "" {
			config.ProxyHeader = cfg.Features.Proxy.ProxyHeader
		}
		if len(cfg.Features.Proxy.TrustedProxies) > 0 {
			config.EnableTrustedProxyCheck = true
			config.TrustedProxies = cfg.Features.Proxy.TrustedProxies
		}
	}
	if cfg.ErrorHandler != nil {
		config.ErrorHandler = cfg.ErrorHandler
	}
	return config, nil
}

func InjectTokenSwaggerUI(t string) {
	token = t
}

func (s *HttpServer) Register(method, path string, handler core.HandlerFunc, reqFactory func() any) {
	genHandler := func(c *fiber.Ctx) error {
		// 1. Create concrete request struct using factory
		req := reqFactory()

		// 2. Parse request
		if err := c.BodyParser(req); err != nil && !errors.Is(err, fiber.ErrUnprocessableEntity) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		if err := c.ParamsParser(req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		if err := c.QueryParser(req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		if err := c.ReqHeaderParser(req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// 3. Validate request
		if validator, ok := req.(core.Request); ok {
			if err := validator.Validate(); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
			}
		}

		/*
			ctx, cancel := context.WithTimeout(c.UserContext(), 3*time.Second)
			defer cancel()
		*/

		ctx := auth.WithToken(c.Context(), c.Get("Authorization"))
		var resp core.BaseResponse[any] // Fix: Specify generic type

		var traceID string
		tx := apm.TransactionFromContext(ctx)
		if tx != nil { // Fix: Add nil check
			traceID = tx.TraceContext().Trace.String()
		}

		res, err := handler(ctx, req)

		// TODO: burası daha ayrıntılandırılabilir. Validasyon hataları ile domain hataları ayrılması lazım ve fonksiyonlar daha da sadeleştirilmeli. her errora trace id koymaya gerek yok
		if err != nil {
			resp.Success = false

			if errors.IsExtendError(err) {
				var extendErr *errors.ExtendError
				if errors.As(err, &extendErr) {
					resp.Error = &core.APIError{
						Code:    extendErr.Code,
						Details: extendErr.Metadata,
					}
					if errors.IsInfraError(extendErr) {
						resp.Error.Message = "Internal Server Error"
						// Only expose detailed message in dev mode or logs, here we keep it safe
						if resp.Error.Details == nil {
							resp.Error.Details = "Internal server error please control logs with trace ID: " + traceID
						}
						resp.Error.TraceID = traceID
						return c.Status(fiber.StatusBadGateway).JSON(resp)
					} else if errors.IsAppError(extendErr) {
						resp.Error.Message = "Service Unavailable"
						if resp.Error.Details == nil {
							resp.Error.Details = "Internal application error please control logs with trace ID: " + traceID
						}
						resp.Error.TraceID = traceID
						return c.Status(fiber.StatusServiceUnavailable).JSON(resp)
					} else if errors.IsDomainError(extendErr) {
						resp.Error.Message = extendErr.Error()
						return c.Status(fiber.StatusBadRequest).JSON(resp)
					} else if errors.IsAuthError(extendErr) {
						resp.Error.Message = extendErr.Error()
						return c.Status(fiber.StatusUnauthorized).JSON(resp)
					} else if errors.IsPermissionError(extendErr) {
						resp.Error.Message = extendErr.Error()
						return c.Status(fiber.StatusForbidden).JSON(resp)
					} else if errors.IsUnknownError(extendErr) {
						resp.Error.Message = "Internal Server Error"
						if resp.Error.Details == nil {
							resp.Error.Details = "Unknown error please control logs with trace ID: " + traceID
						}
						resp.Error.TraceID = traceID
						return c.Status(fiber.StatusInternalServerError).JSON(resp)
					}
				}
			} else if errors.Is(err, fiber.ErrNotFound) {
				resp.Error = &core.APIError{Message: "Resource not found"}
				return c.Status(fiber.StatusNotFound).JSON(resp)
			} else {
				// Fallback for other errors
				resp.Error = &core.APIError{Message: err.Error()}
				return c.Status(fiber.StatusInternalServerError).JSON(resp)
			}

		} else {
			resp.Success = true
			resp.Data = res
		}
		return c.JSON(resp)
	}

	s.app.Add(method, path, genHandler)
}
