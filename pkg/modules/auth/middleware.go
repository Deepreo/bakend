package auth

import (
	"context"

	"github.com/Deepreo/bakend/pkg/core"
	"github.com/Deepreo/bakend/pkg/errors"
	"go.elastic.co/apm/v2"
)

// APM Span names
const (
	SpanAuthTokenValidation   = "auth.token.validation"
	SpanAuthPermissionCheck   = "auth.permission.check"
	SpanAuthRoleCheck         = "auth.role.check"
	SpanAuthVerificationCheck = "auth.verification.check"
	SpanAuthContextCreation   = "auth.context.creation"
	SpanAuthHandlerWrapper    = "auth.handler.wrapper"
	SpanAuthOptionalWrapper   = "auth.optional.wrapper"
)

// WithToken, context'e token ekler
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, AuthTokenKey, token)
}

// GetTokenFromContext, context'ten token'ı çıkarır
func GetTokenFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(AuthTokenKey).(string); ok {
		return ExtractTokenFromBearer(token)
	}
	return ""
}

// AuthMiddleware, authentication işlemlerini yönetir
type AuthMiddleware struct {
	authService AuthService
}

// NewAuthMiddleware, yeni bir AuthMiddleware oluşturur
func NewAuthMiddleware(authService AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// AuthRequiredOptions, authentication gereksinimlerini tanımlar
type AuthRequiredOptions struct {
	RequireVerification bool
	RequiredPermissions []string
	RequiredRoles       []string
	TokenType           string // "access" veya "refresh", boşsa "access" varsayılır
}

// WithAuthRequired, context'e authentication gereksinimlerini ekler
func (m *AuthMiddleware) WithAuthRequired(ctx context.Context, token string, options *AuthRequiredOptions) (context.Context, error) {
	span, ctx := apm.StartSpan(ctx, SpanAuthContextCreation, "auth")
	defer span.End()

	if options == nil {
		options = &AuthRequiredOptions{}
	}

	// Token'ı doğrula
	tokenSpan, _ := apm.StartSpan(ctx, SpanAuthTokenValidation, "auth.token")
	if options.TokenType == "" {
		options.TokenType = "access"
	}
	authCtx, err := m.authService.ValidateToken(ctx, token, options.TokenType)
	if err != nil {
		tokenSpan.End()
		return nil, err
	}
	tokenSpan.End()

	// Token tipini kontrol et
	if options.TokenType != "" && authCtx.TokenType != options.TokenType {
		return nil, ErrInvalidTokenType
	}

	// Doğrulama gereksinimlerini kontrol et
	if options.RequireVerification {
		verifySpan, _ := apm.StartSpan(ctx, SpanAuthVerificationCheck, "auth.verification")
		if err := authCtx.RequireVerification(); err != nil {
			verifySpan.End()
			return nil, err
		}
		verifySpan.End()
	}

	// Permission gereksinimlerini kontrol et
	if len(options.RequiredPermissions) > 0 {
		permSpan, _ := apm.StartSpan(ctx, SpanAuthPermissionCheck, "auth.permissions")
		if err := authCtx.RequireAnyPermission(options.RequiredPermissions...); err != nil {
			permSpan.End()
			return nil, err
		}
		permSpan.End()
	}

	// Role gereksinimlerini kontrol et
	if len(options.RequiredRoles) > 0 {
		roleSpan, _ := apm.StartSpan(ctx, SpanAuthRoleCheck, "auth.roles")
		for _, role := range options.RequiredRoles {
			if err := authCtx.RequireRole(role); err != nil {
				roleSpan.End()
				return nil, err
			}
		}
		roleSpan.End()
	}

	// Context'e AuthContext'i ekle
	return WithAuthContext(ctx, authCtx), nil
}

// WithOptionalAuth, opsiyonel authentication işlemi yapar
func (m *AuthMiddleware) WithOptionalAuth(ctx context.Context, token string) context.Context {
	span, ctx := apm.StartSpan(ctx, SpanAuthOptionalWrapper, "auth.optional")
	defer span.End()

	if token == "" {
		return ctx
	}

	tokenSpan, _ := apm.StartSpan(ctx, SpanAuthTokenValidation, "auth.token")
	authCtx, err := m.authService.ValidateToken(ctx, token, "access")
	tokenSpan.End()

	if err != nil {
		return ctx // Hata olursa context'i olduğu gibi döner
	}

	return WithAuthContext(ctx, authCtx)
}

// AuthDecorator, fonksiyonları authentication ile sarar
type AuthDecorator struct {
	middleware *AuthMiddleware
}

// NewAuthDecorator, yeni bir AuthDecorator oluşturur
func NewAuthDecorator(authService AuthService) *AuthDecorator {
	return &AuthDecorator{
		middleware: NewAuthMiddleware(authService),
	}
}

// GenericHandlerDecorator, jenerik handler'lar için authentication decorator'u
type GenericHandlerDecorator struct {
	middleware *AuthMiddleware
}

// NewGenericHandlerDecorator, yeni bir GenericHandlerDecorator oluşturur
func NewGenericHandlerDecorator(authService AuthService) *GenericHandlerDecorator {
	return &GenericHandlerDecorator{
		middleware: NewAuthMiddleware(authService),
	}
}

// WithAuthHandler, jenerik handler'ları authentication ile sarar
func WithAuthHandler[R core.Request, Res core.Response](
	authService AuthService,
	handler core.HandlerInterface[R, Res],
	tokenExtractor func(R) string,
	options *AuthRequiredOptions,
) core.HandlerInterface[R, Res] {
	middleware := NewAuthMiddleware(authService)
	return &authenticatedHandlerWrapper[R, Res]{
		handler:        handler,
		middleware:     middleware,
		tokenExtractor: tokenExtractor,
		options:        options,
	}
}

// WithAuthHandlerFromContext, context'ten token çıkararak handler'ları authentication ile sarar
func WithAuthHandlerFromContext[R core.Request, Res core.Response](
	authService AuthService,
	handler core.HandlerInterface[R, Res],
	options *AuthRequiredOptions,
) core.HandlerInterface[R, Res] {
	middleware := NewAuthMiddleware(authService)
	return &contextTokenHandlerWrapper[R, Res]{
		handler:    handler,
		middleware: middleware,
		options:    options,
	}
}

// WithOptionalAuthHandler, jenerik handler'ları opsiyonel authentication ile sarar
func WithOptionalAuthHandler[R core.Request, Res core.Response](
	authService AuthService,
	handler core.HandlerInterface[R, Res],
	tokenExtractor func(R) string,
) core.HandlerInterface[R, Res] {
	middleware := NewAuthMiddleware(authService)
	return &optionalAuthHandlerWrapper[R, Res]{
		handler:        handler,
		middleware:     middleware,
		tokenExtractor: tokenExtractor,
	}
}

// WithOptionalAuthHandlerFromContext, context'ten token çıkararak handler'ları opsiyonel authentication ile sarar
func WithOptionalAuthHandlerFromContext[R core.Request, Res core.Response](
	authService AuthService,
	handler core.HandlerInterface[R, Res],
) core.HandlerInterface[R, Res] {
	middleware := NewAuthMiddleware(authService)
	return &optionalContextTokenHandlerWrapper[R, Res]{
		handler:    handler,
		middleware: middleware,
	}
}

// contextTokenHandlerWrapper, context'ten token çıkaran authentication wrapper'u
type contextTokenHandlerWrapper[R core.Request, Res core.Response] struct {
	handler    core.HandlerInterface[R, Res]
	middleware *AuthMiddleware
	options    *AuthRequiredOptions
}

// Handle, context'ten token çıkararak authentication kontrolü yapar
func (w *contextTokenHandlerWrapper[R, Res]) Handle(ctx context.Context, req R) (Res, error) {
	span, ctx := apm.StartSpan(ctx, SpanAuthHandlerWrapper, "auth.handler")
	defer span.End()

	// Context'ten token'ı çıkar
	token := GetTokenFromContext(ctx)
	if token == "" {
		var zero Res
		return zero, errors.AuthError(errors.New("authentication token required"))
	}
	// Authentication'ı uygula
	authCtx, err := w.middleware.WithAuthRequired(ctx, token, w.options)
	if err != nil {
		var zero Res
		return zero, errors.AuthError(err)
	}

	// Orjinal handler'ı çağır
	return w.handler.Handle(authCtx, req)
}

// optionalContextTokenHandlerWrapper, context'ten token çıkaran opsiyonel authentication wrapper'u
type optionalContextTokenHandlerWrapper[R core.Request, Res core.Response] struct {
	handler    core.HandlerInterface[R, Res]
	middleware *AuthMiddleware
}

// Handle, context'ten token çıkararak opsiyonel authentication kontrolü yapar
func (w *optionalContextTokenHandlerWrapper[R, Res]) Handle(ctx context.Context, req R) (Res, error) {
	span, ctx := apm.StartSpan(ctx, SpanAuthOptionalWrapper, "auth.optional")
	defer span.End()

	// Context'ten token'ı çıkar
	token := GetTokenFromContext(ctx)

	// Opsiyonel authentication'ı uygula
	authCtx := w.middleware.WithOptionalAuth(ctx, token)

	// Orjinal handler'ı çağır
	return w.handler.Handle(authCtx, req)
}

// authenticatedHandlerWrapper, authentication gerektiren handler'ları sarar
type authenticatedHandlerWrapper[R core.Request, Res core.Response] struct {
	handler        core.HandlerInterface[R, Res]
	middleware     *AuthMiddleware
	tokenExtractor func(R) string
	options        *AuthRequiredOptions
}

// Handle, authentication kontrolü yaparak handler'ı çalıştırır
func (w *authenticatedHandlerWrapper[R, Res]) Handle(ctx context.Context, req R) (Res, error) {
	span, ctx := apm.StartSpan(ctx, SpanAuthHandlerWrapper, "auth.handler")
	defer span.End()

	// Token'ı çıkar
	token := w.tokenExtractor(req)
	if token == "" {
		var zero Res
		return zero, errors.AuthError(errors.New("authentication token required"))
	}

	// Authentication'ı uygula
	authCtx, err := w.middleware.WithAuthRequired(ctx, token, w.options)
	if err != nil {
		var zero Res
		return zero, errors.AuthError(err)
	}

	// Orjinal handler'ı çağır
	return w.handler.Handle(authCtx, req)
}

// optionalAuthHandlerWrapper, opsiyonel authentication ile handler'ları sarar
type optionalAuthHandlerWrapper[R core.Request, Res core.Response] struct {
	handler        core.HandlerInterface[R, Res]
	middleware     *AuthMiddleware
	tokenExtractor func(R) string
}

// Handle, opsiyonel authentication kontrolü yaparak handler'ı çalıştırır
func (w *optionalAuthHandlerWrapper[R, Res]) Handle(ctx context.Context, req R) (Res, error) {
	span, ctx := apm.StartSpan(ctx, SpanAuthOptionalWrapper, "auth.optional")
	defer span.End()

	// Token'ı çıkar
	token := w.tokenExtractor(req)

	// Opsiyonel authentication'ı uygula
	authCtx := w.middleware.WithOptionalAuth(ctx, token)

	// Orjinal handler'ı çağır
	return w.handler.Handle(authCtx, req)
}

// AuthenticatedHandler, authentication gereksinimi olan handler'lar için tip tanımı
type AuthenticatedHandler func(ctx context.Context, req interface{}) (interface{}, error)

// WithAuth, handler'ı authentication ile sarar
func (d *AuthDecorator) WithAuth(
	handler AuthenticatedHandler,
	tokenExtractor func(interface{}) string,
	options *AuthRequiredOptions,
) AuthenticatedHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		// Token'ı çıkar
		token := tokenExtractor(req)
		if token == "" {
			return nil, errors.AuthError(errors.New("authentication token required"))
		}

		// Authentication'ı uygula
		authCtx, err := d.middleware.WithAuthRequired(ctx, token, options)
		if err != nil {
			return nil, errors.AuthError(err)
		}

		// Orjinal handler'ı çağır
		return handler(authCtx, req)
	}
}

// WithOptionalAuth, handler'ı opsiyonel authentication ile sarar
func (d *AuthDecorator) WithOptionalAuth(
	handler AuthenticatedHandler,
	tokenExtractor func(interface{}) string,
) AuthenticatedHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		// Token'ı çıkar
		token := tokenExtractor(req)

		// Opsiyonel authentication'ı uygula
		authCtx := d.middleware.WithOptionalAuth(ctx, token)

		// Orjinal handler'ı çağır
		return handler(authCtx, req)
	}
}

// PermissionGuard, permission tabanlı guard işlemleri yapar
type PermissionGuard struct {
	authService AuthService
}

// NewPermissionGuard, yeni bir PermissionGuard oluşturur
func NewPermissionGuard(authService AuthService) *PermissionGuard {
	return &PermissionGuard{
		authService: authService,
	}
}

// CheckPermission, context'teki kullanıcının permission'ını kontrol eder
func (g *PermissionGuard) CheckPermission(ctx context.Context, permission string) error {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return err
	}

	return authCtx.RequirePermission(permission)
}

// CheckAnyPermission, context'teki kullanıcının permission'larından herhangi birine sahip olup olmadığını kontrol eder
func (g *PermissionGuard) CheckAnyPermission(ctx context.Context, permissions ...string) error {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return err
	}

	return authCtx.RequireAnyPermission(permissions...)
}

// CheckRole, context'teki kullanıcının role'ünü kontrol eder
func (g *PermissionGuard) CheckRole(ctx context.Context, role string) error {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return err
	}

	return authCtx.RequireRole(role)
}

// Kullanışlı helper fonksiyonlar

// RequireAuth, basit authentication kontrolü yapar
func RequireAuth(ctx context.Context) (*AuthContext, error) {
	return FromContext(ctx)
}

// RequireVerifiedUser, doğrulanmış kullanıcı gereksinimi kontrol eder
func RequireVerifiedUser(ctx context.Context) (*AuthContext, error) {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}

	if err := authCtx.RequireVerification(); err != nil {
		return nil, err
	}

	return authCtx, nil
}

// RequirePermission, belirtilen permission gereksinimini kontrol eder
func RequirePermission(ctx context.Context, permission string) (*AuthContext, error) {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}

	if err := authCtx.RequirePermission(permission); err != nil {
		return nil, err
	}

	return authCtx, nil
}

// RequireRole, belirtilen role gereksinimini kontrol eder
func RequireRole(ctx context.Context, role string) (*AuthContext, error) {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}

	if err := authCtx.RequireRole(role); err != nil {
		return nil, err
	}

	return authCtx, nil
}

/*
GenericHandlerDecorator Kullanım Örneği:

type LoginRequest struct {
    Token    string `json:"token"`
    Username string `json:"username"`
    Password string `json:"password"`
}

type LoginResponse struct {
    Success bool   `json:"success"`
    UserID  string `json:"user_id"`
}

type LoginHandler struct{}

func (h *LoginHandler) Handle(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
    // Authentication context'i ctx'ten alınabilir
    authCtx, err := FromContext(ctx)
    if err != nil {
        // Bu bir public endpoint ise err nil olabilir
    }

    // Login logic buraya
    return &LoginResponse{Success: true, UserID: "123"}, nil
}

// Kullanım:
func main() {
    authService := NewAuthService(...) // AuthService implement edilmiş olması gerekir
    loginHandler := &LoginHandler{}

    // 1. Request'ten token çıkaran wrapper (geleneksel)
    authenticatedHandler := WithAuthHandler(
        authService,
        loginHandler,
        func(req *LoginRequest) string { return req.Token }, // Token extractor
        &AuthRequiredOptions{
            RequireVerification: true,
            RequiredPermissions: []string{"user:login"},
        },
    )

    // 2. Context'ten token çıkaran wrapper (yeni)
    contextAuthHandler := WithAuthHandlerFromContext(
        authService,
        loginHandler,
        &AuthRequiredOptions{
            RequireVerification: true,
            RequiredPermissions: []string{"user:login"},
        },
    )

    // 3. Opsiyonel authentication wrapper (geleneksel)
    optionalAuthHandler := WithOptionalAuthHandler(
        authService,
        loginHandler,
        func(req *LoginRequest) string { return req.Token },
    )

    // 4. Context'ten opsiyonel authentication wrapper (yeni)
    contextOptionalHandler := WithOptionalAuthHandlerFromContext(
        authService,
        loginHandler,
    )

    // Kullanım 1: Request'ten token
    ctx := context.Background()
    req := &LoginRequest{Token: "jwt-token-here", Username: "user", Password: "pass"}
    response1, err := authenticatedHandler.Handle(ctx, req)

    // Kullanım 2: Context'ten token
    ctx = WithToken(context.Background(), "jwt-token-here")
    req = &LoginRequest{Username: "user", Password: "pass"} // Token field'ına gerek yok
    response2, err := contextAuthHandler.Handle(ctx, req)

    // Her iki response da aynı sonucu verir
    _ = response1
    _ = response2
    _ = err
}
*/

// APM Tracing Helper Functions

// StartAuthSpan, auth işlemleri için APM span başlatır
func StartAuthSpan(ctx context.Context, name, spanType string) (*apm.Span, context.Context) {
	return apm.StartSpan(ctx, name, spanType)
}

// StartAuthSpanWithOperation, operation bilgisi ile auth span başlatır
func StartAuthSpanWithOperation(ctx context.Context, operation, spanType string) (*apm.Span, context.Context) {
	spanName := "auth." + operation
	return apm.StartSpan(ctx, spanName, spanType)
}

// TraceAuthOperation, auth işlemini APM ile trace eder
func TraceAuthOperation(ctx context.Context, operation string, fn func(context.Context) error) error {
	span, ctx := StartAuthSpanWithOperation(ctx, operation, "auth")
	defer span.End()

	if err := fn(ctx); err != nil {
		span.Outcome = "failure"
		return err
	}

	span.Outcome = "success"
	return nil
}

// TraceAuthOperationWithResult, sonuçlu auth işlemini APM ile trace eder
func TraceAuthOperationWithResult[T any](ctx context.Context, operation string, fn func(context.Context) (T, error)) (T, error) {
	span, ctx := StartAuthSpanWithOperation(ctx, operation, "auth")
	defer span.End()

	result, err := fn(ctx)
	if err != nil {
		span.Outcome = "failure"
		var zero T
		return zero, err
	}

	span.Outcome = "success"
	return result, nil
}
