package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// Bu dosya AuthContext sisteminin nasıl kullanılacağına dair örnekleri içerir

// ExampleUsage, auth sisteminin temel kullanım örneği
func ExampleUsage() {
	// Auth sistemi oluştur
	authSystem, err := NewDefaultAuthSystem()
	if err != nil {
		log.Fatal("Auth system creation failed:", err)
	}
	defer authSystem.Shutdown()

	// Test kullanıcısı oluştur
	userID := uuid.New()

	// Permission provider'a test kullanıcısı ekle
	provider := authSystem.PermissionProvider.(*StaticPermissionProvider)
	provider.SetUserRoles(userID, []string{"manager"})

	// AuthContext oluştur
	authCtx := NewAuthContext(userID, uuid.Max, "test@example.com", "Test User", true)
	// Token oluştur
	tokenPair, err := authSystem.Service.GenerateTokens(context.Background(), authCtx)
	if err != nil {
		log.Fatal("Token generation failed:", err)
	}

	fmt.Printf("Access Token: %s\n", tokenPair.AccessToken)
	fmt.Printf("Expires At: %s\n", tokenPair.ExpiresAt)

	// Token'ı doğrula
	validatedCtx, err := authSystem.Service.ValidateToken(context.Background(), tokenPair.AccessToken, "access")
	if err != nil {
		log.Fatal("Token validation failed:", err)
	}

	fmt.Printf("User ID: %s\n", validatedCtx.UserID)
	fmt.Printf("Email: %s\n", validatedCtx.Email)
	fmt.Printf("Permissions: %v\n", validatedCtx.Permissions)
	fmt.Printf("Roles: %v\n", validatedCtx.Roles)
}

// ExampleAuthenticatedHandler, authentication decorator kullanım örneği
func ExampleAuthenticatedHandler() {
	authSystem, _ := NewDefaultAuthSystem()
	defer authSystem.Shutdown()

	// Request tipi (örnek)
	type CreateUserRequest struct {
		AuthToken string `json:"auth_token"`
		FullName  string `json:"full_name"`
		Email     string `json:"email"`
	}

	type CreateUserResponse struct {
		UserID  string `json:"user_id"`
		Message string `json:"message"`
	}

	// Token extractor
	tokenExtractor := func(req interface{}) string {
		if r, ok := req.(*CreateUserRequest); ok {
			return ExtractTokenFromBearer(r.AuthToken)
		}
		return ""
	}

	// Orjinal handler
	createUserHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		// Context'ten auth bilgilerini al
		authCtx, err := FromContext(ctx)
		if err != nil {
			return nil, err
		}

		// Permission kontrolü
		if err := authCtx.RequirePermission("user.create"); err != nil {
			return nil, err
		}

		r := req.(*CreateUserRequest)

		return &CreateUserResponse{
			UserID:  uuid.New().String(),
			Message: fmt.Sprintf("User %s created by %s", r.Email, authCtx.Email),
		}, nil
	}

	// Authentication ile wrap et
	authenticatedHandler := authSystem.Decorator.WithAuth(
		createUserHandler,
		tokenExtractor,
		&AuthRequiredOptions{
			RequireVerification: true,
			RequiredPermissions: []string{"user.create"},
		},
	)

	// Test kullanımı
	// Bu kısımda normalde HTTP request'ten gelen data kullanılır
	ctx := context.Background()
	req := &CreateUserRequest{
		AuthToken: "Bearer valid-token-here",
		FullName:  "New User",
		Email:     "newuser@example.com",
	}

	response, err := authenticatedHandler(ctx, req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Response: %+v\n", response)
	}
}

// ExamplePermissionGuard, permission guard kullanım örneği
func ExamplePermissionGuard() {
	authSystem, _ := NewDefaultAuthSystem()
	defer authSystem.Shutdown()

	// Test kullanıcısı oluştur
	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.Max, "test@example.com", "Test User", true)

	// Context'e auth ekle
	ctx := WithAuthContext(context.Background(), authCtx)

	// Permission kontrolü
	err := authSystem.PermissionGuard.CheckPermission(ctx, "user.create")
	if err != nil {
		fmt.Printf("Permission denied: %v\n", err)
	} else {
		fmt.Println("Permission granted")
	}

	// Multiple permission kontrolü
	err = authSystem.PermissionGuard.CheckAnyPermission(ctx, "user.create", "user.update")
	if err != nil {
		fmt.Printf("No required permissions: %v\n", err)
	} else {
		fmt.Println("At least one permission granted")
	}
}

// ExampleBusinessLogic, business logic'te auth context kullanım örneği
func ExampleBusinessLogic() {
	// User service example
	type UserService struct {
		authSystem *AuthSystem
	}

	// GetUserProfile, kullanıcının kendi profilini getiren method
	getUserProfile := func(ctx context.Context, userService *UserService) (interface{}, error) {
		// Auth context'i al
		authCtx, err := RequireAuth(ctx)
		if err != nil {
			return nil, err
		}

		// Doğrulanmış kullanıcı gerekli
		if err := authCtx.RequireVerification(); err != nil {
			return nil, err
		}

		// Kullanıcının kendi profili mi kontrol et (business logic)
		// Bu kısımda authCtx.UserID kullanarak veritabanından data çekilir

		return map[string]interface{}{
			"user_id":     authCtx.UserID,
			"email":       authCtx.Email,
			"full_name":   authCtx.FullName,
			"permissions": authCtx.Permissions,
		}, nil
	}

	// Admin-only operation
	adminOperation := func(ctx context.Context) (interface{}, error) {
		// Admin role gerekli
		authCtx, err := RequireRole(ctx, "admin")
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"message":     "Admin operation completed",
			"executed_by": authCtx.Email,
		}, nil
	}

	fmt.Println("Business logic examples defined")

	// Örnekleri kullanmak için fonksiyon pointerları
	_ = getUserProfile
	_ = adminOperation
}

// RequirePermissionGuard, permission guard helper
func RequirePermissionGuard(ctx context.Context) *PermissionGuard {
	// Bu normalde dependency injection ile sağlanır
	authSystem, _ := NewDefaultAuthSystem()
	return authSystem.PermissionGuard
}

// ExampleMiddlewareIntegration, middleware entegrasyon örneği
func ExampleMiddlewareIntegration() {
	authSystem, _ := NewDefaultAuthSystem()
	defer authSystem.Shutdown()

	// HTTP handler benzeri bir fonksiyon
	type HTTPRequest struct {
		Headers map[string]string
		Body    interface{}
	}

	type HTTPResponse struct {
		StatusCode int
		Body       interface{}
	}

	// Middleware fonksiyon
	authMiddleware := func(next func(context.Context, *HTTPRequest) *HTTPResponse) func(context.Context, *HTTPRequest) *HTTPResponse {
		return func(ctx context.Context, req *HTTPRequest) *HTTPResponse {
			// Authorization header'dan token al
			authHeader := req.Headers["Authorization"]
			token := ExtractTokenFromBearer(authHeader)

			if token == "" {
				return &HTTPResponse{
					StatusCode: 401,
					Body:       map[string]string{"error": "Authorization header required"},
				}
			}

			// Token'ı doğrula ve context'e ekle
			authCtx, err := authSystem.Middleware.WithAuthRequired(ctx, token, &AuthRequiredOptions{
				RequireVerification: true,
			})

			if err != nil {
				return &HTTPResponse{
					StatusCode: 401,
					Body:       map[string]string{"error": err.Error()},
				}
			}

			// Next handler'ı auth context ile çağır
			return next(authCtx, req)
		}
	}

	// Protected handler
	protectedHandler := func(ctx context.Context, req *HTTPRequest) *HTTPResponse {
		authCtx, _ := FromContext(ctx)

		return &HTTPResponse{
			StatusCode: 200,
			Body: map[string]interface{}{
				"message":     "Protected resource accessed",
				"user":        authCtx.Email,
				"permissions": authCtx.Permissions,
			},
		}
	}

	// Middleware'i uygula
	wrappedHandler := authMiddleware(protectedHandler)

	// Test request
	testReq := &HTTPRequest{
		Headers: map[string]string{
			"Authorization": "Bearer valid-token-here",
		},
		Body: nil,
	}

	response := wrappedHandler(context.Background(), testReq)
	fmt.Printf("Response: %+v\n", response)
}

// ExampleConfigUsage, konfigürasyon kullanım örneği
func ExampleConfigUsage() {
	// Custom config oluştur
	config := &AuthConfig{
		Token: &SimpleTokenConfig{
			SecretKey:              "my-super-secret-key-for-production-use",
			AccessTokenExpiration:  30 * time.Minute,
			RefreshTokenExpiration: 7 * 24 * time.Hour,
			Issuer:                 "my-app",
		},
		Session: &SessionConfig{
			CleanupInterval: 5 * time.Minute,
			MaxSessions:     10,
		},
		Enabled: true,
	}

	// Config ile auth system oluştur
	authSystem, err := NewAuthSystemWithConfig(config)
	if err != nil {
		log.Fatal("Auth system creation failed:", err)
	}
	defer authSystem.Shutdown()

	fmt.Println("Custom auth system created successfully")
}
