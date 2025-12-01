package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthContext(t *testing.T) {
	// Test kullanıcısı oluştur
	userID := uuid.New()

	authCtx := NewAuthContext(userID, uuid.Max, "test@example.com", "Test User", true)
	authCtx.WithRoles("manager", "user")
	authCtx.WithPermissions("user.create", "user.read", "user.update")
	authCtx.WithExpiration(1 * time.Hour)

	// Temel kontroller
	if authCtx.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, authCtx.UserID)
	}

	if authCtx.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", authCtx.Email)
	}

	// Permission kontrolleri
	if !authCtx.HasPermission("user.create") {
		t.Error("Expected to have user.create permission")
	}

	if !authCtx.HasAllPermissions("user.create", "user.read") {
		t.Error("Expected to have all permissions")
	}

	if !authCtx.HasAnyPermission("user.delete", "user.create") {
		t.Error("Expected to have at least one permission")
	}

	// Role kontrolleri
	if !authCtx.HasRole("manager") {
		t.Error("Expected to have manager role")
	}

	if !authCtx.HasAnyRole("admin", "manager") {
		t.Error("Expected to have at least one role")
	}

	// Validation
	if err := authCtx.Validate(); err != nil {
		t.Errorf("Expected valid auth context, got error: %v", err)
	}

	t.Log("AuthContext tests passed!")
}

func TestSimpleTokenProvider(t *testing.T) {
	// Token provider oluştur
	provider := NewSimpleTokenProvider(
		"test-secret-key-that-is-32-chars-long",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	// Test auth context
	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.Max, "test@example.com", "Test User", true)
	authCtx.WithRoles("manager")
	authCtx.WithPermissions("user.create", "user.read")
	authCtx.WithExpiration(15 * time.Minute)

	// Access token oluştur
	accessToken, err := provider.GenerateAccessToken(authCtx)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	if accessToken == "" {
		t.Fatal("Expected non-empty access token")
	}

	// Token'ı doğrula
	validatedCtx, err := provider.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}

	// Doğrulanmış context'i kontrol et
	if validatedCtx.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, validatedCtx.UserID)
	}

	if validatedCtx.Email != authCtx.Email {
		t.Errorf("Expected email %s, got %s", authCtx.Email, validatedCtx.Email)
	}

	if !validatedCtx.HasRole("manager") {
		t.Error("Expected validated context to have manager role")
	}

	if !validatedCtx.HasPermission("user.create") {
		t.Error("Expected validated context to have user.create permission")
	}

	t.Log("SimpleTokenProvider tests passed!")
}

func TestJWTTokenProvider(t *testing.T) {
	// JWT token provider oluştur
	provider := NewJWTTokenProvider(
		"test-jwt-secret-key-that-is-32-chars-long",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	// Test auth context
	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.New(), "jwt@example.com", "JWT Test User", true)

	authCtx.WithRoles("admin")
	authCtx.WithPermissions("user.create", "user.read", "user.update", "user.delete")
	authCtx.WithExpiration(15 * time.Minute)

	// Access token oluştur
	accessToken, err := provider.GenerateAccessToken(authCtx)
	if err != nil {
		t.Fatalf("Failed to generate JWT access token: %v", err)
	}

	if accessToken == "" {
		t.Fatal("Expected non-empty JWT access token")
	}

	// Token'ı doğrula
	validatedCtx, err := provider.ValidateAccessToken(accessToken)
	if err != nil {
		t.Fatalf("Failed to validate JWT access token: %v", err)
	}

	// Doğrulanmış context'i kontrol et
	if validatedCtx.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, validatedCtx.UserID)
	}

	if validatedCtx.Email != authCtx.Email {
		t.Errorf("Expected email %s, got %s", authCtx.Email, validatedCtx.Email)
	}

	if !validatedCtx.HasRole("admin") {
		t.Error("Expected validated context to have admin role")
	}

	if !validatedCtx.HasPermission("user.delete") {
		t.Error("Expected validated context to have user.delete permission")
	}

	t.Log("JWTTokenProvider tests passed!")
}

func TestAuthService(t *testing.T) {
	// Auth system oluştur
	authSystem, err := NewTestAuthSystem()
	if err != nil {
		t.Fatalf("Failed to create test auth system: %v", err)
	}
	defer authSystem.Shutdown()

	// Test kullanıcısı setup et
	userID := uuid.New()
	err = authSystem.SetupTestUser(userID.String(), "service@example.com", "Service Test User", []string{"manager"})
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	// Auth context oluştur
	authCtx := NewAuthContext(userID, uuid.New(), "service@example.com", "Service Test User", true)

	// Token oluştur
	ctx := context.Background()
	tokenPair, err := authSystem.Service.GenerateTokens(ctx, authCtx)
	if err != nil {
		t.Fatalf("Failed to generate tokens: %v", err)
	}

	if tokenPair.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}

	if tokenPair.RefreshToken == "" {
		t.Fatal("Expected non-empty refresh token")
	}

	// Token'ı doğrula
	validatedCtx, err := authSystem.Service.ValidateToken(ctx, tokenPair.AccessToken, "access")
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if validatedCtx.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, validatedCtx.UserID)
	}

	// Permission kontrolü (manager role'ünden gelen permission'lar)
	if len(validatedCtx.Permissions) == 0 {
		t.Error("Expected to have permissions from manager role")
	}

	if len(validatedCtx.Roles) == 0 {
		t.Error("Expected to have roles")
	}

	t.Log("AuthService tests passed!")
}

func TestContextIntegration(t *testing.T) {
	// Auth system oluştur
	authSystem, err := NewTestAuthSystem()
	if err != nil {
		t.Fatalf("Failed to create test auth system: %v", err)
	}
	defer authSystem.Shutdown()

	// Test kullanıcısı
	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.New(), "context@example.com", "Context Test User", true)
	authCtx.WithRoles("user")
	authCtx.WithPermissions("user.read")

	// Context'e auth ekle
	ctx := context.Background()
	authContext := WithAuthContext(ctx, authCtx)

	// Context'ten auth al
	retrievedCtx, err := FromContext(authContext)
	if err != nil {
		t.Fatalf("Failed to get auth context: %v", err)
	}

	if retrievedCtx.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, retrievedCtx.UserID)
	}

	// Helper fonksiyon testleri
	retrievedUserID, err := GetUserID(authContext)
	if err != nil {
		t.Fatalf("Failed to get user ID from context: %v", err)
	}

	if retrievedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, retrievedUserID)
	}

	// Permission kontrolü
	hasPermission := HasPermissionInContext(authContext, "user.read")
	if !hasPermission {
		t.Error("Expected to have user.read permission in context")
	}

	// Role kontrolü
	hasRole := HasRoleInContext(authContext, "user")
	if !hasRole {
		t.Error("Expected to have user role in context")
	}

	t.Log("Context integration tests passed!")
}

func TestMemorySessionStore(t *testing.T) {
	// Session store oluştur
	store := NewMemorySessionStore(1 * time.Second)
	defer func() {
		if memStore, ok := store.(*MemorySessionStore); ok {
			memStore.StopCleanup()
		}
	}()

	// Test auth context
	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.New(), "session@example.com", "Session Test User", true)
	sessionID := "test-session-id"
	authCtx.WithSessionID(sessionID)

	ctx := context.Background()

	// Session set et
	err := store.Set(ctx, sessionID, authCtx, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	// Session'ı al
	retrievedCtx, err := store.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrievedCtx.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, retrievedCtx.UserID)
	}

	// Session exists kontrolü
	exists, err := store.Exists(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to check session existence: %v", err)
	}

	if !exists {
		t.Error("Expected session to exist")
	}

	// Session sil
	err = store.Delete(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Session artık mevcut olmamalı
	exists, err = store.Exists(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to check session existence after deletion: %v", err)
	}

	if exists {
		t.Error("Expected session to be deleted")
	}

	t.Log("MemorySessionStore tests passed!")
}

func BenchmarkSimpleTokenGeneration(b *testing.B) {
	provider := NewSimpleTokenProvider(
		"benchmark-secret-key-that-is-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"benchmark-issuer",
	)

	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.New(), "bench@example.com", "Benchmark User", true)
	authCtx.WithRoles("user")
	authCtx.WithPermissions("user.read")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := provider.GenerateAccessToken(authCtx)
		if err != nil {
			b.Fatalf("Failed to generate token: %v", err)
		}
	}
}

func BenchmarkJWTTokenGeneration(b *testing.B) {
	provider := NewJWTTokenProvider(
		"benchmark-jwt-secret-key-that-is-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"benchmark-issuer",
	)

	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.New(), "jwt-bench@example.com", "JWT Benchmark User", true)
	authCtx.WithRoles("user")
	authCtx.WithPermissions("user.read")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := provider.GenerateAccessToken(authCtx)
		if err != nil {
			b.Fatalf("Failed to generate JWT token: %v", err)
		}
	}
}

// Mock Handler for Middleware Tests
type mockRequest struct {
	Val string
}

func (m mockRequest) Validate() error {
	return nil
}

type mockResponse struct {
	Result string
}

type mockAuthHandler struct {
	called  bool
	authCtx *AuthContext
}

func (h *mockAuthHandler) Handle(ctx context.Context, req mockRequest) (mockResponse, error) {
	h.called = true
	h.authCtx, _ = FromContext(ctx)
	return mockResponse{Result: "ok"}, nil
}

func TestAuthMiddlewareWrappers(t *testing.T) {
	// Auth system oluştur
	authSystem, err := NewTestAuthSystem()
	if err != nil {
		t.Fatalf("Failed to create test auth system: %v", err)
	}
	defer authSystem.Shutdown()

	// Test kullanıcısı
	userID := uuid.New()
	authCtx := NewAuthContext(userID, uuid.New(), "middleware@example.com", "Middleware Test User", true)

	// Token oluştur
	tokenPair, err := authSystem.Service.GenerateTokens(context.Background(), authCtx)
	if err != nil {
		t.Fatalf("Failed to generate tokens: %v", err)
	}

	t.Run("WithAuthHandler - Success", func(t *testing.T) {
		handler := &mockAuthHandler{}
		wrappedHandler := WithAuthHandler[mockRequest, mockResponse](authSystem.Service, handler, func(r mockRequest) string {
			return tokenPair.AccessToken // Token extractor mock
		}, nil)

		req := mockRequest{Val: "test"}
		_, err := wrappedHandler.Handle(context.Background(), req)
		if err != nil {
			t.Errorf("Handler returned error: %v", err)
		}

		if !handler.called {
			t.Error("Handler was not called")
		}

		if handler.authCtx == nil || handler.authCtx.UserID != userID {
			t.Error("AuthContext was not passed correctly")
		}
	})

	t.Run("WithAuthHandler - Unauthorized", func(t *testing.T) {
		handler := &mockAuthHandler{}
		wrappedHandler := WithAuthHandler[mockRequest, mockResponse](authSystem.Service, handler, func(r mockRequest) string {
			return "invalid-token"
		}, nil)

		req := mockRequest{Val: "test"}
		_, err := wrappedHandler.Handle(context.Background(), req)
		if err == nil {
			t.Error("Expected error for invalid token, got nil")
		}

		if handler.called {
			t.Error("Handler should not have been called")
		}
	})

	t.Run("WithOptionalAuthHandler - Authenticated", func(t *testing.T) {
		handler := &mockAuthHandler{}
		wrappedHandler := WithOptionalAuthHandler[mockRequest, mockResponse](authSystem.Service, handler, func(r mockRequest) string {
			return tokenPair.AccessToken
		})

		req := mockRequest{Val: "test"}
		_, err := wrappedHandler.Handle(context.Background(), req)
		if err != nil {
			t.Errorf("Handler returned error: %v", err)
		}

		if !handler.called {
			t.Error("Handler was not called")
		}

		if handler.authCtx == nil {
			t.Error("AuthContext should be present")
		}
	})

	t.Run("WithOptionalAuthHandler - Unauthenticated", func(t *testing.T) {
		handler := &mockAuthHandler{}
		wrappedHandler := WithOptionalAuthHandler[mockRequest, mockResponse](authSystem.Service, handler, func(r mockRequest) string {
			return "" // No token
		})

		req := mockRequest{Val: "test"}
		_, err := wrappedHandler.Handle(context.Background(), req)
		if err != nil {
			t.Errorf("Handler returned error: %v", err)
		}

		if !handler.called {
			t.Error("Handler was not called")
		}

		if handler.authCtx != nil {
			t.Error("AuthContext should be nil")
		}
	})
}
