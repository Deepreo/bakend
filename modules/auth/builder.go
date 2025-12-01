package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuthSystem, tüm auth bileşenlerini içeren sistem
type AuthSystem struct {
	Config             *AuthConfig
	Service            AuthService
	Middleware         *AuthMiddleware
	Decorator          *AuthDecorator
	PermissionGuard    *PermissionGuard
	TokenProvider      TokenProvider
	SessionStore       SessionStore
	PermissionProvider PermissionProvider
}

// AuthBuilder, auth sistemi oluşturucu
type AuthBuilder struct {
	config             *AuthConfig
	tokenProvider      TokenProvider
	sessionStore       SessionStore
	permissionProvider PermissionProvider
}

// NewAuthBuilder, yeni auth builder oluşturur
func NewAuthBuilder() *AuthBuilder {
	return &AuthBuilder{
		config: DefaultAuthConfig(),
	}
}

// WithConfig, builder'a config ekler
func (b *AuthBuilder) WithConfig(config *AuthConfig) *AuthBuilder {
	b.config = config
	return b
}

// WithTokenProvider, custom token provider ekler
func (b *AuthBuilder) WithTokenProvider(provider TokenProvider) *AuthBuilder {
	b.tokenProvider = provider
	return b
}

// WithSessionStore, custom session store ekler
func (b *AuthBuilder) WithSessionStore(store SessionStore) *AuthBuilder {
	b.sessionStore = store
	return b
}

// WithPermissionProvider, custom permission provider ekler
func (b *AuthBuilder) WithPermissionProvider(provider PermissionProvider) *AuthBuilder {
	b.permissionProvider = provider
	return b
}

// Build, auth sistemini oluşturur
func (b *AuthBuilder) Build() (*AuthSystem, error) {
	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	if !b.config.Enabled {
		return &AuthSystem{
			Config: b.config,
		}, nil
	}

	// Token provider oluştur
	if b.tokenProvider == nil {
		var provider TokenProvider
		var err error

		if b.config.UseJWT {
			provider, err = b.config.JWT.CreateTokenProvider()
		} else {
			provider, err = b.config.Token.CreateTokenProvider()
		}

		if err != nil {
			return nil, err
		}
		b.tokenProvider = provider
	}

	// Session store oluştur
	if b.sessionStore == nil {
		b.sessionStore = NewMemorySessionStore(b.config.Session.CleanupInterval)
	}

	// Permission provider oluştur
	if b.permissionProvider == nil {
		b.permissionProvider = NewStaticPermissionProvider()
	}

	// Auth service oluştur
	authService := NewAuthService(b.tokenProvider, b.sessionStore, b.permissionProvider)

	// Middleware ve decorator oluştur
	middleware := NewAuthMiddleware(authService)
	decorator := NewAuthDecorator(authService)
	guard := NewPermissionGuard(authService)

	return &AuthSystem{
		Config:             b.config,
		Service:            authService,
		Middleware:         middleware,
		Decorator:          decorator,
		PermissionGuard:    guard,
		TokenProvider:      b.tokenProvider,
		SessionStore:       b.sessionStore,
		PermissionProvider: b.permissionProvider,
	}, nil
}

// IsEnabled, auth sisteminin aktif olup olmadığını kontrol eder
func (s *AuthSystem) IsEnabled() bool {
	return s.Config != nil && s.Config.Enabled
}

// Shutdown, auth sistemini kapatır (cleanup işlemleri için)
func (s *AuthSystem) Shutdown() {
	if s.SessionStore != nil {
		if memStore, ok := s.SessionStore.(*MemorySessionStore); ok {
			memStore.StopCleanup()
		}
	}
}

// Quick setup functions

// NewDefaultAuthSystem, varsayılan auth sistemi oluşturur
func NewDefaultAuthSystem() (*AuthSystem, error) {
	return NewAuthBuilder().Build()
}

// NewAuthSystemWithConfig, konfigürasyon ile auth sistemi oluşturur
func NewAuthSystemWithConfig(config *AuthConfig) (*AuthSystem, error) {
	return NewAuthBuilder().WithConfig(config).Build()
}

// NewDisabledAuthSystem, kapalı auth sistemi oluşturur (test için)
func NewDisabledAuthSystem() *AuthSystem {
	config := DefaultAuthConfig()
	config.Enabled = false

	system, _ := NewAuthBuilder().WithConfig(config).Build()
	return system
}

// Development/Testing helpers

// NewTestAuthSystem, test ortamı için auth sistemi oluşturur
func NewTestAuthSystem() (*AuthSystem, error) {
	config := DefaultAuthConfig()
	config.Token.SecretKey = "test-secret-key-for-development-only-32chars"
	config.Token.AccessTokenExpiration = 1 * time.Hour
	config.Token.RefreshTokenExpiration = 24 * time.Hour
	config.JWT.SecretKey = "test-jwt-secret-key-for-development-only-32chars"
	config.JWT.AccessTokenExpiration = 1 * time.Hour
	config.JWT.RefreshTokenExpiration = 24 * time.Hour
	config.Session.CleanupInterval = 1 * time.Minute
	config.UseJWT = false // Test için simple token kullan

	return NewAuthBuilder().WithConfig(config).Build()
}

// NewTestAuthSystemWithJWT, JWT ile test ortamı için auth sistemi oluşturur
func NewTestAuthSystemWithJWT() (*AuthSystem, error) {
	config := DefaultAuthConfig()
	config.JWT.SecretKey = "test-jwt-secret-key-for-development-only-32chars"
	config.JWT.AccessTokenExpiration = 1 * time.Hour
	config.JWT.RefreshTokenExpiration = 24 * time.Hour
	config.Session.CleanupInterval = 1 * time.Minute
	config.UseJWT = true // JWT kullan

	return NewAuthBuilder().WithConfig(config).Build()
}

// SetupTestUser, test kullanıcısı oluşturur
func (s *AuthSystem) SetupTestUser(userID string, email string, fullName string, roles []string) error {
	if !s.IsEnabled() {
		return errors.New("auth system is disabled")
	}

	provider, ok := s.PermissionProvider.(*StaticPermissionProvider)
	if !ok {
		return errors.New("test user setup only works with StaticPermissionProvider")
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}

	// Kullanıcıya roller ata
	provider.SetUserRoles(userUUID, roles)

	return nil
}

// Utility functions

// ExtractTokenFromBearer, "Bearer token" formatından token'ı çıkarır
func ExtractTokenFromBearer(bearerToken string) string {
	stringPrefix := "Bearer "
	if strings.HasPrefix(bearerToken, stringPrefix) {
		return bearerToken[len(stringPrefix):]
	}
	return ""
}

// CreateBearerToken, token'ı "Bearer token" formatına çevirir
func CreateBearerToken(token string) string {
	return "Bearer " + token
}
