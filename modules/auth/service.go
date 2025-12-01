package auth

import (
	"context"

	"github.com/Deepreo/bakend/errors"

	"time"

	"github.com/google/uuid"
)

// AuthService, authentication işlemlerini yönetir
type AuthService interface {
	// Token işlemleri
	GenerateTokens(ctx context.Context, authCtx *AuthContext) (*TokenPair, error)
	ValidateToken(ctx context.Context, token, tokenType string) (*AuthContext, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
	RevokeToken(ctx context.Context, token string) error

	// Session işlemleri
	CreateSession(ctx context.Context, authCtx *AuthContext) error
	GetSession(ctx context.Context, sessionID string) (*AuthContext, error)
	UpdateSession(ctx context.Context, sessionID string, authCtx *AuthContext) error
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error

	// Permission işlemleri
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error)
	HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
	HasRole(ctx context.Context, userID uuid.UUID, role string) (bool, error)
}

// TokenProvider, token oluşturma ve doğrulama işlemlerini yapar
type TokenProvider interface {
	GenerateAccessToken(authCtx *AuthContext) (string, error)
	GenerateRefreshToken(authCtx *AuthContext) (string, error)
	ValidateAccessToken(token string) (*AuthContext, error)
	ValidateRefreshToken(token string) (*AuthContext, error)
	GetTokenExpiration() time.Duration
	GetRefreshTokenExpiration() time.Duration
}

// SessionStore, session verilerini saklar
type SessionStore interface {
	Set(ctx context.Context, sessionID string, authCtx *AuthContext, expiration time.Duration) error
	Get(ctx context.Context, sessionID string) (*AuthContext, error)
	Delete(ctx context.Context, sessionID string) error
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
	Exists(ctx context.Context, sessionID string) (bool, error)
}

// PermissionProvider, kullanıcı permission ve role bilgilerini sağlar
type PermissionProvider interface {
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error)
	GetRolePermissions(ctx context.Context, role string) ([]string, error)
}

// TokenPair, access ve refresh token çiftini temsil eder
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// AuthServiceImpl, AuthService'in varsayılan implementasyonu
type AuthServiceImpl struct {
	tokenProvider      TokenProvider
	sessionStore       SessionStore
	permissionProvider PermissionProvider
}

// NewAuthService, yeni bir AuthService oluşturur
func NewAuthService(
	tokenProvider TokenProvider,
	sessionStore SessionStore,
	permissionProvider PermissionProvider,
) AuthService {
	return &AuthServiceImpl{
		tokenProvider:      tokenProvider,
		sessionStore:       sessionStore,
		permissionProvider: permissionProvider,
	}
}

// GenerateTokens, AuthContext için access ve refresh token oluşturur
func (s *AuthServiceImpl) GenerateTokens(ctx context.Context, authCtx *AuthContext) (*TokenPair, error) {
	// Kullanıcı permission ve role'lerini al
	permissions, err := s.permissionProvider.GetUserPermissions(ctx, authCtx.UserID)
	if err != nil {
		return nil, err
	}
	authCtx.WithPermissions(permissions...)

	roles, err := s.permissionProvider.GetUserRoles(ctx, authCtx.UserID)
	if err != nil {
		return nil, err
	}
	authCtx.WithRoles(roles...)

	// Access token oluştur
	authCtx.WithTokenType("access").WithExpiration(s.tokenProvider.GetTokenExpiration())
	accessToken, err := s.tokenProvider.GenerateAccessToken(authCtx)
	if err != nil {
		return nil, err
	}

	// Refresh token oluştur
	refreshAuthCtx := authCtx.Clone()
	refreshAuthCtx.WithTokenType("refresh").WithExpiration(s.tokenProvider.GetRefreshTokenExpiration())
	refreshToken, err := s.tokenProvider.GenerateRefreshToken(refreshAuthCtx)
	if err != nil {
		return nil, err
	}

	// Session oluştur
	if err := s.CreateSession(ctx, authCtx); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.tokenProvider.GetTokenExpiration().Seconds()),
		ExpiresAt:    authCtx.ExpiresAt,
	}, nil
}

// ValidateToken, token'ı doğrular ve AuthContext döner
func (s *AuthServiceImpl) ValidateToken(ctx context.Context, token string, tokenType string) (*AuthContext, error) {
	if tokenType != "access" && tokenType != "refresh" {
		return nil, errors.AuthError(errors.New("invalid token type"))
	}

	var authCtx *AuthContext
	var err error

	if tokenType == "access" {
		authCtx, err = s.tokenProvider.ValidateAccessToken(token)
	} else {
		authCtx, err = s.tokenProvider.ValidateRefreshToken(token)
	}
	if err != nil {
		return nil, err
	}

	// Token geçerliliğini kontrol et
	if err := authCtx.Validate(); err != nil {
		return nil, err
	}

	// Session'ı kontrol et
	exists, err := s.sessionStore.Exists(ctx, authCtx.SessionID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.AuthError(errors.New("session not found"))
	}

	return authCtx, nil
}

// RefreshToken, refresh token kullanarak yeni token çifti oluşturur
func (s *AuthServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	authCtx, err := s.tokenProvider.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if err := authCtx.Validate(); err != nil {
		return nil, err
	}

	// Session'ı kontrol et
	exists, err := s.sessionStore.Exists(ctx, authCtx.SessionID)
	if err != nil {
		return nil, err
	}
	if !exists {
		// Eğer session yoksa, bu token daha önce kullanılmış (rotated) veya iptal edilmiş olabilir.
		// Güvenlik riski: Token reuse attempt!
		return nil, errors.AuthError(errors.New("session not found or token reused"))
	}

	// 1. Eski session'ı iptal et (Rotation)
	if err := s.RevokeSession(ctx, authCtx.SessionID); err != nil {
		return nil, err
	}

	// 2. Yeni token çifti oluştur (Yeni Session ID ile)
	// NewAuthContext otomatik olarak yeni bir SessionID üretir.
	newAuthCtx := NewAuthContext(authCtx.UserID, authCtx.CompanyID, authCtx.Email, authCtx.FullName, authCtx.IsVerified)

	// Eski yetkileri kopyala
	newAuthCtx.Permissions = authCtx.Permissions
	newAuthCtx.Roles = authCtx.Roles

	return s.GenerateTokens(ctx, newAuthCtx)
}

// RevokeToken, token'ı iptal eder
func (s *AuthServiceImpl) RevokeToken(ctx context.Context, token string) error {
	authCtx, err := s.tokenProvider.ValidateAccessToken(token)
	if err != nil {
		return err
	}

	return s.RevokeSession(ctx, authCtx.SessionID)
}

// CreateSession, yeni session oluşturur
func (s *AuthServiceImpl) CreateSession(ctx context.Context, authCtx *AuthContext) error {
	return s.sessionStore.Set(ctx, authCtx.SessionID, authCtx, s.tokenProvider.GetRefreshTokenExpiration())
}

// GetSession, session'ı getirir
func (s *AuthServiceImpl) GetSession(ctx context.Context, sessionID string) (*AuthContext, error) {
	return s.sessionStore.Get(ctx, sessionID)
}

// UpdateSession, session'ı günceller
func (s *AuthServiceImpl) UpdateSession(ctx context.Context, sessionID string, authCtx *AuthContext) error {
	return s.sessionStore.Set(ctx, sessionID, authCtx, s.tokenProvider.GetRefreshTokenExpiration())
}

// RevokeSession, session'ı iptal eder
func (s *AuthServiceImpl) RevokeSession(ctx context.Context, sessionID string) error {
	return s.sessionStore.Delete(ctx, sessionID)
}

// RevokeAllSessions, kullanıcının tüm session'larını iptal eder
func (s *AuthServiceImpl) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	return s.sessionStore.DeleteAllForUser(ctx, userID)
}

// GetUserPermissions, kullanıcının permission'larını getirir
func (s *AuthServiceImpl) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.permissionProvider.GetUserPermissions(ctx, userID)
}

// GetUserRoles, kullanıcının role'lerini getirir
func (s *AuthServiceImpl) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.permissionProvider.GetUserRoles(ctx, userID)
}

// HasPermission, kullanıcının belirtilen permission'a sahip olup olmadığını kontrol eder
func (s *AuthServiceImpl) HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, p := range permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// HasRole, kullanıcının belirtilen role'e sahip olup olmadığını kontrol eder
func (s *AuthServiceImpl) HasRole(ctx context.Context, userID uuid.UUID, role string) (bool, error) {
	roles, err := s.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}
	return false, nil
}
