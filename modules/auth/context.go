package auth

import (
	"context"
	"time"

	"github.com/Deepreo/bakend/errors"
	"github.com/google/uuid"
)

// AuthContext, authentication ve authorization bilgilerini taşır
type AuthContext struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	CompanyID   uuid.UUID `json:"company_id"`
	FullName    string    `json:"full_name"`
	IsVerified  bool      `json:"is_verified"`
	Permissions []string  `json:"permissions"`
	Roles       []string  `json:"roles"`
	TokenType   string    `json:"token_type"` // "access" veya "refresh"
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SessionID   string    `json:"session_id"`
}

// AuthContextKey, context'te AuthContext'i saklamak için kullanılır
type contextKey string

const (
	AuthContextKey contextKey = "auth_context"
	AuthTokenKey   contextKey = "auth_token"
)

var (
	ErrAuthContextNotFound = errors.New("auth context not found")
	ErrInvalidAuthContext  = errors.AuthError(errors.New("invalid auth context"))
	ErrTokenExpired        = errors.AuthError(errors.New("token expired"))
	ErrPermissionDenied    = errors.PermissionError(errors.New("permission denied"))
	ErrRoleNotFound        = errors.PermissionError(errors.New("role not found"))
	ErrUserNotVerified     = errors.PermissionError(errors.New("user email not verified"))
	ErrInvalidTokenType    = errors.AuthError(errors.New("invalid token type"))
)

// NewAuthContext, yeni bir AuthContext oluşturur
func NewAuthContext(userID, companyID uuid.UUID, email, fullName string, isVerified bool) *AuthContext {
	return &AuthContext{
		UserID:      userID,
		Email:       email,
		CompanyID:   companyID,
		FullName:    fullName,
		IsVerified:  isVerified,
		Permissions: make([]string, 0),
		Roles:       make([]string, 0),
		TokenType:   "access",
		IssuedAt:    time.Now(),
		SessionID:   uuid.New().String(),
	}
}

// WithPermissions, AuthContext'e permission'lar ekler
func (ac *AuthContext) WithPermissions(permissions ...string) *AuthContext {
	ac.Permissions = append(ac.Permissions, permissions...)
	return ac
}

// WithRoles, AuthContext'e roller ekler
func (ac *AuthContext) WithRoles(roles ...string) *AuthContext {
	ac.Roles = append(ac.Roles, roles...)
	return ac
}

// WithTokenType, token tipini belirler
func (ac *AuthContext) WithTokenType(tokenType string) *AuthContext {
	ac.TokenType = tokenType
	return ac
}

// WithExpiration, token'ın bitiş süresini belirler
func (ac *AuthContext) WithExpiration(duration time.Duration) *AuthContext {
	ac.ExpiresAt = ac.IssuedAt.Add(duration)
	return ac
}

// WithSessionID, session ID'sini belirler
func (ac *AuthContext) WithSessionID(sessionID string) *AuthContext {
	ac.SessionID = sessionID
	return ac
}

// IsExpired, token'ın süresi bitmiş mi kontrol eder
func (ac *AuthContext) IsExpired() bool {
	if ac.ExpiresAt.IsZero() {
		return false // Süresiz token
	}
	return time.Now().After(ac.ExpiresAt)
}

// HasPermission, belirtilen permission'a sahip mi kontrol eder
func (ac *AuthContext) HasPermission(permission string) bool {
	for _, p := range ac.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission, belirtilen permission'lardan herhangi birine sahip mi kontrol eder
func (ac *AuthContext) HasAnyPermission(permissions ...string) bool {
	for _, permission := range permissions {
		if ac.HasPermission(permission) {
			return true
		}
	}
	return false
}

// HasAllPermissions, belirtilen tüm permission'lara sahip mi kontrol eder
func (ac *AuthContext) HasAllPermissions(permissions ...string) bool {
	for _, permission := range permissions {
		if !ac.HasPermission(permission) {
			return false
		}
	}
	return true
}

// HasRole, belirtilen role'e sahip mi kontrol eder
func (ac *AuthContext) HasRole(role string) bool {
	for _, r := range ac.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole, belirtilen role'lerden herhangi birine sahip mi kontrol eder
func (ac *AuthContext) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if ac.HasRole(role) {
			return true
		}
	}
	return false
}

// IsAccessToken, access token mi kontrol eder
func (ac *AuthContext) IsAccessToken() bool {
	return ac.TokenType == "access"
}

// IsRefreshToken, refresh token mi kontrol eder
func (ac *AuthContext) IsRefreshToken() bool {
	return ac.TokenType == "refresh"
}

// Validate, AuthContext'in geçerli olduğunu kontrol eder
func (ac *AuthContext) Validate() error {
	if ac.UserID == uuid.Nil {
		return ErrInvalidAuthContext
	}
	if ac.Email == "" {
		return ErrInvalidAuthContext
	}
	if ac.IsExpired() {
		return ErrTokenExpired
	}
	if ac.TokenType != "access" && ac.TokenType != "refresh" {
		return ErrInvalidTokenType
	}
	return nil
}

// RequireVerification, kullanıcının doğrulanmış olmasını gerektirir
func (ac *AuthContext) RequireVerification() error {
	if !ac.IsVerified {
		return ErrUserNotVerified
	}
	return nil
}

// RequirePermission, belirtilen permission'a sahip olunmasını gerektirir
func (ac *AuthContext) RequirePermission(permission string) error {
	if !ac.HasPermission(permission) {
		return ErrPermissionDenied
	}
	return nil
}

// RequireAnyPermission, belirtilen permission'lardan herhangi birine sahip olunmasını gerektirir
func (ac *AuthContext) RequireAnyPermission(permissions ...string) error {
	if !ac.HasAnyPermission(permissions...) {
		return ErrPermissionDenied
	}
	return nil
}

// RequireRole, belirtilen role'e sahip olunmasını gerektirir
func (ac *AuthContext) RequireRole(role string) error {
	if !ac.HasRole(role) {
		return ErrRoleNotFound
	}
	return nil
}

// RequireAccessToken, access token olmasını gerektirir
func (ac *AuthContext) RequireAccessToken() error {
	if !ac.IsAccessToken() {
		return ErrInvalidTokenType
	}
	return nil
}

// Clone, AuthContext'in bir kopyasını oluşturur
func (ac *AuthContext) Clone() *AuthContext {
	clone := &AuthContext{
		UserID:      ac.UserID,
		Email:       ac.Email,
		CompanyID:   ac.CompanyID,
		FullName:    ac.FullName,
		IsVerified:  ac.IsVerified,
		Permissions: make([]string, len(ac.Permissions)),
		Roles:       make([]string, len(ac.Roles)),
		TokenType:   ac.TokenType,
		IssuedAt:    ac.IssuedAt,
		ExpiresAt:   ac.ExpiresAt,
		SessionID:   ac.SessionID,
	}
	copy(clone.Permissions, ac.Permissions)
	copy(clone.Roles, ac.Roles)
	return clone
}

// Context işlemleri

// WithAuthContext, context'e AuthContext ekler
func WithAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	return context.WithValue(ctx, AuthContextKey, authCtx)
}

// FromContext, context'ten AuthContext'i alır
func FromContext(ctx context.Context) (*AuthContext, error) {
	authCtx, ok := ctx.Value(AuthContextKey).(*AuthContext)
	if !ok || authCtx == nil {
		return nil, ErrAuthContextNotFound
	}
	return authCtx, nil
}

// MustFromContext, context'ten AuthContext'i alır, bulamazsa panic yapar
func MustFromContext(ctx context.Context) *AuthContext {
	authCtx, err := FromContext(ctx)
	if err != nil {
		panic(err)
	}
	return authCtx
}

// GetUserID, context'ten user ID'yi alır
func GetUserID(ctx context.Context) (uuid.UUID, error) {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return authCtx.UserID, nil
}

// GetCompanyID, context'ten company ID'yi alır
func GetCompanyID(ctx context.Context) (uuid.UUID, error) {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return authCtx.CompanyID, nil
}

// HasPermissionInContext, context'teki kullanıcının belirtilen permission'a sahip olup olmadığını kontrol eder
func HasPermissionInContext(ctx context.Context, permission string) bool {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return false
	}
	return authCtx.HasPermission(permission)
}

// HasRoleInContext, context'teki kullanıcının belirtilen role'e sahip olup olmadığını kontrol eder
func HasRoleInContext(ctx context.Context, role string) bool {
	authCtx, err := FromContext(ctx)
	if err != nil {
		return false
	}
	return authCtx.HasRole(role)
}
