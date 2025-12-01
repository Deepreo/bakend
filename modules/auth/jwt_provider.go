package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTClaims, JWT token'ında saklanan claim'leri temsil eder
type JWTClaims struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	FullName    string   `json:"full_name"`
	CompanyID   *string  `json:"company_id,omitempty"`
	IsVerified  bool     `json:"is_verified"`
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	TokenType   string   `json:"token_type"`
	SessionID   string   `json:"session_id"`
	jwt.RegisteredClaims
}

// JWTTokenProvider, JWT tabanlı token provider implementasyonu
type JWTTokenProvider struct {
	secretKey              []byte
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
	issuer                 string
}

// NewJWTTokenProvider, yeni bir JWT token provider oluşturur
func NewJWTTokenProvider(
	secretKey string,
	accessTokenExpiration time.Duration,
	refreshTokenExpiration time.Duration,
	issuer string,
) TokenProvider {
	return &JWTTokenProvider{
		secretKey:              []byte(secretKey),
		accessTokenExpiration:  accessTokenExpiration,
		refreshTokenExpiration: refreshTokenExpiration,
		issuer:                 issuer,
	}
}

// GenerateAccessToken, access token oluşturur
func (p *JWTTokenProvider) GenerateAccessToken(authCtx *AuthContext) (string, error) {
	return p.generateToken(authCtx, p.accessTokenExpiration)
}

// GenerateRefreshToken, refresh token oluşturur
func (p *JWTTokenProvider) GenerateRefreshToken(authCtx *AuthContext) (string, error) {
	return p.generateToken(authCtx, p.refreshTokenExpiration)
}

// ValidateAccessToken, access token'ı doğrular
func (p *JWTTokenProvider) ValidateAccessToken(tokenString string) (*AuthContext, error) {
	return p.validateToken(tokenString, "access")
}

// ValidateRefreshToken, refresh token'ı doğrular
func (p *JWTTokenProvider) ValidateRefreshToken(tokenString string) (*AuthContext, error) {
	return p.validateToken(tokenString, "refresh")
}

// GetTokenExpiration, access token süresini döner
func (p *JWTTokenProvider) GetTokenExpiration() time.Duration {
	return p.accessTokenExpiration
}

// GetRefreshTokenExpiration, refresh token süresini döner
func (p *JWTTokenProvider) GetRefreshTokenExpiration() time.Duration {
	return p.refreshTokenExpiration
}

// generateToken, JWT token oluşturur
func (p *JWTTokenProvider) generateToken(authCtx *AuthContext, expiration time.Duration) (string, error) {
	now := time.Now()
	exp := now.Add(expiration)

	claims := JWTClaims{
		UserID: authCtx.UserID.String(),
		Email:  authCtx.Email,
		CompanyID: func() *string {
			if authCtx.CompanyID != uuid.Nil {
				cid := authCtx.CompanyID.String()
				return &cid
			} else {
				return nil
			}
		}(),
		FullName:    authCtx.FullName,
		IsVerified:  authCtx.IsVerified,
		Permissions: authCtx.Permissions,
		Roles:       authCtx.Roles,
		TokenType:   authCtx.TokenType,
		SessionID:   authCtx.SessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    p.issuer,
			Subject:   authCtx.UserID.String(),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.secretKey)
}

// validateToken, JWT token'ı doğrular
func (p *JWTTokenProvider) validateToken(tokenString string, expectedTokenType string) (*AuthContext, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return p.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Token tipini kontrol et
	if claims.TokenType != expectedTokenType {
		return nil, ErrInvalidTokenType
	}

	// User ID'yi parse et
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	// AuthContext'i oluştur
	authCtx := &AuthContext{
		UserID: userID,
		Email:  claims.Email,
		CompanyID: func() uuid.UUID {
			if claims.CompanyID != nil {
				cid, err := uuid.Parse(*claims.CompanyID)
				if err == nil {
					return cid
				}
			}
			return uuid.Nil
		}(),
		FullName:    claims.FullName,
		IsVerified:  claims.IsVerified,
		Permissions: claims.Permissions,
		Roles:       claims.Roles,
		TokenType:   claims.TokenType,
		SessionID:   claims.SessionID,
		IssuedAt:    claims.IssuedAt.Time,
		ExpiresAt:   claims.ExpiresAt.Time,
	}

	return authCtx, nil
}

// JWTConfig, JWT konfigürasyon yapısı
type JWTConfig struct {
	SecretKey              string        `mapstructure:"secret_key" json:"secret_key"`
	AccessTokenExpiration  time.Duration `mapstructure:"access_token_expiration" json:"access_token_expiration"`
	RefreshTokenExpiration time.Duration `mapstructure:"refresh_token_expiration" json:"refresh_token_expiration"`
	Issuer                 string        `mapstructure:"issuer" json:"issuer"`
}

// DefaultJWTConfig, varsayılan JWT konfigürasyonu
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		SecretKey:              "your-secret-key-here", // Üretimde mutlaka değiştirilmeli
		AccessTokenExpiration:  15 * time.Minute,       // 15 dakika
		RefreshTokenExpiration: 7 * 24 * time.Hour,     // 7 gün
		Issuer:                 "bakend",
	}
}

// Validate, JWT konfigürasyonunu doğrular
func (c *JWTConfig) Validate() error {
	if c.SecretKey == "" {
		return errors.New("JWT secret key cannot be empty")
	}
	if len(c.SecretKey) < 32 {
		return errors.New("JWT secret key must be at least 32 characters")
	}
	if c.AccessTokenExpiration <= 0 {
		return errors.New("access token expiration must be positive")
	}
	if c.RefreshTokenExpiration <= 0 {
		return errors.New("refresh token expiration must be positive")
	}
	if c.RefreshTokenExpiration <= c.AccessTokenExpiration {
		return errors.New("refresh token expiration must be greater than access token expiration")
	}
	return nil
}

// CreateTokenProvider, konfigürasyona göre token provider oluşturur
func (c *JWTConfig) CreateTokenProvider() (TokenProvider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return NewJWTTokenProvider(
		c.SecretKey,
		c.AccessTokenExpiration,
		c.RefreshTokenExpiration,
		c.Issuer,
	), nil
}
