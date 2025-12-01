package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SimpleTokenPayload, basit token'da saklanan veri yapısı
type SimpleTokenPayload struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	FullName    string   `json:"full_name"`
	CompanyID   *string  `json:"company_id,omitempty"`
	IsVerified  bool     `json:"is_verified"`
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	TokenType   string   `json:"token_type"`
	SessionID   string   `json:"session_id"`
	IssuedAt    int64    `json:"issued_at"`
	ExpiresAt   int64    `json:"expires_at"`
	Issuer      string   `json:"issuer"`
}

// SimpleTokenProvider, basit HMAC tabanlı token provider implementasyonu
type SimpleTokenProvider struct {
	secretKey              []byte
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
	issuer                 string
}

// NewSimpleTokenProvider, yeni bir Simple token provider oluşturur
func NewSimpleTokenProvider(
	secretKey string,
	accessTokenExpiration time.Duration,
	refreshTokenExpiration time.Duration,
	issuer string,
) TokenProvider {
	return &SimpleTokenProvider{
		secretKey:              []byte(secretKey),
		accessTokenExpiration:  accessTokenExpiration,
		refreshTokenExpiration: refreshTokenExpiration,
		issuer:                 issuer,
	}
}

// GenerateAccessToken, access token oluşturur
func (p *SimpleTokenProvider) GenerateAccessToken(authCtx *AuthContext) (string, error) {
	return p.generateToken(authCtx, p.accessTokenExpiration)
}

// GenerateRefreshToken, refresh token oluşturur
func (p *SimpleTokenProvider) GenerateRefreshToken(authCtx *AuthContext) (string, error) {
	return p.generateToken(authCtx, p.refreshTokenExpiration)
}

// ValidateAccessToken, access token'ı doğrular
func (p *SimpleTokenProvider) ValidateAccessToken(tokenString string) (*AuthContext, error) {
	return p.validateToken(tokenString, "access")
}

// ValidateRefreshToken, refresh token'ı doğrular
func (p *SimpleTokenProvider) ValidateRefreshToken(tokenString string) (*AuthContext, error) {
	return p.validateToken(tokenString, "refresh")
}

// GetTokenExpiration, access token süresini döner
func (p *SimpleTokenProvider) GetTokenExpiration() time.Duration {
	return p.accessTokenExpiration
}

// GetRefreshTokenExpiration, refresh token süresini döner
func (p *SimpleTokenProvider) GetRefreshTokenExpiration() time.Duration {
	return p.refreshTokenExpiration
}

// generateToken, basit HMAC token oluşturur
func (p *SimpleTokenProvider) generateToken(authCtx *AuthContext, expiration time.Duration) (string, error) {
	now := time.Now()
	exp := now.Add(expiration)

	payload := SimpleTokenPayload{
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
		IssuedAt:    now.Unix(),
		ExpiresAt:   exp.Unix(),
		Issuer:      p.issuer,
	}

	// Payload'ı JSON'a çevir
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Base64 encode et
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Random nonce ekle
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)

	// HMAC signature oluştur
	data := fmt.Sprintf("%s.%s", payloadB64, nonceB64)
	signature := p.generateSignature(data)

	// Token'ı birleştir
	token := fmt.Sprintf("%s.%s", data, signature)
	return token, nil
}

// validateToken, basit HMAC token'ı doğrular
func (p *SimpleTokenProvider) validateToken(tokenString string, expectedTokenType string) (*AuthContext, error) {
	// Token'ı parçalara ayır
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	payloadB64, nonceB64, signature := parts[0], parts[1], parts[2]
	data := fmt.Sprintf("%s.%s", payloadB64, nonceB64)

	// Signature'ı doğrula
	expectedSignature := p.generateSignature(data)
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return nil, errors.New("invalid token signature")
	}

	// Payload'ı decode et
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("invalid token payload encoding")
	}

	var payload SimpleTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, errors.New("invalid token payload")
	}

	// Token tipini kontrol et
	if payload.TokenType != expectedTokenType {
		return nil, ErrInvalidTokenType
	}

	// Expiration'ı kontrol et
	now := time.Now().Unix()
	if payload.ExpiresAt < now {
		return nil, ErrTokenExpired
	}

	// User ID'yi parse et
	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	// AuthContext'i oluştur
	authCtx := &AuthContext{
		UserID:   userID,
		Email:    payload.Email,
		FullName: payload.FullName,
		CompanyID: func() uuid.UUID {
			if payload.CompanyID != nil {
				cid, err := uuid.Parse(*payload.CompanyID)
				if err == nil {
					return cid
				}
			}
			return uuid.Nil
		}(),
		IsVerified:  payload.IsVerified,
		Permissions: payload.Permissions,
		Roles:       payload.Roles,
		TokenType:   payload.TokenType,
		SessionID:   payload.SessionID,
		IssuedAt:    time.Unix(payload.IssuedAt, 0),
		ExpiresAt:   time.Unix(payload.ExpiresAt, 0),
	}

	return authCtx, nil
}

// generateSignature, HMAC signature oluşturur
func (p *SimpleTokenProvider) generateSignature(data string) string {
	h := hmac.New(sha256.New, p.secretKey)
	h.Write([]byte(data))
	signature := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature)
}

// SimpleTokenConfig, Simple token konfigürasyon yapısı
type SimpleTokenConfig struct {
	SecretKey              string        `mapstructure:"secret_key" json:"secret_key"`
	AccessTokenExpiration  time.Duration `mapstructure:"access_token_expiration" json:"access_token_expiration"`
	RefreshTokenExpiration time.Duration `mapstructure:"refresh_token_expiration" json:"refresh_token_expiration"`
	Issuer                 string        `mapstructure:"issuer" json:"issuer"`
}

// DefaultSimpleTokenConfig, varsayılan Simple token konfigürasyonu
func DefaultSimpleTokenConfig() *SimpleTokenConfig {
	return &SimpleTokenConfig{
		SecretKey:              "your-secret-key-here-must-be-at-least-32-chars", // Üretimde mutlaka değiştirilmeli
		AccessTokenExpiration:  15 * time.Minute,                                 // 15 dakika
		RefreshTokenExpiration: 7 * 24 * time.Hour,                               // 7 gün
		Issuer:                 "bakend",
	}
}

// Validate, Simple token konfigürasyonunu doğrular
func (c *SimpleTokenConfig) Validate() error {
	if c.SecretKey == "" {
		return errors.New("token secret key cannot be empty")
	}
	if len(c.SecretKey) < 32 {
		return errors.New("token secret key must be at least 32 characters")
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
func (c *SimpleTokenConfig) CreateTokenProvider() (TokenProvider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return NewSimpleTokenProvider(
		c.SecretKey,
		c.AccessTokenExpiration,
		c.RefreshTokenExpiration,
		c.Issuer,
	), nil
}
