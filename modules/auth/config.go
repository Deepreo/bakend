package auth

import (
	"errors"
	"time"
)

// AuthConfig, auth sistemi konfigürasyonu
type AuthConfig struct {
	Token   *SimpleTokenConfig `mapstructure:"token" json:"token"`
	JWT     *JWTConfig         `mapstructure:"jwt" json:"jwt"`
	Session *SessionConfig     `mapstructure:"session" json:"session"`
	Enabled bool               `mapstructure:"enabled" json:"enabled"`
	UseJWT  bool               `mapstructure:"use_jwt" json:"use_jwt"`
}

// SessionConfig, session konfigürasyonu
type SessionConfig struct {
	CleanupInterval time.Duration `mapstructure:"cleanup_interval" json:"cleanup_interval"`
	MaxSessions     int           `mapstructure:"max_sessions_per_user" json:"max_sessions_per_user"`
}

// DefaultAuthConfig, varsayılan auth konfigürasyonu
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Token:   DefaultSimpleTokenConfig(),
		JWT:     DefaultJWTConfig(),
		Session: DefaultSessionConfig(),
		Enabled: true,
		UseJWT:  false, // Varsayılan olarak simple token kullan
	}
}

// DefaultSessionConfig, varsayılan session konfigürasyonu
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		CleanupInterval: 10 * time.Minute, // 10 dakikada bir cleanup
		MaxSessions:     5,                // Kullanıcı başına max 5 aktif session
	}
}

// Validate, auth konfigürasyonunu doğrular
func (c *AuthConfig) Validate() error {
	if !c.Enabled {
		return nil // Auth disabled ise validation yapmaya gerek yok
	}
	if !c.UseJWT && c.Token == nil {
		return errors.New("token config is required when auth is enabled")
	}
	if !c.UseJWT && c.Token != nil {
		if err := c.Token.Validate(); err != nil {
			return err
		}
	}
	// JWT kullanılıyorsa JWT config'i de kontrol et
	if c.UseJWT {
		if c.JWT == nil {
			return errors.New("JWT config is required when JWT is enabled")
		}
		if err := c.JWT.Validate(); err != nil {
			return err
		}
	}

	if c.Session == nil {
		return errors.New("session config is required when auth is enabled")
	}

	if c.Session.CleanupInterval <= 0 {
		return errors.New("session cleanup interval must be positive")
	}

	if c.Session.MaxSessions < 1 {
		return errors.New("max sessions per user must be at least 1")
	}

	return nil
}
