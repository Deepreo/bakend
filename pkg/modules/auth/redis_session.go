package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RedisSessionStore, Redis tabanlı session store implementasyonu
type RedisSessionStore struct {
	client *redis.Client
	prefix string
}

// NewRedisSessionStore, yeni bir RedisSessionStore oluşturur
func NewRedisSessionStore(client *redis.Client, prefix string) SessionStore {
	if prefix == "" {
		prefix = "session:"
	}
	return &RedisSessionStore{
		client: client,
		prefix: prefix,
	}
}

// Set, session'ı Redis'e kaydeder
func (s *RedisSessionStore) Set(ctx context.Context, sessionID string, authCtx *AuthContext, expiration time.Duration) error {
	if sessionID == "" {
		return errors.New("session ID cannot be empty")
	}
	if authCtx == nil {
		return errors.New("auth context cannot be nil")
	}

	// AuthContext'i JSON'a çevir
	data, err := json.Marshal(authCtx)
	if err != nil {
		return fmt.Errorf("failed to marshal auth context: %w", err)
	}

	// Transaction başlat (Pipeline)
	pipe := s.client.Pipeline()

	// Session verisini kaydet
	key := s.getSessionKey(sessionID)
	pipe.Set(ctx, key, data, expiration)

	// Kullanıcının session listesine ekle
	userKey := s.getUserSessionsKey(authCtx.UserID)
	pipe.SAdd(ctx, userKey, sessionID)
	pipe.Expire(ctx, userKey, expiration) // User set'in süresini de uzat

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to save session to redis: %w", err)
	}

	return nil
}

// Get, session'ı Redis'ten getirir
func (s *RedisSessionStore) Get(ctx context.Context, sessionID string) (*AuthContext, error) {
	if sessionID == "" {
		return nil, errors.New("session ID cannot be empty")
	}

	key := s.getSessionKey(sessionID)
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("session not found")
		}
		return nil, fmt.Errorf("failed to get session from redis: %w", err)
	}

	var authCtx AuthContext
	if err := json.Unmarshal(data, &authCtx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth context: %w", err)
	}

	return &authCtx, nil
}

// Delete, session'ı Redis'ten siler
func (s *RedisSessionStore) Delete(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("session ID cannot be empty")
	}

	// Önce session verisini alıp user ID'yi bulmamız lazım
	// Ancak performans için direkt silmeyi deneyebiliriz.
	// User set'ten silmek için user ID'ye ihtiyacımız var.
	// Bu yüzden önce Get yapmamız gerekebilir.

	authCtx, err := s.Get(ctx, sessionID)
	if err != nil {
		// Session zaten yoksa hata döndürme
		return nil
	}

	pipe := s.client.Pipeline()

	// Session verisini sil
	key := s.getSessionKey(sessionID)
	pipe.Del(ctx, key)

	// Kullanıcının session listesinden çıkar
	userKey := s.getUserSessionsKey(authCtx.UserID)
	pipe.SRem(ctx, userKey, sessionID)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session from redis: %w", err)
	}

	return nil
}

// DeleteAllForUser, kullanıcının tüm session'larını siler
func (s *RedisSessionStore) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	userKey := s.getUserSessionsKey(userID)

	// Kullanıcının tüm session ID'lerini al
	sessionIDs, err := s.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions from redis: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil
	}

	pipe := s.client.Pipeline()

	// Her bir session'ı sil
	for _, sessionID := range sessionIDs {
		key := s.getSessionKey(sessionID)
		pipe.Del(ctx, key)
	}

	// User set'i sil
	pipe.Del(ctx, userKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete all user sessions from redis: %w", err)
	}

	return nil
}

// Exists, session'ın var olup olmadığını kontrol eder
func (s *RedisSessionStore) Exists(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, errors.New("session ID cannot be empty")
	}

	key := s.getSessionKey(sessionID)
	count, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check session existence in redis: %w", err)
	}

	return count > 0, nil
}

// Helper methods

func (s *RedisSessionStore) getSessionKey(sessionID string) string {
	return fmt.Sprintf("%s%s", s.prefix, sessionID)
}

func (s *RedisSessionStore) getUserSessionsKey(userID uuid.UUID) string {
	return fmt.Sprintf("%suser:%s", s.prefix, userID.String())
}
