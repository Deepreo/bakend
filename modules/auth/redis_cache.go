package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache, CacheInterface'i implement eden Redis adaptörü
type RedisCache struct {
	client *redis.Client
	prefix string
}

// NewRedisCache, yeni bir RedisCache oluşturur
func NewRedisCache(client *redis.Client, prefix string) CacheInterface {
	return &RedisCache{
		client: client,
		prefix: prefix,
	}
}

// Get, cache'den veri okur
func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	return c.client.Get(ctx, c.prefix+key).Bytes()
}

// Set, cache'e veri yazar
func (c *RedisCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.client.Set(ctx, c.prefix+key, value, expiration).Err()
}

// Del, cache'den veri siler
func (c *RedisCache) Del(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.prefix+key).Err()
}
