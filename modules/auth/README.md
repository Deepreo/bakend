# Bakend Auth System

Bu paket, HTTP'den bağımsız, esnek, güvenli ve production-ready bir authentication/authorization sistemi sağlar.

## Özellikler

- **HTTP'den Bağımsız**: Pure Go context tabanlı auth sistemi.
- **Flexible Token Providers**: Simple HMAC ve JWT token desteği.
- **Session Management**:
    - **Redis Session Store**: Production için ölçeklenebilir session yönetimi.
    - **Memory Session Store**: Test ve geliştirme için.
- **Permission/Role System**:
    - **Database Permission Provider**: Veritabanı tabanlı dinamik yetki yönetimi (Caching destekli).
    - **Static Permission Provider**: Test ve basit senaryolar için.
- **Security**:
    - **Refresh Token Rotation**: Token çalınmasına karşı ekstra güvenlik.
    - **Secure Defaults**: Güvenli varsayılan konfigürasyonlar.
- **Middleware Support**: Type-safe handler wrapper'ları ve HTTP middleware entegrasyonu.
- **Config Integration**: Merkezi konfigürasyon yönetimi.
- **Elastic APM Integration**: Detaylı tracing ve monitoring.

## Kurulum ve Konfigürasyon

### 1. Auth Config

Auth sistemi, merkezi bir `AuthConfig` yapısı ile yönetilir.

```go
package main

import (
    "github.com/Deepreo/bakend/modules/auth"
    "time"
)

func main() {
    // Varsayılan konfigürasyon
    config := auth.DefaultAuthConfig()
    
    // Özelleştirme
    config.UseJWT = true
    config.JWT.SecretKey = "your-very-secure-secret-key-min-32-chars"
    config.JWT.AccessTokenExpiration = 15 * time.Minute
    config.JWT.RefreshTokenExpiration = 7 * 24 * time.Hour
    config.JWT.Issuer = "bakend"
    
    // Redis ayarları
    config.RedisURL = "localhost:6379"
    config.RedisPrefix = "bakend:session:"
    
    // Auth sistemini oluştur
    authSystem, err := auth.NewAuthSystemWithConfig(config)
    if err != nil {
        panic(err)
    }
}
```

### 2. Provider Seçimi

Production ortamında Redis ve Database provider'larının kullanılması önerilir.

```go
// Redis Client
redisClient := redis.NewClient(&redis.Options{Addr: config.RedisURL})

// Database Connection (pgx)
dbPool, _ := pgxpool.New(ctx, dbURL)

// Cache (Redis tabanlı)
cache := NewRedisCache(redisClient) 

// Builder ile sistem oluşturma
authSystem, err := auth.NewAuthBuilder().
    WithConfig(config).
    WithSessionStore(auth.NewRedisSessionStore(redisClient, config.RedisPrefix)).
    WithPermissionProvider(auth.NewSQLPermissionProvider(dbPool, cache)).
    Build()
```

## Kullanım

### 1. Token İşlemleri

```go
// Token oluştur (Login)
userID := uuid.New()
authCtx := auth.NewAuthContext(userID, uuid.New(), "user@example.com", "John Doe", true)
tokenPair, err := authSystem.Service.GenerateTokens(ctx, authCtx)

// Token yenileme (Refresh Token Rotation)
// Bu işlem eski session'ı iptal eder ve yeni bir session oluşturur.
newTokenPair, err := authSystem.Service.RefreshToken(ctx, tokenPair.RefreshToken)
```

### 2. Middleware Kullanımı

Handler'larınızı type-safe wrapper'lar ile koruyun.

```go
// Handler tanımı
type CreateUserHandler struct {
    service UserService
}

func (h *CreateUserHandler) Handle(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error) {
    // Auth context otomatik olarak ctx içinde
    authCtx, _ := auth.FromContext(ctx)
    // ...
}

// Wrapper kullanımı
handler := auth.WithAuthHandlerFromContext(
    authSystem.Service,
    &CreateUserHandler{},
    &auth.AuthRequiredOptions{
        RequireVerification: true,
        RequiredPermissions: []string{"user.create"},
        RequiredRoles:       []string{"admin"},
    },
)
```

### 3. Permission Kontrolü

```go
// Context üzerinden kontrol
if err := auth.RequirePermission(ctx, "document.edit"); err != nil {
    return err // ErrPermissionDenied
}

// AuthContext üzerinden kontrol
authCtx, _ := auth.FromContext(ctx)
if authCtx.HasRole("manager") {
    // ...
}
```

## Veritabanı Şeması (SQLPermissionProvider)

`SQLPermissionProvider` aşağıdaki tablo yapısını bekler:

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id),
    permission_id UUID NOT NULL REFERENCES permissions(id),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_permissions (
    user_id UUID NOT NULL,
    permission_id UUID NOT NULL REFERENCES permissions(id),
    PRIMARY KEY (user_id, permission_id)
);
```

## Güvenlik Özellikleri

### Refresh Token Rotation
Bir refresh token kullanıldığında, o token'a bağlı olan session **iptal edilir** (revoke) ve yeni bir session oluşturulur. Bu, çalınan refresh token'ların tekrar kullanılmasını engeller ve "token reuse" saldırılarını tespit etmeyi sağlar.

### Caching
`SQLPermissionProvider`, performans için yetkileri cache'ler. `CacheInterface` implementasyonu sağlanarak (örn. Redis) veritabanı yükü azaltılır. Cache süresi varsayılan olarak 5 dakikadır.

## Test

Modül kapsamlı unit testlere sahiptir.

```bash
go test -v ./modules/auth/...
```

Testler için `NewTestAuthSystem` helper'ı kullanılabilir. Bu helper, in-memory bileşenleri kullanarak hızlı test ortamı sağlar.
