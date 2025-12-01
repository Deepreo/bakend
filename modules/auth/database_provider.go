package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DBInterface, veritabanı işlemlerini soyutlar (pgx uyumlu)
type DBInterface interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// CacheInterface, cache işlemlerini soyutlar
type CacheInterface interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	Del(ctx context.Context, key string) error
}

// SQLPermissionProvider, veritabanı tabanlı permission provider
type SQLPermissionProvider struct {
	db    DBInterface
	cache CacheInterface
}

// NewSQLPermissionProvider, yeni bir SQLPermissionProvider oluşturur
func NewSQLPermissionProvider(db DBInterface, cache CacheInterface) PermissionProvider {
	return &SQLPermissionProvider{
		db:    db,
		cache: cache,
	}
}

// GetUserPermissions, kullanıcının permission'larını veritabanından getirir
func (p *SQLPermissionProvider) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// 1. Cache kontrolü
	if p.cache != nil {
		key := fmt.Sprintf("permissions:%s", userID)
		if data, err := p.cache.Get(ctx, key); err == nil {
			var permissions []string
			if err := json.Unmarshal(data, &permissions); err == nil {
				return permissions, nil
			}
		}
	}

	// 2. Veritabanından sorgula
	// Hem doğrudan atanan permission'ları hem de roller üzerinden gelenleri birleştiriyoruz
	query := `
		SELECT DISTINCT p.name
		FROM permissions p
		LEFT JOIN user_permissions up ON p.id = up.permission_id
		LEFT JOIN role_permissions rp ON p.id = rp.permission_id
		LEFT JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE up.user_id = $1 OR ur.user_id = $1
	`

	rows, err := p.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// 3. Cache'e yaz
	if p.cache != nil {
		key := fmt.Sprintf("permissions:%s", userID)
		if data, err := json.Marshal(permissions); err == nil {
			_ = p.cache.Set(ctx, key, data, 5*time.Minute)
		}
	}

	return permissions, nil
}

// GetUserRoles, kullanıcının rollerini veritabanından getirir
func (p *SQLPermissionProvider) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := p.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// GetRolePermissions, rolün permission'larını veritabanından getirir
func (p *SQLPermissionProvider) GetRolePermissions(ctx context.Context, role string) ([]string, error) {
	query := `
		SELECT p.name
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		WHERE r.name = $1
	`

	rows, err := p.db.Query(ctx, query, role)
	if err != nil {
		return nil, fmt.Errorf("failed to query role permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, nil
}
