package auth

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// StaticPermissionProvider, statik permission verisi sağlayan basit implementasyon
// Gerçek uygulamada bu veriler veritabanından gelecek
type StaticPermissionProvider struct {
	userPermissions map[uuid.UUID][]string
	userRoles       map[uuid.UUID][]string
	rolePermissions map[string][]string
	mutex           sync.RWMutex
}

// NewStaticPermissionProvider, yeni bir static permission provider oluşturur
func NewStaticPermissionProvider() PermissionProvider {
	provider := &StaticPermissionProvider{
		userPermissions: make(map[uuid.UUID][]string),
		userRoles:       make(map[uuid.UUID][]string),
		rolePermissions: make(map[string][]string),
	}

	// Varsayılan roller ve permission'ları ekle
	provider.initializeDefaultRolesAndPermissions()

	return provider
}

// GetUserPermissions, kullanıcının doğrudan permission'larını ve role'lerinden gelen permission'larını döner
func (p *StaticPermissionProvider) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	permissionsMap := make(map[string]bool)

	// Doğrudan kullanıcı permission'larını ekle
	if userPerms, exists := p.userPermissions[userID]; exists {
		for _, perm := range userPerms {
			permissionsMap[perm] = true
		}
	}

	// Role'lerden gelen permission'ları ekle
	if userRoles, exists := p.userRoles[userID]; exists {
		for _, role := range userRoles {
			if rolePerms, exists := p.rolePermissions[role]; exists {
				for _, perm := range rolePerms {
					permissionsMap[perm] = true
				}
			}
		}
	}

	// Map'ten slice'a çevir
	var permissions []string
	for perm := range permissionsMap {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GetUserRoles, kullanıcının role'lerini döner
func (p *StaticPermissionProvider) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if roles, exists := p.userRoles[userID]; exists {
		// Slice'ın kopyasını döner
		rolesCopy := make([]string, len(roles))
		copy(rolesCopy, roles)
		return rolesCopy, nil
	}

	return []string{}, nil
}

// GetRolePermissions, bir role'ün permission'larını döner
func (p *StaticPermissionProvider) GetRolePermissions(ctx context.Context, role string) ([]string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if permissions, exists := p.rolePermissions[role]; exists {
		// Slice'ın kopyasını döner
		permsCopy := make([]string, len(permissions))
		copy(permsCopy, permissions)
		return permsCopy, nil
	}

	return []string{}, nil
}

// Management methodları - Gerçek uygulamada bu işlemler veritabanı üzerinden yapılacak

// SetUserPermissions, kullanıcının doğrudan permission'larını belirler
func (p *StaticPermissionProvider) SetUserPermissions(userID uuid.UUID, permissions []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(permissions) == 0 {
		delete(p.userPermissions, userID)
	} else {
		p.userPermissions[userID] = append([]string(nil), permissions...)
	}
}

// AddUserPermission, kullanıcıya doğrudan permission ekler
func (p *StaticPermissionProvider) AddUserPermission(userID uuid.UUID, permission string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	userPerms, exists := p.userPermissions[userID]
	if !exists {
		p.userPermissions[userID] = []string{permission}
		return
	}

	// Duplicate kontrolü
	for _, perm := range userPerms {
		if perm == permission {
			return
		}
	}

	p.userPermissions[userID] = append(userPerms, permission)
}

// RemoveUserPermission, kullanıcıdan doğrudan permission kaldırır
func (p *StaticPermissionProvider) RemoveUserPermission(userID uuid.UUID, permission string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	userPerms, exists := p.userPermissions[userID]
	if !exists {
		return
	}

	var newPerms []string
	for _, perm := range userPerms {
		if perm != permission {
			newPerms = append(newPerms, perm)
		}
	}

	if len(newPerms) == 0 {
		delete(p.userPermissions, userID)
	} else {
		p.userPermissions[userID] = newPerms
	}
}

// SetUserRoles, kullanıcının role'lerini belirler
func (p *StaticPermissionProvider) SetUserRoles(userID uuid.UUID, roles []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(roles) == 0 {
		delete(p.userRoles, userID)
	} else {
		p.userRoles[userID] = append([]string(nil), roles...)
	}
}

// AddUserRole, kullanıcıya role ekler
func (p *StaticPermissionProvider) AddUserRole(userID uuid.UUID, role string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	userRoles, exists := p.userRoles[userID]
	if !exists {
		p.userRoles[userID] = []string{role}
		return
	}

	// Duplicate kontrolü
	for _, r := range userRoles {
		if r == role {
			return
		}
	}

	p.userRoles[userID] = append(userRoles, role)
}

// RemoveUserRole, kullanıcıdan role kaldırır
func (p *StaticPermissionProvider) RemoveUserRole(userID uuid.UUID, role string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	userRoles, exists := p.userRoles[userID]
	if !exists {
		return
	}

	var newRoles []string
	for _, r := range userRoles {
		if r != role {
			newRoles = append(newRoles, r)
		}
	}

	if len(newRoles) == 0 {
		delete(p.userRoles, userID)
	} else {
		p.userRoles[userID] = newRoles
	}
}

// DefineRole, yeni bir role tanımlar ve permission'larını belirler
func (p *StaticPermissionProvider) DefineRole(role string, permissions []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(permissions) == 0 {
		delete(p.rolePermissions, role)
	} else {
		p.rolePermissions[role] = append([]string(nil), permissions...)
	}
}

// AddRolePermission, role'e permission ekler
func (p *StaticPermissionProvider) AddRolePermission(role string, permission string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	rolePerms, exists := p.rolePermissions[role]
	if !exists {
		p.rolePermissions[role] = []string{permission}
		return
	}

	// Duplicate kontrolü
	for _, perm := range rolePerms {
		if perm == permission {
			return
		}
	}

	p.rolePermissions[role] = append(rolePerms, permission)
}

// RemoveRolePermission, role'den permission kaldırır
func (p *StaticPermissionProvider) RemoveRolePermission(role string, permission string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	rolePerms, exists := p.rolePermissions[role]
	if !exists {
		return
	}

	var newPerms []string
	for _, perm := range rolePerms {
		if perm != permission {
			newPerms = append(newPerms, perm)
		}
	}

	if len(newPerms) == 0 {
		delete(p.rolePermissions, role)
	} else {
		p.rolePermissions[role] = newPerms
	}
}

// initializeDefaultRolesAndPermissions, varsayılan roller ve permission'ları tanımlar
func (p *StaticPermissionProvider) initializeDefaultRolesAndPermissions() {
	// Admin role - tüm permission'lar
	p.rolePermissions["admin"] = []string{
		"user.create",
		"user.read",
		"user.update",
		"user.delete",
		"user.list",
		"company.create",
		"company.read",
		"company.update",
		"company.delete",
		"company.list",
		"contract.create",
		"contract.read",
		"contract.update",
		"contract.delete",
		"contract.list",
		"system.admin",
		"reports.view",
		"reports.export",
		"settings.manage",
	}

	// Manager role - yönetim permission'ları
	p.rolePermissions["manager"] = []string{
		"user.read",
		"user.list",
		"company.read",
		"company.update",
		"company.list",
		"contract.create",
		"contract.read",
		"contract.update",
		"contract.list",
		"reports.view",
		"reports.export",
	}

	// User role - temel permission'lar
	p.rolePermissions["user"] = []string{
		"user.read",     // Kendi profili
		"company.read",  // Kendi şirketi
		"contract.read", // Kendi kontratları
		"reports.view",  // Temel rapor görüntüleme
	}

	// Viewer role - sadece okuma permission'ları
	p.rolePermissions["viewer"] = []string{
		"user.read",
		"company.read",
		"contract.read",
		"reports.view",
	}

	// Guest role - çok sınırlı permission'lar
	p.rolePermissions["guest"] = []string{
		"company.read", // Sadece şirket bilgisi
	}
}

// GetAllRoles, tanımlı tüm rolleri döner
func (p *StaticPermissionProvider) GetAllRoles() []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var roles []string
	for role := range p.rolePermissions {
		roles = append(roles, role)
	}

	return roles
}

// GetAllPermissions, sistemdeki tüm mevcut permission'ları döner
func (p *StaticPermissionProvider) GetAllPermissions() []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	permissionsMap := make(map[string]bool)

	// Role permission'larından topla
	for _, permissions := range p.rolePermissions {
		for _, perm := range permissions {
			permissionsMap[perm] = true
		}
	}

	// User permission'larından topla
	for _, permissions := range p.userPermissions {
		for _, perm := range permissions {
			permissionsMap[perm] = true
		}
	}

	var allPermissions []string
	for perm := range permissionsMap {
		allPermissions = append(allPermissions, perm)
	}

	return allPermissions
}

// DatabasePermissionProvider interfacesi - gerçek implementasyon için
type DatabasePermissionProvider interface {
	PermissionProvider

	// Database-specific methods
	LoadUserPermissions(ctx context.Context, userID uuid.UUID) error
	LoadUserRoles(ctx context.Context, userID uuid.UUID) error
	SaveUserPermissions(ctx context.Context, userID uuid.UUID, permissions []string) error
	SaveUserRoles(ctx context.Context, userID uuid.UUID, roles []string) error
	InvalidateUserCache(userID uuid.UUID)
	InvalidateRoleCache(role string)
}

// Burada gerçek veritabanı implementasyonu yazılabilir
// type DatabasePermissionProviderImpl struct {
//     db *sql.DB
//     cache map[uuid.UUID]*CachedUserPermissions
//     ...
// }
