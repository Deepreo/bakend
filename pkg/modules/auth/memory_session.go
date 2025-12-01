package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionData, session verilerini tutar
type SessionData struct {
	AuthContext *AuthContext `json:"auth_context"`
	ExpiresAt   time.Time    `json:"expires_at"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// IsExpired, session'ın süresi bitmiş mi kontrol eder
func (s *SessionData) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// MemorySessionStore, memory'de session saklayan implementasyon
type MemorySessionStore struct {
	sessions        map[string]*SessionData
	userSessions    map[uuid.UUID][]string // user ID -> session ID'leri
	mutex           sync.RWMutex
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupStarted  bool
}

// NewMemorySessionStore, yeni bir memory session store oluşturur
func NewMemorySessionStore(cleanupInterval time.Duration) SessionStore {
	store := &MemorySessionStore{
		sessions:        make(map[string]*SessionData),
		userSessions:    make(map[uuid.UUID][]string),
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
	}

	// Otomatik cleanup başlat
	if cleanupInterval > 0 {
		store.startCleanup()
	}

	return store
}

// Set, session'ı saklar
func (s *MemorySessionStore) Set(ctx context.Context, sessionID string, authCtx *AuthContext, expiration time.Duration) error {
	if sessionID == "" {
		return errors.New("session ID cannot be empty")
	}
	if authCtx == nil {
		return errors.New("auth context cannot be nil")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	sessionData := &SessionData{
		AuthContext: authCtx.Clone(),
		ExpiresAt:   now.Add(expiration),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Eski session'ı varsa kaldır
	if oldSession, exists := s.sessions[sessionID]; exists {
		s.removeUserSession(oldSession.AuthContext.UserID, sessionID)
	}

	// Yeni session'ı ekle
	s.sessions[sessionID] = sessionData
	s.addUserSession(authCtx.UserID, sessionID)

	return nil
}

// Get, session'ı getirir
func (s *MemorySessionStore) Get(ctx context.Context, sessionID string) (*AuthContext, error) {
	if sessionID == "" {
		return nil, errors.New("session ID cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sessionData, exists := s.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	if sessionData.IsExpired() {
		// Expired session'ı arka planda temizle
		go func() {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			s.deleteSessionUnsafe(sessionID)
		}()
		return nil, errors.New("session expired")
	}

	return sessionData.AuthContext.Clone(), nil
}

// Delete, session'ı siler
func (s *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("session ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.deleteSessionUnsafe(sessionID)
}

// DeleteAllForUser, kullanıcının tüm session'larını siler
func (s *MemorySessionStore) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sessionIDs, exists := s.userSessions[userID]
	if !exists {
		return nil // Kullanıcının session'ı yok
	}

	// Tüm session'ları sil
	for _, sessionID := range sessionIDs {
		delete(s.sessions, sessionID)
	}

	// User sessions'ı temizle
	delete(s.userSessions, userID)

	return nil
}

// Exists, session'ın var olup olmadığını kontrol eder
func (s *MemorySessionStore) Exists(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, errors.New("session ID cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sessionData, exists := s.sessions[sessionID]
	if !exists {
		return false, nil
	}

	if sessionData.IsExpired() {
		// Expired session'ı arka planda temizle
		go func() {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			s.deleteSessionUnsafe(sessionID)
		}()
		return false, nil
	}

	return true, nil
}

// GetUserSessionCount, kullanıcının aktif session sayısını döner
func (s *MemorySessionStore) GetUserSessionCount(ctx context.Context, userID uuid.UUID) int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sessionIDs, exists := s.userSessions[userID]
	if !exists {
		return 0
	}

	// Expired session'ları say
	activeCount := 0
	for _, sessionID := range sessionIDs {
		if sessionData, exists := s.sessions[sessionID]; exists && !sessionData.IsExpired() {
			activeCount++
		}
	}

	return activeCount
}

// GetAllUserSessions, kullanıcının tüm aktif session'larını döner
func (s *MemorySessionStore) GetAllUserSessions(ctx context.Context, userID uuid.UUID) ([]*AuthContext, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sessionIDs, exists := s.userSessions[userID]
	if !exists {
		return []*AuthContext{}, nil
	}

	var activeSessions []*AuthContext
	for _, sessionID := range sessionIDs {
		if sessionData, exists := s.sessions[sessionID]; exists && !sessionData.IsExpired() {
			activeSessions = append(activeSessions, sessionData.AuthContext.Clone())
		}
	}

	return activeSessions, nil
}

// StopCleanup, cleanup goroutine'ini durdurur
func (s *MemorySessionStore) StopCleanup() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.cleanupStarted {
		close(s.stopCleanup)
		s.cleanupStarted = false
	}
}

// GetStats, session store istatistiklerini döner
type SessionStats struct {
	TotalSessions   int            `json:"total_sessions"`
	ExpiredSessions int            `json:"expired_sessions"`
	ActiveSessions  int            `json:"active_sessions"`
	UserSessions    map[string]int `json:"user_sessions"`
}

func (s *MemorySessionStore) GetStats() *SessionStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &SessionStats{
		TotalSessions: len(s.sessions),
		UserSessions:  make(map[string]int),
	}

	expiredCount := 0
	activeCount := 0

	for _, sessionData := range s.sessions {
		if sessionData.IsExpired() {
			expiredCount++
		} else {
			activeCount++
		}
	}

	stats.ExpiredSessions = expiredCount
	stats.ActiveSessions = activeCount

	// User sessions stats
	for userID, sessionIDs := range s.userSessions {
		activeUserSessions := 0
		for _, sessionID := range sessionIDs {
			if sessionData, exists := s.sessions[sessionID]; exists && !sessionData.IsExpired() {
				activeUserSessions++
			}
		}
		if activeUserSessions > 0 {
			stats.UserSessions[userID.String()] = activeUserSessions
		}
	}

	return stats
}

// Private helper methods

func (s *MemorySessionStore) addUserSession(userID uuid.UUID, sessionID string) {
	sessionIDs, exists := s.userSessions[userID]
	if !exists {
		s.userSessions[userID] = []string{sessionID}
		return
	}

	// Duplicate kontrolü
	for _, existingSessionID := range sessionIDs {
		if existingSessionID == sessionID {
			return
		}
	}

	s.userSessions[userID] = append(sessionIDs, sessionID)
}

func (s *MemorySessionStore) removeUserSession(userID uuid.UUID, sessionID string) {
	sessionIDs, exists := s.userSessions[userID]
	if !exists {
		return
	}

	// Session'ı listeden kaldır
	var newSessionIDs []string
	for _, existingSessionID := range sessionIDs {
		if existingSessionID != sessionID {
			newSessionIDs = append(newSessionIDs, existingSessionID)
		}
	}

	if len(newSessionIDs) == 0 {
		delete(s.userSessions, userID)
	} else {
		s.userSessions[userID] = newSessionIDs
	}
}

func (s *MemorySessionStore) deleteSessionUnsafe(sessionID string) error {
	sessionData, exists := s.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	// User sessions'tan kaldır
	s.removeUserSession(sessionData.AuthContext.UserID, sessionID)

	// Session'ı sil
	delete(s.sessions, sessionID)

	return nil
}

func (s *MemorySessionStore) startCleanup() {
	if s.cleanupStarted {
		return
	}

	s.cleanupStarted = true
	go s.cleanupRoutine()
}

func (s *MemorySessionStore) cleanupRoutine() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupExpiredSessions()
		case <-s.stopCleanup:
			return
		}
	}
}

func (s *MemorySessionStore) cleanupExpiredSessions() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var expiredSessionIDs []string

	// Expired session'ları bul
	for sessionID, sessionData := range s.sessions {
		if sessionData.IsExpired() {
			expiredSessionIDs = append(expiredSessionIDs, sessionID)
		}
	}

	// Expired session'ları sil
	for _, sessionID := range expiredSessionIDs {
		s.deleteSessionUnsafe(sessionID)
	}
}
