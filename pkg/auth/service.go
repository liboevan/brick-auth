package auth

import (
	"crypto/rsa"
	"time"

	"gorm.io/gorm"
	"brick-auth/pkg/user"
)

// Service handles authentication operations
type Service struct {
	db          *gorm.DB
	privateKey  *rsa.PrivateKey
	tokenExpiry time.Duration
	jwtService  *JWTService
}

// NewService creates a new auth service
func NewService(db *gorm.DB, privateKey *rsa.PrivateKey, tokenExpiry time.Duration) *Service {
	jwtService := &JWTService{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}

	return &Service{
		db:          db,
		privateKey:  privateKey,
		tokenExpiry: tokenExpiry,
		jwtService:  jwtService,
	}
}

// GenerateToken generates a JWT token for a user
func (s *Service) GenerateToken(user *user.User) (string, time.Time, error) {
	// Extract permissions from user's role
	var permissions []string
	if user.Role.ID != 0 {
		for _, perm := range user.Role.Permissions {
			permissions = append(permissions, perm.Name)
		}
	}

	// Generate token
	token, err := s.jwtService.GenerateToken(
		user.ID,
		user.Username,
		user.Role.Name,
		permissions,
		s.tokenExpiry,
	)
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := time.Now().Add(s.tokenExpiry)
	return token, expiresAt, nil
}

// ValidateToken validates a JWT token and returns claims
func (s *Service) ValidateToken(token string) (*Claims, error) {
	return s.jwtService.ValidateToken(token)
} 