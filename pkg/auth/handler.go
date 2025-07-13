package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"brick-auth/pkg/user"
)

// Handler handles authentication HTTP requests
type Handler struct {
	service *Service
	db      *gorm.DB
}

// NewHandler creates a new auth handler
func NewHandler(service *Service, db *gorm.DB) *Handler {
	return &Handler{
		service: service,
		db:      db,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token       string   `json:"token"`
	User        UserInfo `json:"user"`
	Permissions []string `json:"permissions"`
	ExpiresAt   string   `json:"expires_at"`
}

// UserInfo represents user information for API responses
type UserInfo struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
	IsActive  bool   `json:"is_active"`
}

// Login handles login requests
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var userObj user.User
	if err := h.db.Preload("Role.Permissions").Where("username = ?", req.Username).First(&userObj).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if !userObj.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is disabled"})
		return
	}

	// Compare password with hash
	if err := bcrypt.CompareHashAndPassword([]byte(userObj.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate token and session
	token, expiresAt, err := h.service.GenerateToken(&userObj)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Create session
	session := user.Session{
		UserID:    userObj.ID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
	if err := h.db.Create(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Extract permissions from user's role
	var permissions []string
	if userObj.Role.ID != 0 {
		for _, perm := range userObj.Role.Permissions {
			permissions = append(permissions, perm.Name)
		}
	}

	// Construct user info for response
	userInfo := UserInfo{
		ID:        userObj.ID,
		Username:  userObj.Username,
		Email:     userObj.Email,
		FirstName: userObj.FirstName,
		LastName:  userObj.LastName,
		Role:      userObj.Role.Name,
		IsActive:  userObj.IsActive,
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:       token,
		User:        userInfo,
		Permissions: permissions,
		ExpiresAt:   expiresAt.Format(time.RFC3339),
	})
}

// ValidateToken handles token validation requests
func (h *Handler) ValidateToken(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		token = c.Query("token")
	}
	
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token required"})
		return
	}

	// Remove "Bearer " prefix if present
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	claims, err := h.service.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user": gin.H{
			"id":       claims.UserID,
			"username": claims.Username,
			"role":     claims.Role,
		},
		"permissions": claims.Permissions,
	})
}

// RefreshToken handles token refresh requests
func (h *Handler) RefreshToken(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Refresh token endpoint"})
}

// Me handles current user requests
func (h *Handler) Me(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token required"})
		return
	}

	// Remove "Bearer " prefix if present
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	claims, err := h.service.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	var userObj user.User
	if err := h.db.Preload("Role.Permissions").Where("id = ?", claims.UserID).First(&userObj).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, userObj)
}

// GenerateToken generates a token for a user (service-style method)
func (h *Handler) GenerateToken(user *user.User) (string, time.Time, error) {
	return h.service.GenerateToken(user)
}

// ValidateTokenString validates a token and returns claims (service-style method)
func (h *Handler) ValidateTokenString(token string) (*Claims, error) {
	return h.service.ValidateToken(token)
}

// DecodeToken handles token decoding with permission check
func (h *Handler) DecodeToken(c *gin.Context) {
	// Get token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		return
	}

	// Extract token from "Bearer <token>"
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
		return
	}

	userToken := tokenParts[1]

	// Validate user's token first
	userClaims, err := h.service.ValidateToken(userToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user token"})
		return
	}

	// Check if user has auth/token_decode permission
	hasPermission := false
	for _, perm := range userClaims.Permissions {
		if perm == "auth/token_decode" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to decode tokens"})
		return
	}

	// Get token to decode from request body
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token to decode is required"})
		return
	}

	// Decode the target token
	targetClaims, err := h.service.ValidateToken(req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token to decode"})
		return
	}

	// Return decoded token information
	c.JSON(http.StatusOK, gin.H{
		"header": gin.H{
			"alg": "HS256",
			"typ": "JWT",
		},
		"payload": gin.H{
			"user_id":    targetClaims.UserID,
			"username":   targetClaims.Username,
			"role":       targetClaims.Role,
			"permissions": targetClaims.Permissions,
			"exp":        targetClaims.ExpiresAt.Unix(),
			"iat":        targetClaims.IssuedAt.Unix(),
		},
	})
}
