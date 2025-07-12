package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// loadPrivateKey loads the RSA private key
func loadPrivateKey() error {
	keyData, err := os.ReadFile(config.Auth.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	var parsedKey interface{}
	if block.Type == "RSA PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		return fmt.Errorf("unknown key type %s", block.Type)
	}
	
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	key, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("key is not an RSA private key")
	}

	privateKey = key
	return nil
}

// getBearerToken extracts Bearer token from Authorization header
func getBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// validatePassword validates password against security policy
func validatePassword(password string) error {
	if len(password) < config.Security.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", config.Security.PasswordMinLength)
	}

	if config.Security.PasswordRequireUpper {
		if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if config.Security.PasswordRequireLower {
		if !regexp.MustCompile(`[a-z]`).MatchString(password) {
			return fmt.Errorf("password must contain at least one lowercase letter")
		}
	}

	if config.Security.PasswordRequireNumber {
		if !regexp.MustCompile(`[0-9]`).MatchString(password) {
			return fmt.Errorf("password must contain at least one number")
		}
	}

	if config.Security.PasswordRequireSpecial {
		if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// comparePassword compares a password with its hash
func comparePassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// createToken creates a JWT token for a user
func createToken(user *User) (string, time.Time, error) {
	// Get user permissions
	var permissions []Permission
	if err := db.Model(&user.Role).Association("Permissions").Find(&permissions); err != nil {
		log.Printf("Failed to get user permissions: %v", err)
	}

	// Convert permissions to string slice
	permissionStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionStrings[i] = fmt.Sprintf("%s/%s", perm.Resource, perm.Action)
	}

	expirationTime := time.Now().Add(config.Auth.TokenExpiry)
	claims := &Claims{
		UserID:      user.ID,
		Username:    user.Username,
		Role:        user.Role.Name,
		Permissions: permissionStrings,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expirationTime, nil
}

// parseToken parses and validates a JWT token
func parseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	
	return claims, nil
}

// logAuditEvent logs an audit event
func logAuditEvent(userID *uint, action, resource, details, ipAddress, userAgent string) {
	if !config.Security.EnableAuditLog {
		return
	}

	auditLog := &AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Details:   details,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := db.Create(auditLog).Error; err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
}

// getClientIP gets the client IP address
func getClientIP(c *gin.Context) string {
	// Try to get real IP from headers
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return c.ClientIP()
}

// getUserAgent gets the user agent string
func getUserAgent(c *gin.Context) string {
	return c.GetHeader("User-Agent")
}

// healthCheck handles health check requests
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "brick-auth",
		"version":   AppVersion,
	})
}

// version handles version requests
func version(c *gin.Context) {
	buildInfo := loadBuildInfo()
	c.JSON(http.StatusOK, buildInfo)
}

// loginHandler handles user login
func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Get client info for audit logging
	clientIP := getClientIP(c)
	userAgent := getUserAgent(c)

	// Find user
	var user User
	if err := db.Preload("Role").Where("username = ? AND is_active = ?", req.Username, true).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logAuditEvent(nil, "login_failed", "auth", "Invalid username", clientIP, userAgent)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Check password
	if err := comparePassword(req.Password, user.Password); err != nil {
		logAuditEvent(&user.ID, "login_failed", "auth", "Invalid password", clientIP, userAgent)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create token
	tokenString, expirationTime, err := createToken(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	// Update last login
	now := time.Now()
	user.LastLogin = &now
	db.Save(&user)

	// Get permissions
	var permissions []Permission
	db.Model(&user.Role).Association("Permissions").Find(&permissions)
	permissionStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionStrings[i] = fmt.Sprintf("%s/%s", perm.Resource, perm.Action)
	}

	// Create session if enabled
	if config.Security.EnableSessionTracking {
		session := &Session{
			UserID:    user.ID,
			Token:     tokenString,
			ExpiresAt: expirationTime,
			IPAddress: clientIP,
			UserAgent: userAgent,
		}
		db.Create(session)
	}

	// Log successful login
	logAuditEvent(&user.ID, "login_success", "auth", "User logged in successfully", clientIP, userAgent)

	// Return response
	c.JSON(http.StatusOK, LoginResponse{
		Token:       tokenString,
		ExpiresAt:   expirationTime,
		Permissions: permissionStrings,
		User: UserInfo{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role.Name,
			IsActive:  user.IsActive,
		},
	})
}

// validateTokenHandler handles token validation
func validateTokenHandler(c *gin.Context) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	claims, err := parseToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Check if user still exists and is active
	var user User
	if err := db.Where("id = ? AND is_active = ?", claims.UserID, true).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found or inactive"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":       true,
		"user_id":     claims.UserID,
		"username":    claims.Username,
		"role":        claims.Role,
		"permissions": claims.Permissions,
	})
}

// refreshTokenHandler handles token refresh
func refreshTokenHandler(c *gin.Context) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	claims, err := parseToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Check if user still exists and is active
	var user User
	if err := db.Preload("Role").Where("id = ? AND is_active = ?", claims.UserID, true).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found or inactive"})
		return
	}

	// Create new token
	tokenString, expirationTime, err := createToken(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		return
	}

	// Get permissions
	var permissions []Permission
	db.Model(&user.Role).Association("Permissions").Find(&permissions)
	permissionStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionStrings[i] = fmt.Sprintf("%s/%s", perm.Resource, perm.Action)
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token:       tokenString,
		ExpiresAt:   expirationTime,
		Permissions: permissionStrings,
		User: UserInfo{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role.Name,
			IsActive:  user.IsActive,
		},
	})
}

// meHandler returns current user information
func meHandler(c *gin.Context) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	claims, err := parseToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	var user User
	if err := db.Preload("Role").Where("id = ? AND is_active = ?", claims.UserID, true).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found or inactive"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": UserInfo{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role.Name,
			IsActive:  user.IsActive,
		},
	})
} 