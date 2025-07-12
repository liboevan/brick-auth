package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Config holds application configuration
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Auth     AuthConfig     `json:"auth"`
}

type ServerConfig struct {
	Port string `json:"port"`
	Host string `json:"host"`
}

type DatabaseConfig struct {
	Path string `json:"path"`
}

type AuthConfig struct {
	PrivateKeyPath string `json:"private_key_path"`
	TokenExpiry    int    `json:"token_expiry"`
}

// User model
type User struct {
	gorm.Model
	Username   string `json:"username" gorm:"unique"`
	Password   string `json:"password"`
	Role       string `json:"role"`
	Permissions string `json:"permissions"` // comma-separated
}

// Token model
type Token struct {
	gorm.Model
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token" gorm:"unique"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Claims for JWT
type Claims struct {
	UserID      int      `json:"user_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

var (
	AppVersion    = "0.1.0-dev"
	BuildDateTime = "2025-07-10T13:00:00Z"
	db            *gorm.DB
	privateKey    *rsa.PrivateKey
	config        Config
)

// getEnvWithDefault returns environment variable value or default
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ensureDirectories creates necessary directories
func ensureDirectories() error {
	dirs := []string{
		filepath.Dir(config.Database.Path),
		filepath.Dir(config.Auth.PrivateKeyPath),
		"/var/log/brick-auth",
		"/var/lib/brick-auth",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// loadConfig loads configuration from file or environment
func loadConfig() error {
	configPath := getEnvWithDefault("BRICK_AUTH_CONFIG_PATH", "/etc/brick-auth/config.json")
	
	// Set default configuration
	config = Config{
		Server: ServerConfig{
			Port: getEnvWithDefault("BRICK_AUTH_PORT", "17001"),
			Host: getEnvWithDefault("BRICK_AUTH_HOST", "0.0.0.0"),
		},
		Database: DatabaseConfig{
			Path: getEnvWithDefault("BRICK_AUTH_DB_PATH", "/var/lib/brick-auth/auth.db"),
		},
		Auth: AuthConfig{
			PrivateKeyPath: getEnvWithDefault("BRICK_AUTH_PRIVATE_KEY_PATH", "/app/private.pem"),
			TokenExpiry:    3600, // 1 hour
		},
	}

	// Try to load from config file if it exists
	if _, err := os.Stat(configPath); err == nil {
		file, err := os.Open(configPath)
		if err != nil {
			return fmt.Errorf("failed to open config file: %w", err)
		}
		defer file.Close()

		if err := json.NewDecoder(file).Decode(&config); err != nil {
			return fmt.Errorf("failed to decode config file: %w", err)
		}
	}

	return nil
}

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

// initDatabase initializes the database
func initDatabase() error {
	var err error
	db, err = gorm.Open(sqlite.Open(config.Database.Path), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto migrate the schema
	if err := db.AutoMigrate(&User{}, &Token{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Check if users exist
	var count int64
	db.Model(&User{}).Count(&count)
	if count == 0 {
		// Create default users
		adminPass, err := bcrypt.GenerateFromPassword([]byte("brickadminpass"), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash admin password: %w", err)
		}
		userPass, err := bcrypt.GenerateFromPassword([]byte("brickpass"), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash user password: %w", err)
		}

		// Admin: all permissions
		adminUser := User{
			Username:   "brick-admin",
			Password:   string(adminPass),
			Role:       "admin",
			Permissions: "clock/view,clock/clients,clock/server-mode,clock/servers",
		}
		if err := db.Create(&adminUser).Error; err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Common user: limited permissions
		user := User{
			Username:   "brick",
			Password:   string(userPass),
			Role:       "user",
			Permissions: "clock/view,clock/clients",
		}
		if err := db.Create(&user).Error; err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		log.Println("Initialized DB with default users: brick-admin/brickadminpass and brick/brickpass")
	}

	return nil
}



// healthCheck endpoint
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now().UTC(),
	})
}

// BuildInfo struct
type BuildInfo struct {
	Version        string `json:"version"`
	BuildDateTime  string `json:"buildDateTime"`
	BuildTimestamp int64  `json:"buildTimestamp"`
	Environment    string `json:"environment"`
	Service        string `json:"service"`
	Description    string `json:"description"`
}

// loadBuildInfo loads build information from file
func loadBuildInfo() *BuildInfo {
	data, err := os.ReadFile("/app/build-info.json")
	if err != nil {
		return nil
	}
	var buildInfo BuildInfo
	if err := json.Unmarshal(data, &buildInfo); err != nil {
		return nil
	}
	return &buildInfo
}

// version endpoint
func version(c *gin.Context) {
	buildInfo := loadBuildInfo()
	response := gin.H{
		"version":        AppVersion,
		"build_datetime": BuildDateTime,
		"service":        "brick-auth",
	}
	if buildInfo != nil {
		response["build_info"] = buildInfo
	}
	c.JSON(http.StatusOK, response)
}

// Helper function to get bearer token
func getBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// Login handler
func loginHandler(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	var user User
	if err := db.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	permissions := []string{}
	if user.Permissions != "" {
		permissions = strings.Split(user.Permissions, ",")
	}

	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		UserID:      int(user.ID),
		Username:    user.Username,
		Role:        user.Role,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Validate token handler
func validateTokenHandler(c *gin.Context) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
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

// Refresh token handler
func refreshTokenHandler(c *gin.Context) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	expirationTime := time.Now().Add(15 * time.Minute)
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := newToken.SignedString(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Get current user info handler
func meHandler(c *gin.Context) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": claims})
}

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Ensure directories exist
	if err := ensureDirectories(); err != nil {
		log.Fatalf("Failed to ensure directories: %v", err)
	}

	// Load private key
	if err := loadPrivateKey(); err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// Initialize database
	if err := initDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}



	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	r := gin.Default()

	// Add health check endpoint
	r.GET("/health", healthCheck)
	
	// Add version endpoint
	r.GET("/version", version)

	// Add authentication routes
	r.POST("/login", loginHandler)
	r.POST("/validate", validateTokenHandler)
	r.GET("/validate", validateTokenHandler)  // Also support GET for hub compatibility
	r.POST("/refresh", refreshTokenHandler)
	r.GET("/me", meHandler)

	// Create server
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port),
		Handler: r,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s:%s", config.Server.Host, config.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Give outstanding requests a deadline for completion
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
} 