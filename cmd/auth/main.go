package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"brick-auth/pkg/auth"
	"brick-auth/pkg/httpapi"
	"brick-auth/pkg/user"
)

// Global variables
var (
	authHandler   *auth.Handler
	AppVersion    = "0.1.0-dev"
	BuildDateTime = "2025-07-10T13:00:00Z"
	db            *gorm.DB
	privateKey    *rsa.PrivateKey
	config        Config
	authService   *auth.Service
	userService   *user.Service
	userHandler   *user.Handler
	router        *httpapi.Router
)

// Config represents the application configuration
type Config struct {
	Server struct {
		Host         string        `yaml:"host"`
		Port         string        `yaml:"port"`
		ReadTimeout  time.Duration `yaml:"read_timeout"`
		WriteTimeout time.Duration `yaml:"write_timeout"`
		IdleTimeout  time.Duration `yaml:"idle_timeout"`
	} `yaml:"server"`
	Database struct {
		Path         string `yaml:"path"`
		MaxOpenConns int    `yaml:"max_open_conns"`
		MaxIdleConns int    `yaml:"max_idle_conns"`
	} `yaml:"database"`
	Auth struct {
		PrivateKeyPath string        `yaml:"private_key_path"`
		TokenExpiry    time.Duration `yaml:"token_expiry"`
	} `yaml:"auth"`
}

// loadConfig loads the configuration
func loadConfig() error {
	// Set default values
	config.Server.Host = "0.0.0.0"
	config.Server.Port = "17001"
	config.Server.ReadTimeout = 30 * time.Second
	config.Server.WriteTimeout = 30 * time.Second
	config.Server.IdleTimeout = 60 * time.Second
	
	config.Database.Path = "/var/lib/brick-auth/auth.db"
	config.Database.MaxOpenConns = 25
	config.Database.MaxIdleConns = 5
	
	config.Auth.PrivateKeyPath = "/app/private.pem"
	config.Auth.TokenExpiry = 24 * time.Hour
	
	return nil
}

// validateConfig validates the configuration
func validateConfig() error {
	if config.Auth.PrivateKeyPath == "" {
		return fmt.Errorf("private key path is required")
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
	
	// Configure GORM logger
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}
	
	db, err = gorm.Open(sqlite.Open(config.Database.Path), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}
	
	sqlDB.SetMaxOpenConns(config.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(config.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto migrate the schema
	if err := db.AutoMigrate(&user.User{}, &user.Role{}, &user.Permission{}, &user.RolePermission{}, &user.Session{}, &user.AuditLog{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}

// initializeServices initializes all services
func initializeServices() {
	// Initialize auth service
	authService = auth.NewService(db, privateKey, config.Auth.TokenExpiry)
	
	// Initialize user service
	userService = user.NewService(db)
	
	// Initialize user handler
	// Initialize auth handler
	authHandler = auth.NewHandler(authService, db)
	userHandler = user.NewHandler(userService)
	
	// Initialize router
	router = httpapi.NewRouter(db, authHandler, userHandler)
}

// cleanupExpiredSessions removes expired sessions
func cleanupExpiredSessions() error {
	result := db.Where("expires_at < ?", time.Now()).Delete(&user.Session{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		log.Printf("Cleaned up %d expired sessions", result.RowsAffected)
	}
	return nil
}

// cleanupOldAuditLogs removes old audit logs
func cleanupOldAuditLogs() error {
	// Keep audit logs for 90 days
	cutoffDate := time.Now().AddDate(0, 0, -90)
	result := db.Where("created_at < ?", cutoffDate).Delete(&user.AuditLog{})
	if result.Error != nil {
		return fmt.Errorf("failed to cleanup old audit logs: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		log.Printf("Cleaned up %d old audit log entries", result.RowsAffected)
	}
	return nil
}

// startCleanupRoutine starts the cleanup routine
func startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if err := cleanupExpiredSessions(); err != nil {
				log.Printf("Session cleanup error: %v", err)
			}
			if err := cleanupOldAuditLogs(); err != nil {
				log.Printf("Audit log cleanup error: %v", err)
			}
		}
	}()
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

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Validate configuration
	if err := validateConfig(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
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

	// Initialize services
	initializeServices()

	// Start cleanup routine
	startCleanupRoutine()

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create server with timeout configuration
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port),
		Handler:      router.GetEngine(),
		ReadTimeout:  config.Server.ReadTimeout,
		WriteTimeout: config.Server.WriteTimeout,
		IdleTimeout:  config.Server.IdleTimeout,
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