package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds application configuration
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Auth     AuthConfig     `json:"auth"`
	Security SecurityConfig `json:"security"`
	Logging  LoggingConfig  `json:"logging"`
}

type ServerConfig struct {
	Port         string        `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

type DatabaseConfig struct {
	Path       string `json:"path"`
	MaxOpenConns int `json:"max_open_conns"`
	MaxIdleConns int `json:"max_idle_conns"`
}

type AuthConfig struct {
	PrivateKeyPath    string        `json:"private_key_path"`
	TokenExpiry       time.Duration `json:"token_expiry"`
	RefreshTokenExpiry time.Duration `json:"refresh_token_expiry"`
	SessionExpiry     time.Duration `json:"session_expiry"`
}

type SecurityConfig struct {
	PasswordMinLength     int  `json:"password_min_length"`
	PasswordRequireUpper  bool `json:"password_require_upper"`
	PasswordRequireLower  bool `json:"password_require_lower"`
	PasswordRequireNumber bool `json:"password_require_number"`
	PasswordRequireSpecial bool `json:"password_require_special"`
	MaxLoginAttempts      int  `json:"max_login_attempts"`
	LockoutDuration       time.Duration `json:"lockout_duration"`
	EnableAuditLog        bool `json:"enable_audit_log"`
	EnableSessionTracking bool `json:"enable_session_tracking"`
}

type LoggingConfig struct {
	Level      string `json:"level"`
	Format     string `json:"format"`
	OutputPath string `json:"output_path"`
	MaxSize    int    `json:"max_size"`
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age"`
}

// getEnvWithDefault returns environment variable value or default
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvIntWithDefault returns environment variable as int or default
func getEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvDurationWithDefault returns environment variable as duration or default
func getEnvDurationWithDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getEnvBoolWithDefault returns environment variable as bool or default
func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// loadConfig loads configuration from file or environment
func loadConfig() error {
	configPath := getEnvWithDefault("BRICK_AUTH_CONFIG_PATH", "/etc/brick-auth/config.json")
	
	// Set default configuration
	config = Config{
		Server: ServerConfig{
			Port:         getEnvWithDefault("BRICK_AUTH_PORT", "17001"),
			Host:         getEnvWithDefault("BRICK_AUTH_HOST", "0.0.0.0"),
			ReadTimeout:  getEnvDurationWithDefault("BRICK_AUTH_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDurationWithDefault("BRICK_AUTH_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDurationWithDefault("BRICK_AUTH_IDLE_TIMEOUT", 60*time.Second),
		},
		Database: DatabaseConfig{
			Path:         getEnvWithDefault("BRICK_AUTH_DB_PATH", "/var/lib/brick-auth/auth.db"),
			MaxOpenConns: getEnvIntWithDefault("BRICK_AUTH_DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns: getEnvIntWithDefault("BRICK_AUTH_DB_MAX_IDLE_CONNS", 5),
		},
		Auth: AuthConfig{
			PrivateKeyPath:     getEnvWithDefault("BRICK_AUTH_PRIVATE_KEY_PATH", "/app/private.pem"),
			TokenExpiry:        getEnvDurationWithDefault("BRICK_AUTH_TOKEN_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getEnvDurationWithDefault("BRICK_AUTH_REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),
			SessionExpiry:      getEnvDurationWithDefault("BRICK_AUTH_SESSION_EXPIRY", 24*time.Hour),
		},
		Security: SecurityConfig{
			PasswordMinLength:     getEnvIntWithDefault("BRICK_AUTH_PASSWORD_MIN_LENGTH", 8),
			PasswordRequireUpper:  getEnvBoolWithDefault("BRICK_AUTH_PASSWORD_REQUIRE_UPPER", true),
			PasswordRequireLower:  getEnvBoolWithDefault("BRICK_AUTH_PASSWORD_REQUIRE_LOWER", true),
			PasswordRequireNumber: getEnvBoolWithDefault("BRICK_AUTH_PASSWORD_REQUIRE_NUMBER", true),
			PasswordRequireSpecial: getEnvBoolWithDefault("BRICK_AUTH_PASSWORD_REQUIRE_SPECIAL", false),
			MaxLoginAttempts:      getEnvIntWithDefault("BRICK_AUTH_MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:       getEnvDurationWithDefault("BRICK_AUTH_LOCKOUT_DURATION", 15*time.Minute),
			EnableAuditLog:        getEnvBoolWithDefault("BRICK_AUTH_ENABLE_AUDIT_LOG", true),
			EnableSessionTracking: getEnvBoolWithDefault("BRICK_AUTH_ENABLE_SESSION_TRACKING", true),
		},
		Logging: LoggingConfig{
			Level:      getEnvWithDefault("BRICK_AUTH_LOG_LEVEL", "info"),
			Format:     getEnvWithDefault("BRICK_AUTH_LOG_FORMAT", "json"),
			OutputPath: getEnvWithDefault("BRICK_AUTH_LOG_PATH", "/var/log/brick-auth/app.log"),
			MaxSize:    getEnvIntWithDefault("BRICK_AUTH_LOG_MAX_SIZE", 100),
			MaxBackups: getEnvIntWithDefault("BRICK_AUTH_LOG_MAX_BACKUPS", 3),
			MaxAge:     getEnvIntWithDefault("BRICK_AUTH_LOG_MAX_AGE", 28),
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

// validateConfig validates the configuration
func validateConfig() error {
	if config.Server.Port == "" {
		return fmt.Errorf("server port is required")
	}
	
	if config.Database.Path == "" {
		return fmt.Errorf("database path is required")
	}
	
	if config.Auth.PrivateKeyPath == "" {
		return fmt.Errorf("private key path is required")
	}
	
	if config.Auth.TokenExpiry <= 0 {
		return fmt.Errorf("token expiry must be positive")
	}
	
	if config.Security.PasswordMinLength < 6 {
		return fmt.Errorf("password minimum length must be at least 6")
	}
	
	if config.Security.MaxLoginAttempts < 1 {
		return fmt.Errorf("max login attempts must be at least 1")
	}
	
	return nil
} 