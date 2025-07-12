package main

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

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
	if err := db.AutoMigrate(&User{}, &Role{}, &Permission{}, &RolePermission{}, &Session{}, &AuditLog{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize default data if database is empty
	if err := initializeDefaultData(); err != nil {
		return fmt.Errorf("failed to initialize default data: %w", err)
	}

	return nil
}

// initializeDefaultData initializes default roles, permissions, and users
func initializeDefaultData() error {
	// Check if roles exist
	var roleCount int64
	db.Model(&Role{}).Count(&roleCount)
	if roleCount > 0 {
		log.Println("Database already has roles, skipping initialization")
		return nil
	}

	log.Println("Initializing default data...")

	// Create permissions
	permissions := []Permission{
		{Name: "clock_view", Description: "View clock status", Resource: "clock", Action: "view"},
		{Name: "clock_clients", Description: "View clock clients", Resource: "clock", Action: "clients"},
		{Name: "clock_server_mode", Description: "Manage clock server mode", Resource: "clock", Action: "server_mode"},
		{Name: "clock_servers", Description: "Manage clock servers", Resource: "clock", Action: "servers"},
		{Name: "user_read", Description: "Read user information", Resource: "user", Action: "read"},
		{Name: "user_create", Description: "Create users", Resource: "user", Action: "create"},
		{Name: "user_update", Description: "Update users", Resource: "user", Action: "update"},
		{Name: "user_delete", Description: "Delete users", Resource: "user", Action: "delete"},
		{Name: "role_read", Description: "Read roles", Resource: "role", Action: "read"},
		{Name: "role_create", Description: "Create roles", Resource: "role", Action: "create"},
		{Name: "role_update", Description: "Update roles", Resource: "role", Action: "update"},
		{Name: "role_delete", Description: "Delete roles", Resource: "role", Action: "delete"},
		{Name: "permission_read", Description: "Read permissions", Resource: "permission", Action: "read"},
		{Name: "permission_create", Description: "Create permissions", Resource: "permission", Action: "create"},
		{Name: "permission_update", Description: "Update permissions", Resource: "permission", Action: "update"},
		{Name: "permission_delete", Description: "Delete permissions", Resource: "permission", Action: "delete"},
	}

	for i := range permissions {
		if err := db.Create(&permissions[i]).Error; err != nil {
			return fmt.Errorf("failed to create permission %s: %w", permissions[i].Name, err)
		}
	}

	// Create roles
	roles := []Role{
		{
			Name:        "super-admin",
			Description: "Super administrator with all permissions",
		},
		{
			Name:        "admin",
			Description: "Administrator with most permissions",
		},
		{
			Name:        "user",
			Description: "Regular user with basic permissions",
		},
	}

	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			return fmt.Errorf("failed to create role %s: %w", roles[i].Name, err)
		}
	}

	// Assign permissions to roles
	// Super-admin gets all permissions
	var superAdminRole Role
	db.Where("name = ?", "super-admin").First(&superAdminRole)
	db.Model(&superAdminRole).Association("Permissions").Replace(permissions)

	// Admin gets most permissions (no role/permission management)
	var adminRole Role
	db.Where("name = ?", "admin").First(&adminRole)
	adminPermissions := []Permission{}
	for _, perm := range permissions {
		if perm.Resource != "role" && perm.Resource != "permission" {
			adminPermissions = append(adminPermissions, perm)
		}
	}
	db.Model(&adminRole).Association("Permissions").Replace(adminPermissions)

	// User gets basic permissions
	var userRole Role
	db.Where("name = ?", "user").First(&userRole)
	userPermissions := []Permission{}
	for _, perm := range permissions {
		if perm.Resource == "clock" && (perm.Action == "view" || perm.Action == "clients") {
			userPermissions = append(userPermissions, perm)
		}
	}
	db.Model(&userRole).Association("Permissions").Replace(userPermissions)

	// Create default users
	users := []User{
		{
			Username:  "brick-super-admin",
			Password:  "brickpass",
			Email:     "bsuperadmin@brick.local",
			FirstName: "Brick",
			LastName:  "Superadmin",
			IsActive:  true,
			RoleID:    superAdminRole.ID,
		},
		{
			Username:  "brick-admin",
			Password:  "brickpass",
			Email:     "badmin@brick.local",
			FirstName: "Brick",
			LastName:  "Admin",
			IsActive:  true,
			RoleID:    adminRole.ID,
		},
		{
			Username:  "brick",
			Password:  "brickpass",
			Email:     "bregular@brick.local",
			FirstName: "Brick",
			LastName:  "Regular",
			IsActive:  true,
			RoleID:    userRole.ID,
		},
	}

	for i := range users {
		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(users[i].Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password for user %s: %w", users[i].Username, err)
		}
		users[i].Password = string(hashedPassword)

		if err := db.Create(&users[i]).Error; err != nil {
			return fmt.Errorf("failed to create user %s: %w", users[i].Username, err)
		}
	}

	log.Println("Default data initialized successfully")
	return nil
}

// cleanupExpiredSessions removes expired sessions
func cleanupExpiredSessions() error {
	result := db.Where("expires_at < ?", time.Now()).Delete(&Session{})
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
	result := db.Where("created_at < ?", cutoffDate).Delete(&AuditLog{})
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