package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"brick-auth/pkg/user"
)

// SeederData represents the structure of seeder data files
type SeederData struct {
	Users       []*user.User       `json:"users"`
	Roles       []*user.Role       `json:"roles"`
	Permissions []*user.Permission `json:"permissions"`
	UserRoles   []*user.RolePermission   `json:"user_roles"`
	RolePermissions []*user.RolePermission `json:"role_permissions"`
}

func main() {
	var (
		dataDir = flag.String("data", "data", "Directory containing data files")
		dbPath  = flag.String("dbpath", "auth.db", "Database file path")
	)
	flag.Parse()

	// Connect to database using GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}
	
	db, err := gorm.Open(sqlite.Open(*dbPath), gormConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate the schema (same as main.go)
	if err := db.AutoMigrate(&user.User{}, &user.Role{}, &user.Permission{}, &user.RolePermission{}, &user.Session{}, &user.AuditLog{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Load and seed data
	if err := seedData(db, *dataDir); err != nil {
		log.Fatalf("Failed to seed data: %v", err)
	}

	log.Println("Data seeding completed successfully")
}

// seedData loads and seeds data from files
func seedData(db *gorm.DB, dataDir string) error {
	// Load users
	if err := loadUsers(db, filepath.Join(dataDir, "users.json")); err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	// Load roles
	if err := loadRoles(db, filepath.Join(dataDir, "roles.json")); err != nil {
		return fmt.Errorf("failed to load roles: %w", err)
	}

	// Load permissions
	if err := loadPermissions(db, filepath.Join(dataDir, "permissions.json")); err != nil {
		return fmt.Errorf("failed to load permissions: %w", err)
	}

	// Load role permissions
	if err := loadRolePermissions(db, filepath.Join(dataDir, "role_permissions.json")); err != nil {
		return fmt.Errorf("failed to load role permissions: %w", err)
	}

	return nil
}

// loadUsers loads users from JSON file
func loadUsers(db *gorm.DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Users file not found: %s", filePath)
			return nil
		}
		return err
	}

	var users []*user.User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}

	for _, u := range users {
		if err := db.Create(u).Error; err != nil {
			return fmt.Errorf("failed to insert user %s: %w", u.Username, err)
		}
	}

	log.Printf("Loaded %d users", len(users))
	return nil
}

// loadRoles loads roles from JSON file
func loadRoles(db *gorm.DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Roles file not found: %s", filePath)
			return nil
		}
		return err
	}

	var roles []*user.Role
	if err := json.Unmarshal(data, &roles); err != nil {
		return err
	}

	for _, r := range roles {
		if err := db.Create(r).Error; err != nil {
			return fmt.Errorf("failed to insert role %s: %w", r.Name, err)
		}
	}

	log.Printf("Loaded %d roles", len(roles))
	return nil
}

// loadPermissions loads permissions from JSON file
func loadPermissions(db *gorm.DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Permissions file not found: %s", filePath)
			return nil
		}
		return err
	}

	var permissions []*user.Permission
	if err := json.Unmarshal(data, &permissions); err != nil {
		return err
	}

	for _, p := range permissions {
		if err := db.Create(p).Error; err != nil {
			return fmt.Errorf("failed to insert permission %s: %w", p.Name, err)
		}
	}

	log.Printf("Loaded %d permissions", len(permissions))
	return nil
}

// loadRolePermissions loads role permissions from JSON file
func loadRolePermissions(db *gorm.DB, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Role permissions file not found: %s", filePath)
			return nil
		}
		return err
	}

	var rolePermissions []*user.RolePermission
	if err := json.Unmarshal(data, &rolePermissions); err != nil {
		return err
	}

	for _, rp := range rolePermissions {
		if err := db.Create(rp).Error; err != nil {
			return fmt.Errorf("failed to insert role permission: %w", err)
		}
	}

	log.Printf("Loaded %d role permissions", len(rolePermissions))
	return nil
} 