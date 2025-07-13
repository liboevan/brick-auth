package user

import (
	"time"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// Role represents a user role
type Role struct {
	gorm.Model
	Name        string `json:"name" gorm:"unique;not null"`
	Description string `json:"description"`
	Permissions []Permission `json:"permissions" gorm:"many2many:role_permissions;"`
}

// Permission represents a system permission
type Permission struct {
	gorm.Model
	Name        string `json:"name" gorm:"unique;not null"`
	Description string `json:"description"`
	Resource    string `json:"resource" gorm:"not null"`
	Action      string `json:"action" gorm:"not null"`
	Roles       []Role `json:"roles" gorm:"many2many:role_permissions;"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	RoleID       uint `json:"role_id" gorm:"primaryKey"`
	PermissionID uint `json:"permission_id" gorm:"primaryKey"`
}

// User represents a system user
type User struct {
	gorm.Model
	Username  string `json:"username" gorm:"unique;not null"`
	Password  string `json:"password" gorm:"not null"`
	Email     string `json:"email" gorm:"unique"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IsActive  bool   `json:"is_active" gorm:"default:true"`
	RoleID    uint   `json:"role_id" gorm:"not null"`
	Role      Role   `json:"role" gorm:"foreignKey:RoleID"`
	LastLogin *time.Time `json:"last_login"`
}

// Session represents a user session
type Session struct {
	gorm.Model
	UserID    uint      `json:"user_id" gorm:"not null"`
	Token     string    `json:"token" gorm:"unique;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	User      User      `json:"user" gorm:"foreignKey:UserID"`
}

// AuditLog represents system audit events
type AuditLog struct {
	gorm.Model
	UserID    *uint     `json:"user_id"`
	Action    string    `json:"action" gorm:"not null"`
	Resource  string    `json:"resource" gorm:"not null"`
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	User      *User     `json:"user" gorm:"foreignKey:UserID"`
}

// Claims for JWT token
type Claims struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// CreateUserRequest represents user creation request
type CreateUserRequest struct {
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	RoleID    uint   `json:"role_id" binding:"required"`
}

// UpdateUserRequest represents user update request
type UpdateUserRequest struct {
	Email     *string `json:"email"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	IsActive  *bool   `json:"is_active"`
	RoleID    *uint   `json:"role_id"`
}

// CreateRoleRequest represents role creation request
type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Permissions []uint `json:"permissions"`
}

// PermissionInfo represents permission information
type PermissionInfo struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// RoleInfo represents role information
type RoleInfo struct {
	ID          uint             `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Permissions []PermissionInfo `json:"permissions"`
} 