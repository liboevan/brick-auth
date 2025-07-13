package user

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service handles user management operations
type Service struct {
	db *gorm.DB
}

// NewService creates a new user service
func NewService(db *gorm.DB) *Service {
	return &Service{
		db: db,
	}
}

// CreateUser creates a new user
func (s *Service) CreateUser(req *CreateUserRequest) (*User, error) {
	// Check if username already exists
	var existingUser User
	if err := s.db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		Username:  req.Username,
		Password:  string(hashedPassword),
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IsActive:  true,
		RoleID:    req.RoleID,
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Load role information
	if err := s.db.Preload("Role.Permissions").First(user, user.ID).Error; err != nil {
		return nil, fmt.Errorf("failed to load user role: %w", err)
	}

	return user, nil
}

// GetUserByID gets a user by ID
func (s *Service) GetUserByID(userID uint) (*User, error) {
	var user User
	if err := s.db.Preload("Role.Permissions").First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername gets a user by username
func (s *Service) GetUserByUsername(username string) (*User, error) {
	var user User
	if err := s.db.Preload("Role.Permissions").Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates a user
func (s *Service) UpdateUser(userID uint, req *UpdateUserRequest) (*User, error) {
	user, err := s.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.RoleID != nil {
		user.RoleID = *req.RoleID
	}

	user.UpdatedAt = time.Now()

	if err := s.db.Save(user).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Reload with role information
	if err := s.db.Preload("Role.Permissions").First(user, user.ID).Error; err != nil {
		return nil, fmt.Errorf("failed to load user role: %w", err)
	}

	return user, nil
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(userID uint) error {
	return s.db.Delete(&User{}, userID).Error
}

// ListUsers lists all users
func (s *Service) ListUsers() ([]*User, error) {
	var users []*User
	if err := s.db.Preload("Role.Permissions").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

// GetUserPermissions gets permissions for a user
func (s *Service) GetUserPermissions(userID uint) ([]string, error) {
	var permissions []Permission
	if err := s.db.Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN users ON users.role_id = role_permissions.role_id").
		Where("users.id = ?", userID).
		Find(&permissions).Error; err != nil {
		return nil, err
	}

	permissionNames := make([]string, len(permissions))
	for i, p := range permissions {
		permissionNames[i] = p.Name
	}

	return permissionNames, nil
}

// CreateRole creates a new role
func (s *Service) CreateRole(req *CreateRoleRequest) (*Role, error) {
	role := &Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.db.Create(role).Error; err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	// Assign permissions if provided
	if len(req.Permissions) > 0 {
		if err := s.db.Model(role).Association("Permissions").Replace(&Permission{}, req.Permissions); err != nil {
			return nil, fmt.Errorf("failed to assign permissions: %w", err)
		}
	}

	return role, nil
}

// GetRoleByID gets a role by ID
func (s *Service) GetRoleByID(roleID uint) (*Role, error) {
	var role Role
	if err := s.db.Preload("Permissions").First(&role, roleID).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole updates a role
func (s *Service) UpdateRole(roleID uint, name, description string) (*Role, error) {
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	if name != "" {
		role.Name = name
	}
	if description != "" {
		role.Description = description
	}

	role.UpdatedAt = time.Now()

	if err := s.db.Save(role).Error; err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	return role, nil
}

// DeleteRole deletes a role
func (s *Service) DeleteRole(roleID uint) error {
	return s.db.Delete(&Role{}, roleID).Error
}

// ListRoles lists all roles
func (s *Service) ListRoles() ([]*Role, error) {
	var roles []*Role
	if err := s.db.Preload("Permissions").Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

// CreatePermission creates a new permission
func (s *Service) CreatePermission(name, description, resource, action string) (*Permission, error) {
	permission := &Permission{
		Name:        name,
		Description: description,
		Resource:    resource,
		Action:      action,
	}

	if err := s.db.Create(permission).Error; err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return permission, nil
}

// GetPermissionByID gets a permission by ID
func (s *Service) GetPermissionByID(permissionID uint) (*Permission, error) {
	var permission Permission
	if err := s.db.First(&permission, permissionID).Error; err != nil {
		return nil, err
	}
	return &permission, nil
}

// UpdatePermission updates a permission
func (s *Service) UpdatePermission(permissionID uint, name, description, resource, action string) (*Permission, error) {
	permission, err := s.GetPermissionByID(permissionID)
	if err != nil {
		return nil, fmt.Errorf("permission not found: %w", err)
	}

	if name != "" {
		permission.Name = name
	}
	if description != "" {
		permission.Description = description
	}
	if resource != "" {
		permission.Resource = resource
	}
	if action != "" {
		permission.Action = action
	}

	permission.UpdatedAt = time.Now()

	if err := s.db.Save(permission).Error; err != nil {
		return nil, fmt.Errorf("failed to update permission: %w", err)
	}

	return permission, nil
}

// DeletePermission deletes a permission
func (s *Service) DeletePermission(permissionID uint) error {
	return s.db.Delete(&Permission{}, permissionID).Error
}

// ListPermissions lists all permissions
func (s *Service) ListPermissions() ([]*Permission, error) {
	var permissions []*Permission
	if err := s.db.Find(&permissions).Error; err != nil {
		return nil, err
	}
	return permissions, nil
}

// AssignPermissionToRole assigns a permission to a role
func (s *Service) AssignPermissionToRole(roleID, permissionID uint) error {
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("role not found")
	}

	permission, err := s.GetPermissionByID(permissionID)
	if err != nil {
		return fmt.Errorf("permission not found")
	}

	return s.db.Model(role).Association("Permissions").Append(permission)
}

// RemovePermissionFromRole removes a permission from a role
func (s *Service) RemovePermissionFromRole(roleID, permissionID uint) error {
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("role not found")
	}

	permission, err := s.GetPermissionByID(permissionID)
	if err != nil {
		return fmt.Errorf("permission not found")
	}

	return s.db.Model(role).Association("Permissions").Delete(permission)
} 