package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ==================== User Management APIs ====================

// listUsersHandler lists all users (super-admin only)
func listUsersHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	var users []User
	if err := db.Preload("Role").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	// Convert to response format (exclude password)
	var userList []UserInfo
	for _, user := range users {
		userList = append(userList, UserInfo{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role.Name,
			IsActive:  user.IsActive,
		})
	}

	c.JSON(http.StatusOK, gin.H{"users": userList})
}

// createUserHandler creates a new user (super-admin only)
func createUserHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate password
	if err := validatePassword(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if username already exists
	var existingUser User
	if err := db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Check if email already exists
	if req.Email != "" {
		if err := db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create user
	user := User{
		Username:  req.Username,
		Password:  hashedPassword,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IsActive:  true,
		RoleID:    req.RoleID,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "user_create", "user", fmt.Sprintf("Created user: %s", req.Username), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
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

// updateUserHandler updates a user (super-admin only)
func updateUserHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Find user
	var user User
	if err := db.Preload("Role").Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Update fields if provided
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

	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "user_update", "user", fmt.Sprintf("Updated user: %s", user.Username), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
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

// deleteUserHandler deletes a user (super-admin only)
func deleteUserHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Find user
	var user User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Prevent deleting self
	if user.ID == claims.UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete your own account"})
		return
	}

	if err := db.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "user_delete", "user", fmt.Sprintf("Deleted user: %s", user.Username), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// ==================== Role Management APIs ====================

// listRolesHandler lists all roles (super-admin only)
func listRolesHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	var roles []Role
	if err := db.Preload("Permissions").Find(&roles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch roles"})
		return
	}

	// Convert to response format
	var roleList []RoleInfo
	for _, role := range roles {
		var permissions []PermissionInfo
		for _, perm := range role.Permissions {
			permissions = append(permissions, PermissionInfo{
				ID:          perm.ID,
				Name:        perm.Name,
				Description: perm.Description,
				Resource:    perm.Resource,
				Action:      perm.Action,
			})
		}
		roleList = append(roleList, RoleInfo{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			Permissions: permissions,
		})
	}

	c.JSON(http.StatusOK, gin.H{"roles": roleList})
}

// createRoleHandler creates a new role (super-admin only)
func createRoleHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Check if role name already exists
	var existingRole Role
	if err := db.Where("name = ?", req.Name).First(&existingRole).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Role name already exists"})
		return
	}

	// Create role
	role := Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := db.Create(&role).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}

	// Assign permissions if provided
	if len(req.Permissions) > 0 {
		var permissions []Permission
		if err := db.Where("id IN ?", req.Permissions).Find(&permissions).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find permissions"})
			return
		}
		db.Model(&role).Association("Permissions").Replace(permissions)
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "role_create", "role", fmt.Sprintf("Created role: %s", req.Name), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusCreated, gin.H{
		"message": "Role created successfully",
		"role": RoleInfo{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
		},
	})
}

// updateRoleHandler updates a role (super-admin only)
func updateRoleHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Permissions []uint  `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Find role
	var role Role
	if err := db.Preload("Permissions").Where("id = ?", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Prevent updating default roles
	if role.Name == "super-admin" || role.Name == "admin" || role.Name == "user" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot modify default roles"})
		return
	}

	// Update fields if provided
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = *req.Description
	}

	if err := db.Save(&role).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		return
	}

	// Update permissions if provided
	if req.Permissions != nil {
		var permissions []Permission
		if err := db.Where("id IN ?", req.Permissions).Find(&permissions).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find permissions"})
			return
		}
		db.Model(&role).Association("Permissions").Replace(permissions)
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "role_update", "role", fmt.Sprintf("Updated role: %s", role.Name), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusOK, gin.H{
		"message": "Role updated successfully",
		"role": RoleInfo{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
		},
	})
}

// deleteRoleHandler deletes a role (super-admin only)
func deleteRoleHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	// Find role
	var role Role
	if err := db.Where("id = ?", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Prevent deleting default roles
	if role.Name == "super-admin" || role.Name == "admin" || role.Name == "user" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default roles"})
		return
	}

	// Check if role is in use
	var userCount int64
	db.Model(&User{}).Where("role_id = ?", roleID).Count(&userCount)
	if userCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete role that is assigned to users"})
		return
	}

	if err := db.Delete(&role).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "role_delete", "role", fmt.Sprintf("Deleted role: %s", role.Name), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusOK, gin.H{"message": "Role deleted successfully"})
}

// ==================== Permission Management APIs ====================

// listPermissionsHandler lists all permissions (super-admin only)
func listPermissionsHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	var permissions []Permission
	if err := db.Find(&permissions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch permissions"})
		return
	}

	// Convert to response format
	var permissionList []PermissionInfo
	for _, perm := range permissions {
		permissionList = append(permissionList, PermissionInfo{
			ID:          perm.ID,
			Name:        perm.Name,
			Description: perm.Description,
			Resource:    perm.Resource,
			Action:      perm.Action,
		})
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissionList})
}

// createPermissionHandler creates a new permission (super-admin only)
func createPermissionHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Resource    string `json:"resource" binding:"required"`
		Action      string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Check if permission name already exists
	var existingPermission Permission
	if err := db.Where("name = ?", req.Name).First(&existingPermission).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Permission name already exists"})
		return
	}

	// Create permission
	permission := Permission{
		Name:        req.Name,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
	}

	if err := db.Create(&permission).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create permission"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "permission_create", "permission", fmt.Sprintf("Created permission: %s", req.Name), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusCreated, gin.H{
		"message": "Permission created successfully",
		"permission": PermissionInfo{
			ID:          permission.ID,
			Name:        permission.Name,
			Description: permission.Description,
			Resource:    permission.Resource,
			Action:      permission.Action,
		},
	})
}

// updatePermissionHandler updates a permission (super-admin only)
func updatePermissionHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	permissionID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
		return
	}

	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Resource    *string `json:"resource"`
		Action      *string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Find permission
	var permission Permission
	if err := db.Where("id = ?", permissionID).First(&permission).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Update fields if provided
	if req.Name != nil {
		permission.Name = *req.Name
	}
	if req.Description != nil {
		permission.Description = *req.Description
	}
	if req.Resource != nil {
		permission.Resource = *req.Resource
	}
	if req.Action != nil {
		permission.Action = *req.Action
	}

	if err := db.Save(&permission).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update permission"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "permission_update", "permission", fmt.Sprintf("Updated permission: %s", permission.Name), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusOK, gin.H{
		"message": "Permission updated successfully",
		"permission": PermissionInfo{
			ID:          permission.ID,
			Name:        permission.Name,
			Description: permission.Description,
			Resource:    permission.Resource,
			Action:      permission.Action,
		},
	})
}

// deletePermissionHandler deletes a permission (super-admin only)
func deletePermissionHandler(c *gin.Context) {
	// Check if user is super-admin
	claims, err := getCurrentUserClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	if claims.Role != "super-admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
		return
	}

	permissionID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
		return
	}

	// Find permission
	var permission Permission
	if err := db.Where("id = ?", permissionID).First(&permission).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Check if permission is assigned to any role
	var roleCount int64
	db.Model(&Role{}).Joins("JOIN role_permissions ON roles.id = role_permissions.role_id").Where("role_permissions.permission_id = ?", permissionID).Count(&roleCount)
	if roleCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete permission that is assigned to roles"})
		return
	}

	if err := db.Delete(&permission).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete permission"})
		return
	}

	// Log audit event
	logAuditEvent(&claims.UserID, "permission_delete", "permission", fmt.Sprintf("Deleted permission: %s", permission.Name), getClientIP(c), getUserAgent(c))

	c.JSON(http.StatusOK, gin.H{"message": "Permission deleted successfully"})
}

// ==================== Helper Functions ====================

// getCurrentUserClaims gets the current user's claims from the request
func getCurrentUserClaims(c *gin.Context) (*Claims, error) {
	tokenStr := getBearerToken(c)
	if tokenStr == "" {
		return nil, fmt.Errorf("missing token")
	}

	claims, err := parseToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if user still exists and is active
	var user User
	if err := db.Where("id = ? AND is_active = ?", claims.UserID, true).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found or inactive")
	}

	return claims, nil
} 