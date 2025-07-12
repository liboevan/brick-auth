# Brick Auth Database Redesign

## Overview

This document describes the complete redesign of the Brick Auth database structure and permission system to support more robust role-based access control and user management.

## Changes Made

### 1. Database Schema Redesign

#### Before (Single Table)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT ''
);
```

#### After (Normalized Structure)
```sql
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles (id)
);
```

### 2. New Role System

#### Roles
1. **super-admin**: Has all permissions including user/role/permission management
2. **admin**: Has most permissions but cannot manage roles/permissions
3. **user**: Has basic permissions for viewing clock status

#### Permission Structure
- **Resource-based**: `resource/action` format (e.g., `clock/view`, `user/create`)
- **Granular control**: Each API endpoint checks specific permissions
- **Extensible**: Easy to add new permissions and resources

### 3. New API Endpoints

#### User Management
- `GET /users` - List all users (requires `user/read`)
- `POST /users` - Create new user (requires `user/create`)

#### Role Management
- `GET /roles` - List all roles with permissions (requires `role/read`)
- `POST /roles` - Create new role (requires `role/create`)

#### Permission Management
- `GET /permissions` - List all permissions (requires `permission/read`)
- `POST /permissions` - Create new permission (requires `permission/create`)

### 4. Data Initialization System

#### Standalone Initialization App
- `init-data` application for database initialization
- Can read from JSON configuration files
- Supports force reinitialization
- Default data includes 3 users, 3 roles, 16 permissions

#### Configuration File Format
```json
{
  "permissions": [...],
  "roles": [...],
  "users": [...]
}
```

### 5. Default Users

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| brick-super-admin | brickpass | super-admin | All permissions |
| brick-admin | brickpass | admin | Clock + user read |
| brick | brickpass | user | Basic clock view |

### 6. Permission Matrix

| Permission | super-admin | admin | user |
|------------|-------------|-------|------|
| clock/view | ✅ | ✅ | ✅ |
| clock/clients | ✅ | ✅ | ✅ |
| clock/server-mode | ✅ | ✅ | ❌ |
| clock/servers | ✅ | ✅ | ❌ |
| user/read | ✅ | ✅ | ❌ |
| user/create | ✅ | ❌ | ❌ |
| user/update | ✅ | ❌ | ❌ |
| user/delete | ✅ | ❌ | ❌ |
| role/* | ✅ | ❌ | ❌ |
| permission/* | ✅ | ❌ | ❌ |

## Benefits

### 1. Database Design
- **Normalized structure**: Eliminates data redundancy
- **Referential integrity**: Foreign key constraints ensure data consistency
- **Scalability**: Easy to add new roles and permissions
- **Maintainability**: Clear separation of concerns

### 2. Security
- **Fine-grained permissions**: Each action can be controlled individually
- **Role-based access**: Users inherit permissions through roles
- **Audit trail**: Clear permission structure for security reviews
- **Extensible**: Easy to add new security requirements

### 3. Management
- **API-driven**: All management through REST APIs
- **Configuration-driven**: Initialization from JSON files
- **Testable**: Comprehensive test coverage
- **Documented**: Clear API documentation

## Migration Notes

### For Existing Deployments
1. **Backup existing data**: Export current users and their permissions
2. **Run initialization**: Use `init-data` to create new structure
3. **Migrate users**: Create new users with appropriate roles
4. **Update frontend**: Ensure frontend uses new permission names

### For New Deployments
1. **Use default data**: `./init-data` creates everything automatically
2. **Custom configuration**: Use `./init-data -config config/init_data.json`
3. **Test thoroughly**: Run both test scripts to verify functionality

## Testing

### Test Scripts
- `./scripts/test.sh` - Basic authentication tests
- `./scripts/test_new_apis.sh` - New API functionality tests

### Test Coverage
- ✅ Authentication (login, validate, refresh, me)
- ✅ Permission checking
- ✅ Role-based access control
- ✅ User management APIs
- ✅ Role management APIs
- ✅ Permission management APIs
- ✅ Data initialization

## Future Enhancements

### Planned Features
1. **User update/delete APIs**: Complete CRUD operations
2. **Role update/delete APIs**: Manage existing roles
3. **Permission update/delete APIs**: Modify permissions
4. **Bulk operations**: Import/export users and roles
5. **Audit logging**: Track permission changes
6. **Password policies**: Enforce password requirements
7. **Session management**: Track active sessions

### Extensibility
- **New resources**: Easy to add new permission resources
- **Custom roles**: Flexible role creation
- **Permission inheritance**: Support for role hierarchies
- **API versioning**: Maintain backward compatibility

## Conclusion

The redesigned database structure provides a solid foundation for scalable user management and permission control. The normalized design, comprehensive API coverage, and flexible initialization system make it suitable for both development and production environments. 