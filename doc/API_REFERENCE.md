# Brick Auth API Reference

This document provides a comprehensive reference for all Brick Auth API endpoints.

## Base URL

All API endpoints are relative to the base URL of the Brick Auth service:
- **Development**: `http://localhost:17001`
- **Production**: `http://your-domain:17001`

## Authentication

Most endpoints require authentication using JWT tokens. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Core Authentication APIs

### Login

**POST** `/login`

Authenticate a user and receive a JWT token.

**Request Body:**
```json
{
  "username": "brick-super-admin",
  "password": "brickpass"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "brick-super-admin",
    "role": "super-admin",
    "permissions": ["user/*", "role/*", "permission/*", "clock/*"]
  }
}
```

### Validate Token

**POST** `/validate`

Validate a JWT token and return user information.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "brick-super-admin",
    "role": "super-admin",
    "permissions": ["user/*", "role/*", "permission/*", "clock/*"]
  }
}
```

**Alternative: GET** `/validate`

Same functionality as POST, provided for compatibility.

### Refresh Token

**POST** `/refresh`

Refresh an existing JWT token.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "brick-super-admin",
    "role": "super-admin",
    "permissions": ["user/*", "role/*", "permission/*", "clock/*"]
  }
}
```

### Get Current User

**GET** `/me`

Get information about the currently authenticated user.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": 1,
  "username": "brick-super-admin",
  "email": "admin@brick.com",
  "first_name": "Super",
  "last_name": "Admin",
  "role": "super-admin",
  "is_active": true,
  "permissions": ["user/*", "role/*", "permission/*", "clock/*"]
}
```

## System APIs

### Health Check

**GET** `/health`

Check the health status of the auth service.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "uptime": "2h 15m 30s"
}
```

### Version Information

**GET** `/version`

Get version and build information.

**Response:**
```json
{
  "version": "1.0.0",
  "build_date": "2024-01-15T08:00:00Z",
  "environment": "production",
  "service": "brick-auth"
}
```

## Super Admin APIs

### User Management

#### List Users
**GET** `/admin/users`

**Headers:** `Authorization: Bearer <super-admin-token>`

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "brick-super-admin",
      "email": "admin@brick.com",
      "first_name": "Super",
      "last_name": "Admin",
      "role": "super-admin",
      "is_active": true
    }
  ]
}
```

#### Create User
**POST** `/admin/users`

**Headers:** `Authorization: Bearer <super-admin-token>`

**Request Body:**
```json
{
  "username": "newuser",
  "password": "securepassword",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role_id": 2
}
```

#### Update User
**PUT** `/admin/users/{id}`

**Headers:** `Authorization: Bearer <super-admin-token>`

**Request Body:**
```json
{
  "email": "updated@example.com",
  "first_name": "Jane",
  "last_name": "Smith",
  "is_active": true,
  "role_id": 3
}
```

#### Delete User
**DELETE** `/admin/users/{id}`

**Headers:** `Authorization: Bearer <super-admin-token>`

### Role Management

#### List Roles
**GET** `/admin/roles`

**Headers:** `Authorization: Bearer <super-admin-token>`

#### Create Role
**POST** `/admin/roles`

**Headers:** `Authorization: Bearer <super-admin-token>`

**Request Body:**
```json
{
  "name": "moderator",
  "description": "Content Moderator",
  "permissions": [1, 2, 3]
}
```

#### Update Role
**PUT** `/admin/roles/{id}`

**Headers:** `Authorization: Bearer <super-admin-token>`

#### Delete Role
**DELETE** `/admin/roles/{id}`

**Headers:** `Authorization: Bearer <super-admin-token>`

### Permission Management

#### List Permissions
**GET** `/admin/permissions`

**Headers:** `Authorization: Bearer <super-admin-token>`

#### Create Permission
**POST** `/admin/permissions`

**Headers:** `Authorization: Bearer <super-admin-token>`

**Request Body:**
```json
{
  "name": "content_edit",
  "description": "Edit content",
  "resource": "content",
  "action": "edit"
}
```

#### Update Permission
**PUT** `/admin/permissions/{id}`

**Headers:** `Authorization: Bearer <super-admin-token>`

#### Delete Permission
**DELETE** `/admin/permissions/{id}`

**Headers:** `Authorization: Bearer <super-admin-token>`

## Error Responses

### Standard Error Format
```json
{
  "error": "Error message description"
}
```

### HTTP Status Codes

| Code | Description | Example |
|------|-------------|---------|
| 200 | Success | Login successful |
| 201 | Created | User created successfully |
| 400 | Bad Request | Invalid request format |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Super-admin access required |
| 404 | Not Found | User not found |
| 409 | Conflict | Username already exists |
| 500 | Internal Server Error | Database connection failed |

### Common Error Messages

- `"Authentication required"` - Missing or invalid JWT token
- `"Super-admin access required"` - Insufficient privileges
- `"Invalid request format"` - Malformed JSON or missing fields
- `"Username already exists"` - Username is already taken
- `"User not found"` - Requested user doesn't exist
- `"Failed to create user"` - Database or validation error

## Default Users

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| brick-super-admin | brickpass | super-admin | All permissions |
| brick-admin | brickpass | admin | Clock + user read |
| brick | brickpass | user | Basic clock view |

## Permission System

### Permission Format
Permissions use `resource/action` format:
- `clock/view` - View clock status
- `clock/clients` - View clock clients
- `clock/server_mode` - Manage clock server mode
- `clock/servers` - Manage clock servers
- `user/read` - Read user information
- `user/create` - Create users
- `user/update` - Update users
- `user/delete` - Delete users
- `role/*` - Role management permissions
- `permission/*` - Permission management permissions

### Permission Matrix

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

## Testing

### Test Scripts
```bash
# Basic authentication tests
cd brick-auth
./scripts/test.sh

# Admin API tests
./scripts/test_admin.sh
```

### Manual Testing with curl

```bash
# Login
curl -X POST http://localhost:17001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"brick-super-admin","password":"brickpass"}'

# Validate token
curl -H "Authorization: Bearer <token>" \
  http://localhost:17001/validate

# Get user info
curl -H "Authorization: Bearer <token>" \
  http://localhost:17001/me

# Health check
curl http://localhost:17001/health
```

## Rate Limiting

Currently, no rate limiting is implemented. Future versions may include:
- Login attempt limiting
- API call rate limiting
- IP-based restrictions

## Security Considerations

1. **JWT Token Security**: Tokens expire after 15 minutes
2. **Password Requirements**: Minimum 8 characters with complexity
3. **Role-based Access**: Fine-grained permission control
4. **Audit Logging**: All operations are logged
5. **Input Validation**: All inputs are validated and sanitized 