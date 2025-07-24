**[简体中文](README.md)** | English Version

---

# Brick Auth Service

Brick Auth provides user authentication, JWT token management, and permission control for microservice architectures.

## Features

### 🔐 Improved Permission System
- **Role-Based Access Control (RBAC):** Fine-grained management of roles and permissions
- **Resource-Action Model:** Permissions in `resource/action` format
- **Dynamic Assignment:** Runtime assignment and modification of permissions

### 🛡️ Enhanced Security
- **Password Policy:** Configurable password complexity requirements
- **Session Management:** Session tracking and automatic cleanup
- **Audit Logging:** Full audit trail of user actions
- **Login Limiting:** Configurable login attempt limits

### 📊 Improved Database Design
- **Normalized Structure:** Eliminates redundancy, ensures data consistency
- **Foreign Key Constraints:** Data integrity
- **Scalability:** Easy to add new roles and permissions

### ⚙️ Flexible Configuration
- **Environment Variables:** Comprehensive env var support
- **Config File:** JSON config file support
- **Config Validation:** Startup config validation
- **Runtime Reload:** Supports runtime config reload

## Directory Structure

```
brick-auth/
├── cmd/                    # Application entry points
│   ├── auth/              # Main authentication service
│   └── seeder/            # Data seeding tool
├── pkg/                   # Core packages
│   ├── auth/              # Authentication core logic
│   ├── user/              # User management
│   ├── httpapi/           # HTTP API routing
│   ├── config/            # Configuration management
│   ├── database/          # Database management
│   └── models/            # Data models
├── doc/                   # Documentation
│   ├── API_REFERENCE.md   # API reference documentation
│   ├── DEPLOYMENT.md      # Deployment guide
│   └── DATABASE_REDESIGN.md # Database design
├── scripts/               # Script files
├── data/                  # Data files
├── config/                # Configuration files
├── Dockerfile             # Docker build file
├── entrypoint.sh          # Container entry script
├── go.mod                 # Go module file
└── README.md              # This documentation
```

## Container Best Practices

### Directory Layout
- `/etc/brick-auth/` - Config files
- `/var/log/brick-auth/` - Log files
- `/var/lib/brick-auth/` - Data files
- `/app/` - Application files

### Environment Variables
- `BRICK_AUTH_PORT` - Service port (default: 17001)
- `BRICK_AUTH_HOST` - Service host (default: 0.0.0.0)
- `BRICK_AUTH_DB_PATH` - Database path (default: /var/lib/brick-auth/auth.db)
- `BRICK_AUTH_PRIVATE_KEY_PATH` - Private key path (default: /app/private.pem)
- `BRICK_AUTH_TOKEN_EXPIRY` - Token expiry (default: 24h)
- `BRICK_AUTH_PASSWORD_MIN_LENGTH` - Password min length (default: 8)
- `BRICK_AUTH_MAX_LOGIN_ATTEMPTS` - Max login attempts (default: 5)
- `BRICK_AUTH_ENABLE_AUDIT_LOG` - Enable audit log (default: true)
- `BRICK_AUTH_ENABLE_SESSION_TRACKING` - Enable session tracking (default: true)

### Security Features
- Runs as non-root user (brick:1000)
- Standard Linux directory layout
- Health check endpoint
- Environment variable configuration
- Fewer Docker layers (merged RUN commands)

## Build & Run

### Local Build
```bash
docker build -t brick-auth:latest .
```

### With Docker Compose
```bash
cd ../brick-deployment
docker-compose up auth
```

### Health Check
```bash
curl http://localhost:17001/health
```

### Version Info
```bash
curl http://localhost:17001/version
```

## API Endpoints

### Auth Endpoints
- `POST /login` - User login
- `POST /validate` - Validate JWT token
- `GET /validate` - Validate JWT token (compatibility)
- `POST /refresh` - Refresh token
- `GET /me` - Get current user info
- `POST /token/decode` - Decode token

### System Endpoints
- `GET /health` - Health check
- `GET /version` - Version info

### Super Admin Endpoints (requires super-admin permission)

#### User Management
- `GET /admin/users` - Get all users
- `POST /admin/users` - Create user
- `GET /admin/users/:id` - Get user details
- `PUT /admin/users/:id` - Update user
- `DELETE /admin/users/:id` - Delete user

#### Role Management
- `GET /admin/roles` - Get all roles
- `POST /admin/roles` - Create role
- `GET /admin/roles/:id` - Get role details
- `PUT /admin/roles/:id` - Update role
- `DELETE /admin/roles/:id` - Delete role

#### Permission Management
- `GET /admin/permissions` - Get all permissions
- `POST /admin/permissions` - Create permission
- `GET /admin/permissions/:id` - Get permission details
- `PUT /admin/permissions/:id` - Update permission
- `DELETE /admin/permissions/:id` - Delete permission

## Default Users

### Super Admin
- **Username:** `brick-super-admin`
- **Password:** `brickpass`
- **Role:** `super-admin`
- **Permissions:** All permissions including user, role, and permission management

### Admin
- **Username:** `brick-admin`
- **Password:** `brickpass`
- **Role:** `admin`
- **Permissions:** Clock management and user viewing permissions

### Regular User
- **Username:** `brick`
- **Password:** `brickpass`
- **Role:** `user`
- **Permissions:** Basic clock viewing permissions

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

### Role Permission Matrix

| Permission | super-admin | admin | user |
|------------|-------------|-------|------|
| clock/view | ✅ | ✅ | ✅ |
| clock/clients | ✅ | ✅ | ✅ |
| clock/server_mode | ✅ | ✅ | ❌ |
| clock/servers | ✅ | ✅ | ❌ |
| user/read | ✅ | ✅ | ❌ |
| user/create | ✅ | ❌ | ❌ |
| user/update | ✅ | ❌ | ❌ |
| user/delete | ✅ | ❌ | ❌ |
| role/* | ✅ | ❌ | ❌ |
| permission/* | ✅ | ❌ | ❌ |

## Monitoring and Logging

### Log Files
- Location: `/var/log/brick-auth/app.log`
- Format: JSON format
- Rotation: Automatic log rotation

### Health Check
- Endpoint: `http://localhost:17001/health`
- Response: Service status and version information

### Audit Logging
- Automatically records all authentication events
- Includes user actions, IP addresses, user agents, etc.
- Automatically cleans up logs older than 90 days

## Technical Features

- Uses SQLite database for user information storage
- RSA key pair for JWT signing
- bcrypt password hashing
- Role-based permission control
- 24-hour JWT token expiration
- Supports PKCS1 and PKCS8 private key formats
- Automatic session and audit log cleanup
- CORS support
- Configuration validation and error handling

## Security Configuration

### Password Policy
- Minimum length: 8 characters
- Require uppercase: Yes
- Require lowercase: Yes
- Require numbers: Yes
- Require special characters: No

### Login Restrictions
- Maximum login attempts: 5
- Lockout duration: 15 minutes

### Session Management
- Token expiration: 24 hours
- Refresh token expiration: 7 days
- Session expiration: 24 hours

## Troubleshooting

### Common Issues

1. **Database Connection Failure**
   - Check database file permissions
   - Ensure directory exists and is writable

2. **Private Key Loading Failure**
   - Check private key file path
   - Verify private key format (PKCS1 or PKCS8)

3. **Permission Validation Failure**
   - Check user role and permission assignments
   - Verify token validity

4. **Configuration Errors**
   - Check environment variable settings
   - Verify configuration file format

### Debug Commands

```bash
# Check service status
docker ps | grep brick-auth

# View service logs
docker logs brick-auth

# Test authentication endpoint
curl -X POST http://localhost:17001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"brick-admin","password":"brickpass"}'

# Test token validation
curl -H "Authorization: Bearer <token>" \
  http://localhost:17001/validate

# Test super admin API
curl -H "Authorization: Bearer <super-admin-token>" \
  http://localhost:17001/admin/users
```

## Documentation

For detailed documentation, see the `doc/` directory:

- [API Reference](doc/API_REFERENCE.md) - Complete API documentation
- [Super Admin API](doc/ADMIN_API.md) - Admin-specific APIs
- [Deployment Guide](doc/DEPLOYMENT.md) - Deployment and configuration instructions
- [Database Design](doc/DATABASE_REDESIGN.md) - Database architecture documentation

## Future Plans

- [x] User Management API ✅
- [x] Role Management API ✅
- [x] Permission Management API ✅
- [x] JWT Token Management ✅
- [x] Session Management ✅
- [x] Audit Logging ✅
- [ ] Password Policy Configuration
- [ ] Enhanced Session Management
- [ ] Audit Log Interface
- [ ] Password Reset Functionality
- [ ] Multi-Factor Authentication
- [ ] API Versioning