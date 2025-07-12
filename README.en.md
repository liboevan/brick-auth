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
├── main.go                 # Main application entry
├── models.go               # Data models
├── config.go               # Configuration management
├── handlers.go             # API handlers
├── database.go             # Database management
├── Dockerfile              # Docker build file
├── go.mod                  # Go module file
├── private_rsa_pkcs1.pem   # RSA private key
├── scripts/                # Scripts
│   └── test_improved.sh
└── README.md               # Documentation
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
- `BRICK_AUTH_TOKEN_EXPIRY` - Token expiry (default: 15m)
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

### System Endpoints
- `GET /health` - Health check
- `GET /version` - Version info

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
Permissions use the `resource/action` format:
- `clock/view` - View clock status
- `clock/clients` - View clock clients
- `clock/server_mode` - Manage clock server mode
- `clock/servers` - Manage clock servers
- `user/read` - Read user info
- `user/create` - Create users
- `user/update` - Update users
- `user/delete` - Delete users
- `role/*` - Role management
- `permission/*` - Permission management

### Role Permission Matrix

| Permission      | super-admin | admin | user |
|-----------------|-------------|-------|------|
| clock/view      | ✅          | ✅    | ✅   |
| clock/clients   | ✅          | ✅    | ✅   |
| clock/server_mode| ✅         | ✅    | ❌   |
| clock/servers   | ✅          | ✅    | ❌   |
| user/read       | ✅          | ✅    | ❌   |
| user/create     | ✅          | ❌    | ❌   |
| user/update     | ✅          | ❌    | ❌   |
| user/delete     | ✅          | ❌    | ❌   |
| role/*          | ✅          | ❌    | ❌   |
| permission/*    | ✅          | ❌    | ❌   |

## Monitoring & Logging

### Log Files
- Location: `/var/log/brick-auth/app.log`
- Format: JSON
- Rotation: Automatic

### Health Check
- Endpoint: `http://localhost:17001/health`
- Response: Service status and version

### Audit Log
- All auth events are logged
- Includes user actions, IP, user agent, etc.
- Logs older than 90 days are auto-cleaned

## Technical Highlights

- SQLite for user data
- RSA key pair for JWT signing
- bcrypt password hashing
- Role-based permission control
- 15-minute JWT expiry
- Supports PKCS1 and PKCS8 private key formats
- Automatic session and audit log cleanup
- CORS support
- Config validation and error handling

## Security Configuration

### Password Policy
- Min length: 8 characters
- Require uppercase: yes
- Require lowercase: yes
- Require number: yes
- Require special char: no

### Login Limiting
- Max attempts: 5
- Lockout: 15 minutes

### Session Management
- Token expiry: 15 minutes
- Refresh token expiry: 7 days
- Session expiry: 24 hours

## Troubleshooting

### Common Issues

1. **Database connection failed**
   - Check DB file permissions
   - Ensure directory exists and is writable

2. **Private key load failed**
   - Check private key path
   - Validate key format (PKCS1 or PKCS8)

3. **Permission validation failed**
   - Check user role and permission assignment
   - Validate token

4. **Config error**
   - Check environment variables
   - Validate config file format

### Debug Commands

```bash
# Check service status
docker ps | grep brick-auth

# View service logs
docker logs el-brick-auth

# Test auth endpoint
curl -X POST http://localhost:17001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"brick-admin","password":"brickpass"}'

# Test token validation
curl -H "Authorization: Bearer <token>" \
  http://localhost:17001/validate
```

## Documentation

For detailed documentation, see the `doc/` directory:

- [API Reference](doc/API_REFERENCE.md) - Complete API documentation
- [Super Admin API](doc/ADMIN_API.md) - Administrator-specific APIs
- [Deployment Guide](doc/DEPLOYMENT.md) - Deployment and configuration instructions
- [Database Design](doc/DATABASE_REDESIGN.md) - Database architecture documentation

## Roadmap

- [x] User management API ✅
- [x] Role management API ✅
- [x] Permission management API ✅
- [ ] Password policy configuration
- [ ] Enhanced session management
- [ ] Audit log interface
- [ ] Password reset functionality
- [ ] Multi-factor authentication 