# Brick Auth Deployment Guide

This document provides comprehensive instructions for deploying the Brick Auth service in various environments.

## Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for local development)
- SQLite (for local development)

## Quick Start

### Using Docker Compose

1. **Clone the repository:**
```bash
git clone <repository-url>
cd brick
```

2. **Start the auth service:**
```bash
cd brick-deployment
docker-compose up auth
```

3. **Verify the service is running:**
```bash
curl http://localhost:17001/health
```

### Local Development

1. **Navigate to the auth service:**
```bash
cd brick-auth
```

2. **Install dependencies:**
```bash
go mod download
```

3. **Run the service:**
```bash
go run .
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BRICK_AUTH_PORT` | 17001 | Service port |
| `BRICK_AUTH_HOST` | 0.0.0.0 | Service host |
| `BRICK_AUTH_DB_PATH` | /var/lib/brick-auth/auth.db | Database path |
| `BRICK_AUTH_PRIVATE_KEY_PATH` | /app/private.pem | RSA private key path |
| `BRICK_AUTH_TOKEN_EXPIRY` | 15m | JWT token expiry time |
| `BRICK_AUTH_PASSWORD_MIN_LENGTH` | 8 | Minimum password length |
| `BRICK_AUTH_MAX_LOGIN_ATTEMPTS` | 5 | Maximum login attempts |
| `BRICK_AUTH_ENABLE_AUDIT_LOG` | true | Enable audit logging |
| `BRICK_AUTH_ENABLE_SESSION_TRACKING` | true | Enable session tracking |

### Docker Configuration

The service uses a multi-stage Docker build for optimal image size:

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder
# ... build instructions

# Runtime stage
FROM alpine:latest
# ... runtime configuration
```

### Security Features

- **Non-root user**: Runs as `brick:1000`
- **Standard directories**: Uses `/var/lib/brick-auth/` for data
- **Health checks**: Built-in health check endpoint
- **Environment configuration**: All settings via environment variables

## Database Setup

### Initialization

The database is automatically initialized on first run with default users:

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| brick-super-admin | brickpass | super-admin | All permissions |
| brick-admin | brickpass | admin | Clock + user read |
| brick | brickpass | user | Basic clock view |

### Manual Initialization

If you need to reinitialize the database:

```bash
# Stop the service
docker-compose stop auth

# Remove the database file
rm /var/lib/brick-auth/auth.db

# Restart the service
docker-compose up auth
```

## Integration with Other Services

### Gateway Configuration

The auth service integrates with `brick-gateway` (nginx) for JWT validation:

```nginx
# Add to nginx.conf
upstream brick_auth {
    server brick-auth:17001;
}

# JWT validation
location /api/auth/validate {
    internal;
    proxy_pass http://brick_auth/validate;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header Authorization $http_authorization;
}
```

### Frontend Integration

The `brick-hub` frontend integrates with the auth service:

```javascript
// Login
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password })
});

// Include token in requests
const headers = {
  'Authorization': `Bearer ${token}`,
  'Content-Type': 'application/json'
};
```

## Monitoring and Logging

### Health Checks

```bash
# Check service health
curl http://localhost:17001/health

# Get version information
curl http://localhost:17001/version
```

### Logs

```bash
# View service logs
docker logs brick-auth

# Follow logs in real-time
docker logs -f brick-auth
```

### Audit Logging

Audit logs are automatically created and rotated:
- Location: `/var/log/brick-auth/audit.log`
- Format: JSON with timestamp, user, action, and metadata
- Retention: 90 days by default

## Security Considerations

### JWT Token Security

- **Expiration**: 15 minutes by default
- **Algorithm**: RS256 (RSA with SHA-256)
- **Key rotation**: Private key should be rotated periodically

### Password Security

- **Hashing**: bcrypt with cost factor 12
- **Requirements**: Minimum 8 characters
- **Complexity**: Must include uppercase, lowercase, and numbers

### Network Security

- **Internal communication**: Services communicate via Docker network
- **External access**: Only through gateway (nginx)
- **CORS**: Properly configured for frontend integration

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check logs
   docker logs brick-auth
   
   # Verify configuration
   docker-compose config
   ```

2. **Database errors**
   ```bash
   # Check database file permissions
   ls -la /var/lib/brick-auth/
   
   # Reinitialize database
   docker-compose restart auth
   ```

3. **Authentication failures**
   ```bash
   # Test login endpoint
   curl -X POST http://localhost:17001/login \
     -H "Content-Type: application/json" \
     -d '{"username":"brick-super-admin","password":"brickpass"}'
   ```

4. **Private key issues**
   ```bash
   # Check key file
   docker exec brick-auth ls -la /app/private.pem
   
   # Verify key format
   docker exec brick-auth openssl rsa -in /app/private.pem -check
   ```

### Debug Commands

```bash
# Enter the container
docker exec -it brick-auth sh

# Check service status
ps aux | grep brick-auth

# View configuration
env | grep BRICK_AUTH

# Test database connection
sqlite3 /var/lib/brick-auth/auth.db "SELECT * FROM users;"
```

## Performance Tuning

### Resource Limits

```yaml
# docker-compose.yml
services:
  auth:
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
        reservations:
          memory: 128M
          cpus: '0.25'
```

### Database Optimization

- **Connection pooling**: Configured for optimal performance
- **Indexes**: Automatically created on frequently queried columns
- **Vacuum**: Database is automatically vacuumed periodically

## Backup and Recovery

### Database Backup

```bash
# Create backup
docker exec brick-auth sqlite3 /var/lib/brick-auth/auth.db ".backup /tmp/auth_backup.db"

# Copy backup from container
docker cp brick-auth:/tmp/auth_backup.db ./auth_backup.db
```

### Restore Database

```bash
# Stop service
docker-compose stop auth

# Replace database file
cp auth_backup.db /var/lib/brick-auth/auth.db

# Restart service
docker-compose up auth
```

## Scaling

### Horizontal Scaling

The auth service is stateless and can be scaled horizontally:

```yaml
# docker-compose.yml
services:
  auth:
    deploy:
      replicas: 3
```

### Load Balancing

When scaling, ensure all instances share the same database and private key.

## Updates and Maintenance

### Updating the Service

```bash
# Pull latest image
docker-compose pull auth

# Restart service
docker-compose up -d auth
```

### Database Migrations

Database schema changes are handled automatically on startup.

### Key Rotation

1. Generate new RSA key pair
2. Update private key file
3. Restart service
4. Update public key in dependent services

## Support

For issues and questions:
- Check the logs: `docker logs brick-auth`
- Run tests: `./scripts/test.sh`
- Review documentation in `/doc/` directory