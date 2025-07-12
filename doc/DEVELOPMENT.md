# Brick Auth Development Guide

This document provides guidelines for developers working on the Brick Auth service.

## Development Environment Setup

### Prerequisites

- Go 1.21 or later
- SQLite3
- Git
- Docker (optional, for containerized development)

### Local Development Setup

1. **Clone the repository:**
```bash
git clone <repository-url>
cd brick-auth
```

2. **Install dependencies:**
```bash
go mod download
```

3. **Generate go.sum:**
```bash
./scripts/gen-go-sum.sh
```

4. **Run the service:**
```bash
go run .
```

### Docker Development

```bash
# Build development image
docker build -t brick-auth:dev .

# Run with volume mounts for live code changes
docker run -it --rm \
  -v $(pwd):/app \
  -p 17001:17001 \
  -e BRICK_AUTH_DB_PATH=/app/auth.db \
  brick-auth:dev
```

## Project Structure

```
brick-auth/
├── main.go                 # Application entry point
├── config.go               # Configuration management
├── models.go               # Data models and structures
├── database.go             # Database operations
├── handlers.go             # Core API handlers
├── admin_handlers.go       # Admin API handlers
├── Dockerfile              # Container build file
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── scripts/                # Build and test scripts
│   ├── test.sh            # Main test script
│   └── gen-go-sum.sh      # Generate go.sum
├── doc/                    # Documentation
│   ├── API_REFERENCE.md   # Complete API docs
│   ├── ADMIN_API.md       # Admin API docs
│   ├── DEPLOYMENT.md      # Deployment guide
│   ├── DATABASE_REDESIGN.md # Database design
│   └── DEVELOPMENT.md     # This file
└── README.md              # Main documentation
```

## Code Organization

### Main Application (`main.go`)

- Application initialization
- Route definitions
- Middleware setup
- Graceful shutdown handling

### Configuration (`config.go`)

- Environment variable parsing
- Configuration validation
- Default value management
- Runtime configuration reloading

### Models (`models.go`)

- Data structures
- JSON serialization
- Validation methods
- Database mapping

### Database (`database.go`)

- Database initialization
- Schema management
- Connection handling
- Migration support

### Handlers (`handlers.go`)

- Core authentication endpoints
- JWT token management
- Permission checking
- Error handling

### Admin Handlers (`admin_handlers.go`)

- User management APIs
- Role management APIs
- Permission management APIs
- Super admin access control

## Development Workflow

### 1. Feature Development

```bash
# Create feature branch
git checkout -b feature/new-feature

# Make changes
# ... edit files ...

# Run tests
./scripts/test.sh

# Build and test
go build .
go test ./...

# Commit changes
git add .
git commit -m "Add new feature"
```

### 2. Testing

#### Unit Tests
```bash
# Run all tests
go test ./...

# Run specific test
go test -v -run TestLogin

# Run with coverage
go test -cover ./...
```

#### Integration Tests
```bash
# Run integration tests
./scripts/test.sh

# Test specific functionality
curl -X POST http://localhost:17001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"brick-super-admin","password":"brickpass"}'
```

#### Manual Testing
```bash
# Start service
go run .

# Test endpoints
curl http://localhost:17001/health
curl http://localhost:17001/version
```

### 3. Code Quality

#### Linting
```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

#### Formatting
```bash
# Format code
go fmt ./...

# Organize imports
goimports -w .
```

#### Security Scanning
```bash
# Install gosec
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Run security scan
gosec ./...
```

## API Development

### Adding New Endpoints

1. **Define the handler function:**
```go
func handleNewEndpoint(c *gin.Context) {
    // Implementation
}
```

2. **Add route in main.go:**
```go
router.POST("/new-endpoint", middleware.AuthRequired(), handleNewEndpoint)
```

3. **Add tests:**
```go
func TestNewEndpoint(t *testing.T) {
    // Test implementation
}
```

### Permission System

#### Adding New Permissions

1. **Define permission in database initialization:**
```go
permission := models.Permission{
    Name:        "new_resource_action",
    Description: "New resource action",
    Resource:    "new_resource",
    Action:      "action",
}
```

2. **Add permission check in handler:**
```go
if !hasPermission(user, "new_resource", "action") {
    c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
    return
}
```

3. **Update permission matrix in documentation**

### Database Changes

#### Adding New Tables

1. **Define model in models.go:**
```go
type NewTable struct {
    ID        int       `json:"id" db:"id"`
    Name      string    `json:"name" db:"name"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
}
```

2. **Add table creation in database.go:**
```go
CREATE TABLE new_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

3. **Add CRUD operations:**
```go
func (db *Database) CreateNewTable(item *NewTable) error {
    // Implementation
}
```

## Configuration Management

### Environment Variables

Add new configuration options:

1. **Define in config.go:**
```go
type Config struct {
    // ... existing fields
    NewSetting string `env:"BRICK_AUTH_NEW_SETTING" envDefault:"default_value"`
}
```

2. **Add validation:**
```go
func (c *Config) Validate() error {
    // ... existing validation
    if c.NewSetting == "" {
        return errors.New("BRICK_AUTH_NEW_SETTING is required")
    }
    return nil
}
```

3. **Update documentation**

### Configuration File Support

For complex configurations, use JSON files:

```go
type ConfigFile struct {
    Permissions []Permission `json:"permissions"`
    Roles       []Role       `json:"roles"`
    Users       []User       `json:"users"`
}
```

## Error Handling

### Standard Error Responses

```go
// Authentication error
c.JSON(http.StatusUnauthorized, gin.H{
    "error": "Authentication required",
})

// Authorization error
c.JSON(http.StatusForbidden, gin.H{
    "error": "Permission denied",
})

// Validation error
c.JSON(http.StatusBadRequest, gin.H{
    "error": "Invalid request format",
})

// Server error
c.JSON(http.StatusInternalServerError, gin.H{
    "error": "Internal server error",
})
```

### Custom Error Types

```go
type AuthError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}

func (e *AuthError) Error() string {
    return e.Message
}
```

## Logging

### Structured Logging

```go
import "log"

// Info logging
log.Printf("User %s logged in successfully", username)

// Error logging
log.Printf("Failed to create user: %v", err)

// Debug logging (when debug mode is enabled)
if config.Debug {
    log.Printf("Processing request: %s", requestID)
}
```

### Audit Logging

```go
func logAuditEvent(userID int, action string, details map[string]interface{}) {
    event := map[string]interface{}{
        "timestamp": time.Now().UTC(),
        "user_id":   userID,
        "action":    action,
        "details":   details,
    }
    
    log.Printf("AUDIT: %+v", event)
}
```

## Security Best Practices

### Input Validation

```go
func validateUsername(username string) error {
    if len(username) < 3 || len(username) > 50 {
        return errors.New("username must be 3-50 characters")
    }
    
    if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
        return errors.New("username contains invalid characters")
    }
    
    return nil
}
```

### SQL Injection Prevention

```go
// Use parameterized queries
query := "SELECT * FROM users WHERE username = ?"
row := db.QueryRow(query, username)

// Avoid string concatenation
// BAD: query := "SELECT * FROM users WHERE username = '" + username + "'"
```

### Password Security

```go
import "golang.org/x/crypto/bcrypt"

// Hash password
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// Verify password
err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
```

## Performance Optimization

### Database Optimization

```go
// Use prepared statements
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
defer stmt.Close()

// Use transactions for multiple operations
tx, err := db.Begin()
defer tx.Rollback()

// Use indexes on frequently queried columns
CREATE INDEX idx_users_username ON users(username);
```

### Memory Management

```go
// Use object pools for frequently allocated objects
var userPool = sync.Pool{
    New: func() interface{} {
        return &User{}
    },
}

// Reuse objects
user := userPool.Get().(*User)
defer userPool.Put(user)
```

## Testing Strategy

### Unit Tests

```go
func TestLogin(t *testing.T) {
    // Arrange
    db := setupTestDB()
    handler := NewAuthHandler(db)
    
    // Act
    response := handler.Login(testRequest)
    
    // Assert
    assert.Equal(t, http.StatusOK, response.Code)
    assert.Contains(t, response.Body.String(), "token")
}
```

### Integration Tests

```go
func TestLoginIntegration(t *testing.T) {
    // Start test server
    server := setupTestServer()
    defer server.Close()
    
    // Make request
    resp, err := http.Post(server.URL+"/login", "application/json", strings.NewReader(`{
        "username": "test",
        "password": "password"
    }`))
    
    // Assert response
    assert.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

### Performance Tests

```go
func BenchmarkLogin(b *testing.B) {
    handler := setupTestHandler()
    
    for i := 0; i < b.N; i++ {
        handler.Login(testRequest)
    }
}
```

## Deployment

### Build Process

```bash
# Build binary
go build -o brick-auth .

# Build Docker image
docker build -t brick-auth:latest .

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o brick-auth .
```

### Release Process

1. **Update version:**
```go
const Version = "1.1.0"
```

2. **Create release tag:**
```bash
git tag v1.1.0
git push origin v1.1.0
```

3. **Build and push Docker image:**
```bash
docker build -t brick-auth:v1.1.0 .
docker push brick-auth:v1.1.0
```

## Troubleshooting

### Common Development Issues

1. **Database locked**
   - Check for concurrent access
   - Use proper transaction handling
   - Close database connections

2. **Import errors**
   - Run `go mod tidy`
   - Check Go version compatibility
   - Verify module path

3. **Permission denied**
   - Check file permissions
   - Verify user permissions
   - Check Docker volume mounts

### Debug Commands

```bash
# Check Go version
go version

# Check module status
go mod verify

# Check dependencies
go list -m all

# Run with debug logging
BRICK_AUTH_DEBUG=true go run .

# Check database
sqlite3 auth.db ".tables"
```

## Contributing

### Code Style

- Follow Go formatting standards
- Use meaningful variable names
- Add comments for complex logic
- Keep functions small and focused

### Commit Messages

```
feat: add user management API
fix: resolve database connection issue
docs: update API documentation
test: add integration tests for login
```

### Pull Request Process

1. Create feature branch
2. Make changes with tests
3. Update documentation
4. Run full test suite
5. Submit pull request
6. Address review comments

## Resources

- [Go Documentation](https://golang.org/doc/)
- [Gin Framework](https://gin-gonic.com/docs/)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [JWT RFC](https://tools.ietf.org/html/rfc7519) 