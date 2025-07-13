package httpapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"brick-auth/pkg/auth"
	"brick-auth/pkg/user"
)

// Router handles HTTP routing
type Router struct {
	engine      *gin.Engine
	db          *gorm.DB
	authHandler *auth.Handler
	userHandler *user.Handler
}

// NewRouter creates a new router
func NewRouter(db *gorm.DB, authHandler *auth.Handler, userHandler *user.Handler) *Router {
	router := &Router{
		engine:      gin.Default(),
		db:          db,
		authHandler: authHandler,
		userHandler: userHandler,
	}

	router.setupMiddleware()
	router.setupRoutes()

	return router
}

// setupMiddleware sets up middleware
func (r *Router) setupMiddleware() {
	// Add CORS middleware
	r.engine.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})
}

// setupRoutes sets up all routes
func (r *Router) setupRoutes() {
	// Health check endpoint
	r.engine.GET("/health", r.healthCheck)
	
	// Version endpoint
	r.engine.GET("/version", r.version)

	// Authentication routes
	r.engine.POST("/login", r.authHandler.Login)
	r.engine.POST("/validate", r.authHandler.ValidateToken)
	r.engine.GET("/validate", r.authHandler.ValidateToken)  // Also support GET for hub compatibility
	r.engine.POST("/refresh", r.authHandler.RefreshToken)
	r.engine.GET("/me", r.authHandler.Me)
	r.engine.POST("/token/decode", r.authHandler.DecodeToken)

	// Super-admin management routes
	admin := r.engine.Group("/admin")
	admin.Use(r.superAdminMiddleware())

	// User management
	admin.GET("/users", r.userHandler.ListUsers)
	admin.POST("/users", r.userHandler.CreateUser)
	admin.GET("/users/:id", r.userHandler.GetUser)
	admin.PUT("/users/:id", r.userHandler.UpdateUser)
	admin.DELETE("/users/:id", r.userHandler.DeleteUser)

	// Role management
	admin.GET("/roles", r.userHandler.ListRoles)
	admin.POST("/roles", r.userHandler.CreateRole)
	admin.GET("/roles/:id", r.userHandler.GetRole)
	admin.PUT("/roles/:id", r.userHandler.UpdateRole)
	admin.DELETE("/roles/:id", r.userHandler.DeleteRole)

	// Permission management
	admin.GET("/permissions", r.userHandler.ListPermissions)
	admin.POST("/permissions", r.userHandler.CreatePermission)
	admin.GET("/permissions/:id", r.userHandler.GetPermission)
	admin.PUT("/permissions/:id", r.userHandler.UpdatePermission)
	admin.DELETE("/permissions/:id", r.userHandler.DeletePermission)
}

// superAdminMiddleware checks if user is super-admin
func (r *Router) superAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		claims, err := r.authHandler.ValidateTokenString(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims.Role != "super-admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Super-admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// healthCheck handles health check requests
func (r *Router) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now().UTC(),
	})
}

// version handles version requests
func (r *Router) version(c *gin.Context) {
	buildInfo := r.loadBuildInfo()
	c.JSON(http.StatusOK, buildInfo)
}

// loadBuildInfo loads build information
func (r *Router) loadBuildInfo() *BuildInfo {
	return &BuildInfo{
		Version:        "0.1.0-dev",
		BuildDateTime:  "2025-07-10T13:00:00Z",
		BuildTimestamp: time.Now().Unix(),
		Environment:    "production",
		Service:        "brick-auth",
		Description:    "Brick Authentication Service",
	}
}

// BuildInfo struct
type BuildInfo struct {
	Version        string `json:"version"`
	BuildDateTime  string `json:"buildDateTime"`
	BuildTimestamp int64  `json:"buildTimestamp"`
	Environment    string `json:"environment"`
	Service        string `json:"service"`
	Description    string `json:"description"`
}

// GetEngine returns the gin engine
func (r *Router) GetEngine() *gin.Engine {
	return r.engine
} 