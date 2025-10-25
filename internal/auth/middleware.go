package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware provides authentication middleware for HTTP handlers
type AuthMiddleware struct {
	authService *Service
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService *Service) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// RequireAuth middleware that requires authentication
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check for Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token
		authCtx, err := m.authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set auth context in request
		c.Set("auth_context", authCtx)
		c.Next()
	}
}

// RequireAPIKey middleware that requires API key authentication
func (m *AuthMiddleware) RequireAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from header
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			c.Abort()
			return
		}

		// Validate API key
		authCtx, err := m.authService.ValidateAPIKey(apiKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		// Set auth context in request
		c.Set("auth_context", authCtx)
		c.Next()
	}
}

// RequirePermission middleware that requires a specific permission
func (m *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get auth context from request
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid auth context"})
			c.Abort()
			return
		}

		// Check permission
		if !m.authService.CheckPermission(ctx, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware that requires a specific role
func (m *AuthMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get auth context from request
		authCtx, exists := c.Get("auth_context")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		ctx, ok := authCtx.(*AuthContext)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid auth context"})
			c.Abort()
			return
		}

		// Check role
		hasRole := false
		for _, r := range ctx.Roles {
			if r.Name == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient role"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetAuthContext extracts the auth context from the request
func GetAuthContext(c *gin.Context) *AuthContext {
	authCtx, exists := c.Get("auth_context")
	if !exists {
		return nil
	}

	ctx, ok := authCtx.(*AuthContext)
	if !ok {
		return nil
	}

	return ctx
}

// ContextKey is used for storing values in context
type ContextKey string

const (
	AuthContextKey ContextKey = "auth_context"
	UserIDKey      ContextKey = "user_id"
	OrgIDKey       ContextKey = "organization_id"
)

// SetAuthContext sets the auth context in the request context
func SetAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	ctx = context.WithValue(ctx, AuthContextKey, authCtx)
	ctx = context.WithValue(ctx, UserIDKey, authCtx.User.ID)
	if authCtx.Organization != nil {
		ctx = context.WithValue(ctx, OrgIDKey, authCtx.Organization.ID)
	}
	return ctx
}

// GetAuthContextFromContext extracts the auth context from the request context
func GetAuthContextFromContext(ctx context.Context) *AuthContext {
	authCtx, ok := ctx.Value(AuthContextKey).(*AuthContext)
	if !ok {
		return nil
	}
	return authCtx
}

// GetUserIDFromContext extracts the user ID from the request context
func GetUserIDFromContext(ctx context.Context) string {
	userID, ok := ctx.Value(UserIDKey).(string)
	if !ok {
		return ""
	}
	return userID
}

// GetOrganizationIDFromContext extracts the organization ID from the request context
func GetOrganizationIDFromContext(ctx context.Context) string {
	orgID, ok := ctx.Value(OrgIDKey).(string)
	if !ok {
		return ""
	}
	return orgID
}
