package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Service handles authentication and authorization operations
type Service struct {
	userRepo         UserRepository
	organizationRepo OrganizationRepository
	roleRepo         RoleRepository
	sessionRepo      SessionRepository
	apiKeyRepo       APIKeyRepository
	jwtSecret        []byte
	jwtExpiry        time.Duration
	refreshExpiry    time.Duration
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(user *User) error
	GetByID(id string) (*User, error)
	GetByEmail(email string) (*User, error)
	GetByUsername(username string) (*User, error)
	Update(user *User) error
	Delete(id string) error
	List(orgID string, limit, offset int) ([]*User, error)
}

// OrganizationRepository defines the interface for organization data operations
type OrganizationRepository interface {
	Create(org *Organization) error
	GetByID(id string) (*Organization, error)
	GetBySlug(slug string) (*Organization, error)
	Update(org *Organization) error
	Delete(id string) error
	List(limit, offset int) ([]*Organization, error)
}

// RoleRepository defines the interface for role data operations
type RoleRepository interface {
	Create(role *Role) error
	GetByID(id string) (*Role, error)
	GetByName(name string) (*Role, error)
	Update(role *Role) error
	Delete(id string) error
	List(limit, offset int) ([]*Role, error)
}

// SessionRepository defines the interface for session data operations
type SessionRepository interface {
	Create(session *Session) error
	GetByToken(token string) (*Session, error)
	GetByUserID(userID string) ([]*Session, error)
	Update(session *Session) error
	Delete(token string) error
	DeleteByUserID(userID string) error
	CleanupExpired() error
}

// APIKeyRepository defines the interface for API key data operations
type APIKeyRepository interface {
	Create(apiKey *APIKey) error
	GetByID(id string) (*APIKey, error)
	GetByKeyHash(keyHash string) (*APIKey, error)
	GetByUserID(userID string) ([]*APIKey, error)
	Update(apiKey *APIKey) error
	Delete(id string) error
	CleanupExpired() error
}

// NewService creates a new authentication service
func NewService(
	userRepo UserRepository,
	organizationRepo OrganizationRepository,
	roleRepo RoleRepository,
	sessionRepo SessionRepository,
	apiKeyRepo APIKeyRepository,
	jwtSecret []byte,
	jwtExpiry, refreshExpiry time.Duration,
) *Service {
	return &Service{
		userRepo:         userRepo,
		organizationRepo: organizationRepo,
		roleRepo:         roleRepo,
		sessionRepo:      sessionRepo,
		apiKeyRepo:       apiKeyRepo,
		jwtSecret:        jwtSecret,
		jwtExpiry:        jwtExpiry,
		refreshExpiry:    refreshExpiry,
	}
}

// Register creates a new user account
func (s *Service) Register(req *RegisterRequest) (*User, error) {
	// Check if user already exists
	existingUser, _ := s.userRepo.GetByEmail(req.Email)
	if existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	existingUser, _ = s.userRepo.GetByUsername(req.Username)
	if existingUser != nil {
		return nil, fmt.Errorf("user with username %s already exists", req.Username)
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &User{
		ID:           generateID(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: string(passwordHash),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsActive:     true,
		IsVerified:   false, // Require email verification
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// Login authenticates a user and returns a session
func (s *Service) Login(req *LoginRequest) (*LoginResponse, error) {
	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Get organization if specified
	var organization *Organization
	if req.Organization != "" {
		org, err := s.organizationRepo.GetBySlug(req.Organization)
		if err != nil {
			return nil, fmt.Errorf("invalid organization")
		}
		organization = org
	}

	// Create session
	session := &Session{
		ID:             generateID(),
		UserID:         user.ID,
		OrganizationID: organization.ID,
		Token:          generateToken(),
		RefreshToken:   generateToken(),
		UserAgent:      "", // Will be set by handler
		IPAddress:      "", // Will be set by handler
		ExpiresAt:      time.Now().Add(s.jwtExpiry),
		CreatedAt:      time.Now(),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate JWT token
	token, err := s.generateJWT(user, organization, session)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Update last login
	now := time.Now()
	user.LastLogin = &now
	s.userRepo.Update(user)

	return &LoginResponse{
		User:         user,
		Organization: organization,
		Token:        token,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

// Logout invalidates a user session
func (s *Service) Logout(token string) error {
	return s.sessionRepo.Delete(token)
}

// RefreshToken generates a new access token using a refresh token
func (s *Service) RefreshToken(refreshToken string) (*LoginResponse, error) {
	// Get session by refresh token
	sessions, err := s.sessionRepo.GetByUserID("") // We need to find by refresh token
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	var session *Session
	for _, s := range sessions {
		if s.RefreshToken == refreshToken {
			session = s
			break
		}
	}

	if session == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get organization
	var organization *Organization
	if session.OrganizationID != "" {
		org, err := s.organizationRepo.GetByID(session.OrganizationID)
		if err != nil {
			return nil, fmt.Errorf("organization not found")
		}
		organization = org
	}

	// Generate new token
	token, err := s.generateJWT(user, organization, session)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &LoginResponse{
		User:         user,
		Organization: organization,
		Token:        token,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

// ValidateToken validates a JWT token and returns the auth context
func (s *Service) ValidateToken(tokenString string) (*AuthContext, error) {
	// Parse and validate JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Extract user ID
	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID in token")
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get organization if specified
	var organization *Organization
	if orgID, ok := claims["organization_id"].(string); ok && orgID != "" {
		org, err := s.organizationRepo.GetByID(orgID)
		if err != nil {
			return nil, fmt.Errorf("organization not found")
		}
		organization = org
	}

	// Get user roles and permissions
	roles, permissions, err := s.getUserRolesAndPermissions(user.ID, organization.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return &AuthContext{
		User:         user,
		Organization: organization,
		Roles:        roles,
		Permissions:  permissions,
	}, nil
}

// CreateAPIKey creates a new API key for a user
func (s *Service) CreateAPIKey(userID, organizationID, name string, permissions []string, expiresAt *time.Time) (*APIKey, string, error) {
	// Generate API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}
	key := hex.EncodeToString(keyBytes)

	// Hash the key for storage
	keyHash := sha256.Sum256([]byte(key))
	keyHashStr := hex.EncodeToString(keyHash[:])

	// Create API key record
	apiKey := &APIKey{
		ID:             generateID(),
		Name:           name,
		KeyHash:        keyHashStr,
		UserID:         userID,
		OrganizationID: organizationID,
		Permissions:    permissions,
		ExpiresAt:      expiresAt,
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.apiKeyRepo.Create(apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to create API key: %w", err)
	}

	return apiKey, key, nil
}

// ValidateAPIKey validates an API key and returns the auth context
func (s *Service) ValidateAPIKey(key string) (*AuthContext, error) {
	// Hash the provided key
	keyHash := sha256.Sum256([]byte(key))
	keyHashStr := hex.EncodeToString(keyHash[:])

	// Get API key
	apiKey, err := s.apiKeyRepo.GetByKeyHash(keyHashStr)
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}

	if !apiKey.IsActive {
		return nil, fmt.Errorf("API key is inactive")
	}

	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, fmt.Errorf("API key expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(apiKey.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get organization
	var organization *Organization
	if apiKey.OrganizationID != "" {
		org, err := s.organizationRepo.GetByID(apiKey.OrganizationID)
		if err != nil {
			return nil, fmt.Errorf("organization not found")
		}
		organization = org
	}

	// Update last used
	now := time.Now()
	apiKey.LastUsed = &now
	s.apiKeyRepo.Update(apiKey)

	return &AuthContext{
		User:         user,
		Organization: organization,
		Permissions:  apiKey.Permissions,
	}, nil
}

// CheckPermission checks if the auth context has a specific permission
func (s *Service) CheckPermission(ctx *AuthContext, permission string) bool {
	for _, p := range ctx.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// Helper functions

func (s *Service) generateJWT(user *User, organization *Organization, session *Session) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     session.ExpiresAt.Unix(),
		"iat":     time.Now().Unix(),
	}

	if organization != nil {
		claims["organization_id"] = organization.ID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *Service) getUserRolesAndPermissions(userID, organizationID string) ([]Role, []string, error) {
	// This would typically query the database for user roles
	// For now, return default permissions based on role
	// In a real implementation, you'd query the UserRole table

	// Default to scanner role for now
	role := &Role{
		ID:          "scanner",
		Name:        RoleScanner,
		Description: "Scanner role with basic permissions",
		Permissions: DefaultRolePermissions[RoleScanner],
	}

	permissions := make([]string, len(role.Permissions))
	copy(permissions, role.Permissions)

	return []Role{*role}, permissions, nil
}

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
