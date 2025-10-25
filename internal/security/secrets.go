package security

import (
	"context"
	"fmt"
	"time"
)

// SecretsManager handles secrets management operations
type SecretsManager struct {
	backend SecretsBackend
}

// SecretsBackend defines the interface for secrets storage backends
type SecretsBackend interface {
	GetSecret(ctx context.Context, path string) (*Secret, error)
	SetSecret(ctx context.Context, path string, secret *Secret) error
	DeleteSecret(ctx context.Context, path string) error
	ListSecrets(ctx context.Context, prefix string) ([]string, error)
}

// Secret represents a stored secret
type Secret struct {
	Path      string            `json:"path"`
	Data      map[string]string `json:"data"`
	Metadata  map[string]string `json:"metadata"`
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// VaultBackend implements secrets storage using HashiCorp Vault
type VaultBackend struct {
	client VaultClient
}

// VaultClient defines the interface for Vault operations
type VaultClient interface {
	Read(path string) (map[string]interface{}, error)
	Write(path string, data map[string]interface{}) error
	Delete(path string) error
	List(path string) ([]string, error)
}

// NewSecretsManager creates a new secrets manager
func NewSecretsManager(backend SecretsBackend) *SecretsManager {
	return &SecretsManager{
		backend: backend,
	}
}

// GetSecret retrieves a secret from the backend
func (sm *SecretsManager) GetSecret(ctx context.Context, path string) (*Secret, error) {
	return sm.backend.GetSecret(ctx, path)
}

// SetSecret stores a secret in the backend
func (sm *SecretsManager) SetSecret(ctx context.Context, path string, data map[string]string, metadata map[string]string) error {
	secret := &Secret{
		Path:      path,
		Data:      data,
		Metadata:  metadata,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return sm.backend.SetSecret(ctx, path, secret)
}

// DeleteSecret removes a secret from the backend
func (sm *SecretsManager) DeleteSecret(ctx context.Context, path string) error {
	return sm.backend.DeleteSecret(ctx, path)
}

// ListSecrets lists all secrets with a given prefix
func (sm *SecretsManager) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	return sm.backend.ListSecrets(ctx, prefix)
}

// GetProxyCredentials retrieves proxy credentials for a scan
func (sm *SecretsManager) GetProxyCredentials(ctx context.Context, proxyID string) (*ProxyCredentials, error) {
	path := fmt.Sprintf("proxies/%s", proxyID)
	secret, err := sm.GetSecret(ctx, path)
	if err != nil {
		return nil, err
	}

	credentials := &ProxyCredentials{
		ID:       proxyID,
		Host:     secret.Data["host"],
		Port:     secret.Data["port"],
		Username: secret.Data["username"],
		Password: secret.Data["password"],
		Type:     secret.Data["type"],
	}

	return credentials, nil
}

// SetProxyCredentials stores proxy credentials
func (sm *SecretsManager) SetProxyCredentials(ctx context.Context, credentials *ProxyCredentials) error {
	path := fmt.Sprintf("proxies/%s", credentials.ID)

	data := map[string]string{
		"host":     credentials.Host,
		"port":     credentials.Port,
		"username": credentials.Username,
		"password": credentials.Password,
		"type":     credentials.Type,
	}

	metadata := map[string]string{
		"created_by": credentials.CreatedBy,
		"purpose":    "proxy_credentials",
	}

	return sm.SetSecret(ctx, path, data, metadata)
}

// GetAPIKey retrieves an API key for external services
func (sm *SecretsManager) GetAPIKey(ctx context.Context, service, keyID string) (*APIKey, error) {
	path := fmt.Sprintf("api-keys/%s/%s", service, keyID)
	secret, err := sm.GetSecret(ctx, path)
	if err != nil {
		return nil, err
	}

	apiKey := &APIKey{
		ID:      keyID,
		Service: service,
		Key:     secret.Data["key"],
		Secret:  secret.Data["secret"],
		Region:  secret.Data["region"],
	}

	return apiKey, nil
}

// SetAPIKey stores an API key for external services
func (sm *SecretsManager) SetAPIKey(ctx context.Context, apiKey *APIKey) error {
	path := fmt.Sprintf("api-keys/%s/%s", apiKey.Service, apiKey.ID)

	data := map[string]string{
		"key":    apiKey.Key,
		"secret": apiKey.Secret,
		"region": apiKey.Region,
	}

	metadata := map[string]string{
		"created_by": apiKey.CreatedBy,
		"purpose":    "api_key",
	}

	return sm.SetSecret(ctx, path, data, metadata)
}

// ProxyCredentials represents proxy connection credentials
type ProxyCredentials struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Type      string `json:"type"` // http, socks5, etc.
	CreatedBy string `json:"created_by"`
}

// APIKey represents an API key for external services
type APIKey struct {
	ID        string `json:"id"`
	Service   string `json:"service"` // aws, azure, gcp, etc.
	Key       string `json:"key"`
	Secret    string `json:"secret"`
	Region    string `json:"region"`
	CreatedBy string `json:"created_by"`
}

// VaultBackend implementation

// NewVaultBackend creates a new Vault backend
func NewVaultBackend(client VaultClient) *VaultBackend {
	return &VaultBackend{
		client: client,
	}
}

// GetSecret retrieves a secret from Vault
func (vb *VaultBackend) GetSecret(ctx context.Context, path string) (*Secret, error) {
	data, err := vb.client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from vault: %w", err)
	}

	// Convert Vault response to our Secret format
	secret := &Secret{
		Path: path,
		Data: make(map[string]string),
	}

	// Extract data from Vault response
	if dataMap, ok := data["data"].(map[string]interface{}); ok {
		for k, v := range dataMap {
			if str, ok := v.(string); ok {
				secret.Data[k] = str
			}
		}
	}

	// Extract metadata
	if metadata, ok := data["metadata"].(map[string]interface{}); ok {
		secret.Metadata = make(map[string]string)
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				secret.Metadata[k] = str
			}
		}
	}

	return secret, nil
}

// SetSecret stores a secret in Vault
func (vb *VaultBackend) SetSecret(ctx context.Context, path string, secret *Secret) error {
	data := map[string]interface{}{
		"data": secret.Data,
	}

	if secret.Metadata != nil {
		data["metadata"] = secret.Metadata
	}

	return vb.client.Write(path, data)
}

// DeleteSecret removes a secret from Vault
func (vb *VaultBackend) DeleteSecret(ctx context.Context, path string) error {
	return vb.client.Delete(path)
}

// ListSecrets lists secrets in Vault
func (vb *VaultBackend) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	return vb.client.List(prefix)
}

// MockBackend for testing
type MockBackend struct {
	secrets map[string]*Secret
}

// NewMockBackend creates a new mock backend for testing
func NewMockBackend() *MockBackend {
	return &MockBackend{
		secrets: make(map[string]*Secret),
	}
}

// GetSecret retrieves a secret from the mock backend
func (mb *MockBackend) GetSecret(ctx context.Context, path string) (*Secret, error) {
	secret, exists := mb.secrets[path]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", path)
	}
	return secret, nil
}

// SetSecret stores a secret in the mock backend
func (mb *MockBackend) SetSecret(ctx context.Context, path string, secret *Secret) error {
	mb.secrets[path] = secret
	return nil
}

// DeleteSecret removes a secret from the mock backend
func (mb *MockBackend) DeleteSecret(ctx context.Context, path string) error {
	delete(mb.secrets, path)
	return nil
}

// ListSecrets lists secrets in the mock backend
func (mb *MockBackend) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	var paths []string
	for path := range mb.secrets {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			paths = append(paths, path)
		}
	}
	return paths, nil
}
