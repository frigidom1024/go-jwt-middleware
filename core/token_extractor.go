package authmiddle

import (
	"net/http"
	"strings"
	"sync"
)

// TokenExtractor 定义 token 提取器接口
type TokenExtractor interface {
	// Extract 从请求中提取 token
	Extract(r *http.Request) (string, error)
	// Name 返回提取器名称
	Name() string
}

// TokenExtractorRegistry token 提取器注册表
type TokenExtractorRegistry struct {
	extractors map[string]TokenExtractor
	mu         sync.RWMutex
}

// NewTokenExtractorRegistry 创建新的注册表
func NewTokenExtractorRegistry() *TokenExtractorRegistry {
	return &TokenExtractorRegistry{
		extractors: make(map[string]TokenExtractor),
	}
}

// Register 注册 token 提取器
func (registry *TokenExtractorRegistry) Register(extractor TokenExtractor) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.extractors[extractor.Name()] = extractor
}

// Unregister 注销 token 提取器
func (registry *TokenExtractorRegistry) Unregister(name string) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	delete(registry.extractors, name)
}

// Get 获取指定名称的提取器
func (registry *TokenExtractorRegistry) Get(name string) (TokenExtractor, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	extractor, ok := registry.extractors[name]
	return extractor, ok
}

// List 列出所有已注册的提取器名称
func (registry *TokenExtractorRegistry) List() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	names := make([]string, 0, len(registry.extractors))
	for name := range registry.extractors {
		names = append(names, name)
	}
	return names
}

// ==================== 内置提取器实现 ====================

// BearerTokenExtractor Bearer Token 提取器
type BearerTokenExtractor struct{}

func (e *BearerTokenExtractor) Extract(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrMissingToken
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", ErrInvalidTokenFormat
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", ErrInvalidTokenFormat
	}

	return token, nil
}

func (e *BearerTokenExtractor) Name() string {
	return "bearer"
}

// DirectTokenExtractor 直接 Token 提取器（兼容模式，不推荐）
type DirectTokenExtractor struct{}

func (e *DirectTokenExtractor) Extract(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrMissingToken
	}

	if authHeader == "" {
		return "", ErrMissingToken
	}

	return authHeader, nil
}

func (e *DirectTokenExtractor) Name() string {
	return "direct"
}

// QueryTokenExtractor 查询参数 Token 提取器
type QueryTokenExtractor struct {
	// ParamName 查询参数名称，默认为 "token"
	ParamName string
}

func (e *QueryTokenExtractor) Extract(r *http.Request) (string, error) {
	paramName := "token"
	if e.ParamName != "" {
		paramName = e.ParamName
	}

	token := r.URL.Query().Get(paramName)
	if token == "" {
		return "", ErrMissingToken
	}

	return token, nil
}

func (e *QueryTokenExtractor) Name() string {
	if e.ParamName != "" {
		return "query:" + e.ParamName
	}
	return "query"
}

// HeaderTokenExtractor 自定义 Header Token 提取器
type HeaderTokenExtractor struct {
	// HeaderName Header 名称，默认为 "Authorization"
	HeaderName string
	// Prefix Token 前缀（可选）
	Prefix string
}

func (e *HeaderTokenExtractor) Extract(r *http.Request) (string, error) {
	headerName := "Authorization"
	if e.HeaderName != "" {
		headerName = e.HeaderName
	}

	authHeader := r.Header.Get(headerName)
	if authHeader == "" {
		return "", ErrMissingToken
	}

	// 如果有前缀，去除前缀
	if e.Prefix != "" && strings.HasPrefix(authHeader, e.Prefix) {
		token := strings.TrimPrefix(authHeader, e.Prefix)
		if token == "" {
			return "", ErrInvalidTokenFormat
		}
		return token, nil
	}

	return authHeader, nil
}

func (e *HeaderTokenExtractor) Name() string {
	name := "header"
	if e.HeaderName != "" {
		name += ":" + e.HeaderName
	}
	if e.Prefix != "" {
		name += ":" + strings.TrimSuffix(e.Prefix, " ")
	}
	return name
}

// ChainTokenExtractor 链式提取器，依次尝试多个提取器
type ChainTokenExtractor struct {
	extractors []TokenExtractor
}

func NewChainTokenExtractor(extractors ...TokenExtractor) *ChainTokenExtractor {
	return &ChainTokenExtractor{
		extractors: extractors,
	}
}

func (e *ChainTokenExtractor) Extract(r *http.Request) (string, error) {
	for _, extractor := range e.extractors {
		token, err := extractor.Extract(r)
		if err == nil {
			return token, nil
		}
	}
	return "", ErrMissingToken
}

func (e *ChainTokenExtractor) Name() string {
	return "chain"
}

// ==================== 默认注册表 ====================

var defaultRegistry *TokenExtractorRegistry
var registryOnce sync.Once

// GetDefaultRegistry 获取默认注册表（单例）
func GetDefaultRegistry() *TokenExtractorRegistry {
	registryOnce.Do(func() {
		defaultRegistry = NewTokenExtractorRegistry()
		// 注册默认提取器
		defaultRegistry.Register(&BearerTokenExtractor{})
		defaultRegistry.Register(&DirectTokenExtractor{})
		defaultRegistry.Register(&QueryTokenExtractor{})
	})
	return defaultRegistry
}
