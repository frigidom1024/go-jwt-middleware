package test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	auth "github.com/frigidom1024/go-jwt-middleware/core"
)

// TestBearerTokenExtractor 测试 Bearer Token 提取器
func TestBearerTokenExtractor(t *testing.T) {
	extractor := &auth.BearerTokenExtractor{}

	tests := []struct {
		name        string
		setupReq    func(*http.Request)
		expectToken string
		expectErr   error
	}{
		{
			name: "valid Bearer token",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-token-123")
			},
			expectToken: "test-token-123",
			expectErr:   nil,
		},
		{
			name: "missing Authorization header",
			setupReq: func(r *http.Request) {
				// 不设置 header
			},
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
		{
			name: "invalid format - no Bearer prefix",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "test-token-123")
			},
			expectToken: "",
			expectErr:   auth.ErrInvalidTokenFormat,
		},
		{
			name: "invalid format - empty token after Bearer",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer ")
			},
			expectToken: "",
			expectErr:   auth.ErrInvalidTokenFormat,
		},
		{
			name: "valid - lowercase bearer (should fail)",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "bearer test-token")
			},
			expectToken: "",
			expectErr:   auth.ErrInvalidTokenFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupReq(req)

			token, err := extractor.Extract(req)

			if err != tt.expectErr {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}

			if token != tt.expectToken {
				t.Errorf("expected token %q, got %q", tt.expectToken, token)
			}
		})
	}

	// 测试 Name 方法
	if extractor.Name() != "bearer" {
		t.Errorf("expected name 'bearer', got %q", extractor.Name())
	}
}

// TestDirectTokenExtractor 测试直接 Token 提取器
func TestDirectTokenExtractor(t *testing.T) {
	extractor := &auth.DirectTokenExtractor{}

	tests := []struct {
		name        string
		setupReq    func(*http.Request)
		expectToken string
		expectErr   error
	}{
		{
			name: "valid direct token",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "test-token-123")
			},
			expectToken: "test-token-123",
			expectErr:   nil,
		},
		{
			name: "missing Authorization header",
			setupReq: func(r *http.Request) {
				// 不设置 header
			},
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
		{
			name: "Bearer format (will return full string)",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-token")
			},
			expectToken: "Bearer test-token",
			expectErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupReq(req)

			token, err := extractor.Extract(req)

			if err != tt.expectErr {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}

			if token != tt.expectToken {
				t.Errorf("expected token %q, got %q", tt.expectToken, token)
			}
		})
	}

	// 测试 Name 方法
	if extractor.Name() != "direct" {
		t.Errorf("expected name 'direct', got %q", extractor.Name())
	}
}

// TestQueryTokenExtractor 测试查询参数 Token 提取器
func TestQueryTokenExtractor(t *testing.T) {
	tests := []struct {
		name        string
		extractor   *auth.QueryTokenExtractor
		setupURL    string
		expectToken string
		expectErr   error
	}{
		{
			name:        "default param name - valid token",
			extractor:   &auth.QueryTokenExtractor{},
			setupURL:    "/test?token=test-token-123",
			expectToken: "test-token-123",
			expectErr:   nil,
		},
		{
			name:        "custom param name - valid token",
			extractor:   &auth.QueryTokenExtractor{ParamName: "access_token"},
			setupURL:    "/test?access_token=test-token-456",
			expectToken: "test-token-456",
			expectErr:   nil,
		},
		{
			name:        "missing token parameter",
			extractor:   &auth.QueryTokenExtractor{},
			setupURL:    "/test?other=value",
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
		{
			name:        "empty token parameter",
			extractor:   &auth.QueryTokenExtractor{},
			setupURL:    "/test?token=",
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
		{
			name:        "no query parameters",
			extractor:   &auth.QueryTokenExtractor{},
			setupURL:    "/test",
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.setupURL, nil)

			token, err := tt.extractor.Extract(req)

			if err != tt.expectErr {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}

			if token != tt.expectToken {
				t.Errorf("expected token %q, got %q", tt.expectToken, token)
			}
		})
	}

	// 测试 Name 方法
	t.Run("Name method", func(t *testing.T) {
		extractor := &auth.QueryTokenExtractor{}
		if extractor.Name() != "query" {
			t.Errorf("expected name 'query', got %q", extractor.Name())
		}

		extractor = &auth.QueryTokenExtractor{ParamName: "access_token"}
		expectedName := "query:access_token"
		if extractor.Name() != expectedName {
			t.Errorf("expected name %q, got %q", expectedName, extractor.Name())
		}
	})
}

// TestHeaderTokenExtractor 测试自定义 Header Token 提取器
func TestHeaderTokenExtractor(t *testing.T) {
	tests := []struct {
		name        string
		extractor   *auth.HeaderTokenExtractor
		setupReq    func(*http.Request)
		expectToken string
		expectErr   error
	}{
		{
			name:      "default Authorization header",
			extractor: &auth.HeaderTokenExtractor{},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "test-token-123")
			},
			expectToken: "test-token-123",
			expectErr:   nil,
		},
		{
			name:      "custom header name",
			extractor: &auth.HeaderTokenExtractor{HeaderName: "X-Auth-Token"},
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Auth-Token", "test-token-456")
			},
			expectToken: "test-token-456",
			expectErr:   nil,
		},
		{
			name: "with prefix",
			extractor: &auth.HeaderTokenExtractor{
				HeaderName: "Authorization",
				Prefix:     "Token ",
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Token test-token-789")
			},
			expectToken: "test-token-789",
			expectErr:   nil,
		},
		{
			name: "with prefix but no match",
			extractor: &auth.HeaderTokenExtractor{
				HeaderName: "Authorization",
				Prefix:     "Token ",
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-token")
			},
			expectToken: "Bearer test-token",
			expectErr:   nil,
		},
		{
			name: "with prefix but empty token",
			extractor: &auth.HeaderTokenExtractor{
				HeaderName: "Authorization",
				Prefix:     "Token ",
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Token ")
			},
			expectToken: "",
			expectErr:   auth.ErrInvalidTokenFormat,
		},
		{
			name:      "missing header",
			extractor: &auth.HeaderTokenExtractor{},
			setupReq: func(r *http.Request) {
				// 不设置 header
			},
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupReq(req)

			token, err := tt.extractor.Extract(req)

			if err != tt.expectErr {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}

			if token != tt.expectToken {
				t.Errorf("expected token %q, got %q", tt.expectToken, token)
			}
		})
	}

	// 测试 Name 方法
	t.Run("Name method", func(t *testing.T) {
		extractor := &auth.HeaderTokenExtractor{}
		if extractor.Name() != "header" {
			t.Errorf("expected name 'header', got %q", extractor.Name())
		}

		extractor = &auth.HeaderTokenExtractor{HeaderName: "X-Auth-Token"}
		if extractor.Name() != "header:X-Auth-Token" {
			t.Errorf("expected name 'header:X-Auth-Token', got %q", extractor.Name())
		}

		extractor = &auth.HeaderTokenExtractor{
			HeaderName: "Authorization",
			Prefix:     "Token ",
		}
		if extractor.Name() != "header:Authorization:Token" {
			t.Errorf("expected name 'header:Authorization:Token', got %q", extractor.Name())
		}
	})
}

// TestChainTokenExtractor 测试链式 Token 提取器
func TestChainTokenExtractor(t *testing.T) {
	bearerExtractor := &auth.BearerTokenExtractor{}
	directExtractor := &auth.DirectTokenExtractor{}
	queryExtractor := &auth.QueryTokenExtractor{}

	chain := auth.NewChainTokenExtractor(
		bearerExtractor,
		directExtractor,
		queryExtractor,
	)

	tests := []struct {
		name        string
		setupReq    func(*http.Request)
		expectToken string
		expectErr   error
	}{
		{
			name: "Bearer token succeeds first",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-bearer")
			},
			expectToken: "test-bearer",
			expectErr:   nil,
		},
		{
			name: "Direct token succeeds on second try",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "test-direct")
			},
			expectToken: "test-direct",
			expectErr:   nil,
		},
		{
			name: "Query token succeeds on third try",
			setupReq: func(r *http.Request) {
				// 添加查询参数
				query := url.Values{}
				query.Add("token", "test-query")
				r.URL.RawQuery = query.Encode()
			},
			expectToken: "test-query",
			expectErr:   nil,
		},
		{
			name: "All extractors fail",
			setupReq: func(r *http.Request) {
				// 不设置任何 token
			},
			expectToken: "",
			expectErr:   auth.ErrMissingToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupReq(req)

			token, err := chain.Extract(req)

			if err != tt.expectErr {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}

			if token != tt.expectToken {
				t.Errorf("expected token %q, got %q", tt.expectToken, token)
			}
		})
	}

	// 测试 Name 方法
	if chain.Name() != "chain" {
		t.Errorf("expected name 'chain', got %q", chain.Name())
	}

	// 测试空链
	t.Run("empty chain", func(t *testing.T) {
		emptyChain := auth.NewChainTokenExtractor()
		req := httptest.NewRequest("GET", "/test", nil)

		_, err := emptyChain.Extract(req)
		if err != auth.ErrMissingToken {
			t.Errorf("expected error %v, got %v", auth.ErrMissingToken, err)
		}
	})
}

// TestTokenExtractorRegistry 测试 Token 提取器注册表
func TestTokenExtractorRegistry(t *testing.T) {
	registry := auth.NewTokenExtractorRegistry()

	bearerExtractor := &auth.BearerTokenExtractor{}
	queryExtractor := &auth.QueryTokenExtractor{ParamName: "access_token"}

	// 测试 Register
	t.Run("Register", func(t *testing.T) {
		registry.Register(bearerExtractor)
		registry.Register(queryExtractor)

		// 验证注册成功
		if extractor, ok := registry.Get("bearer"); !ok || extractor != bearerExtractor {
			t.Error("failed to register bearer extractor")
		}

		if extractor, ok := registry.Get("query:access_token"); !ok || extractor != queryExtractor {
			t.Error("failed to register query extractor")
		}
	})

	// 测试 Get
	t.Run("Get", func(t *testing.T) {
		// 存在的提取器
		extractor, ok := registry.Get("bearer")
		if !ok {
			t.Error("expected ok=true for existing extractor")
		}
		if extractor != bearerExtractor {
			t.Error("got wrong extractor")
		}

		// 不存在的提取器
		_, ok = registry.Get("nonexistent")
		if ok {
			t.Error("expected ok=false for non-existent extractor")
		}
	})

	// 测试 List
	t.Run("List", func(t *testing.T) {
		names := registry.List()

		// 应该包含至少 2 个提取器
		if len(names) < 2 {
			t.Errorf("expected at least 2 extractors, got %d", len(names))
		}

		// 检查是否包含我们注册的提取器
		hasBearer := false
		hasQuery := false
		for _, name := range names {
			if name == "bearer" {
				hasBearer = true
			}
			if name == "query:access_token" {
				hasQuery = true
			}
		}

		if !hasBearer {
			t.Error("list doesn't contain 'bearer' extractor")
		}
		if !hasQuery {
			t.Error("list doesn't contain 'query:access_token' extractor")
		}
	})

	// 测试 Unregister
	t.Run("Unregister", func(t *testing.T) {
		registry.Unregister("bearer")

		// 验证已注销
		_, ok := registry.Get("bearer")
		if ok {
			t.Error("extractor should be unregistered")
		}

		// 验证列表更新
		names := registry.List()
		for _, name := range names {
			if name == "bearer" {
				t.Error("unregistered extractor still in list")
			}
		}
	})
}

// TestGetDefaultRegistry 测试默认注册表
func TestGetDefaultRegistry(t *testing.T) {
	// 第一次调用
	registry := auth.GetDefaultRegistry()
	if registry == nil {
		t.Fatal("GetDefaultRegistry returned nil")
	}

	// 第二次调用应该返回同一个实例（单例）
	registry2 := auth.GetDefaultRegistry()
	if registry != registry2 {
		t.Error("GetDefaultRegistry should return the same instance")
	}

	// 验证默认提取器已注册
	names := registry.List()
	if len(names) < 3 {
		t.Errorf("expected at least 3 default extractors, got %d", len(names))
	}

	// 检查默认提取器
	defaultExtractors := []string{"bearer", "direct", "query"}
	for _, name := range defaultExtractors {
		found := false
		for _, registeredName := range names {
			if registeredName == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default extractor %q not registered", name)
		}
	}
}

// TestErrorVariables 测试错误变量
func TestErrorVariables(t *testing.T) {
	errors := []struct {
		name  string
		value error
	}{
		{"ErrInvalidToken", auth.ErrInvalidToken},
		{"ErrExpiredToken", auth.ErrExpiredToken},
		{"ErrInvalidClaims", auth.ErrInvalidClaims},
		{"ErrMissingToken", auth.ErrMissingToken},
		{"ErrInvalidTokenFormat", auth.ErrInvalidTokenFormat},
	}

	for _, tt := range errors {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == nil {
				t.Errorf("error variable %q should not be nil", tt.name)
			}
		})
	}
}
