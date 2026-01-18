package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/frigidom1024/go-jwt-middleware/core"
)

// 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestUserData 测试用的用户数据结构
type TestUserData struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

// TestNewAuthMiddleware 测试创建中间件
func TestNewAuthMiddleware(t *testing.T) {
	secret := "test-secret"
	expiration := 24 * time.Hour

	middleware := core.NewAuthMiddleware[TestUserData](secret, expiration)

	if middleware == nil {
		t.Fatal("NewAuthMiddleware returned nil")
	}
}

// TestGenerateToken 测试生成 token
func TestGenerateToken(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
		Roles:    []string{"admin"},
	}

	t.Logf("Generating token for user: %+v", userData)

	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := middleware.GenerateToken(userData, expiresAt)

	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}

	if token == "" {
		t.Error("GenerateToken returned empty token")
	}

	t.Logf("Generated token: %s", token)
	t.Logf("Token expires at: %v", expiresAt)
}

// TestGenerateTokenWithDuration 测试使用时长生成 token
func TestGenerateTokenWithDuration(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
		Roles:    []string{"admin"},
	}

	duration := 2 * time.Hour
	token, err := middleware.GenerateTokenWithDuration(userData, duration)

	if err != nil {
		t.Fatalf("GenerateTokenWithDuration returned error: %v", err)
	}

	if token == "" {
		t.Error("GenerateTokenWithDuration returned empty token")
	}
}

// TestParseToken 测试解析 token
func TestParseToken(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
		Roles:    []string{"admin", "user"},
	}

	t.Logf("Original user data: UserID=%q, Username=%q, Roles=%v",
		userData.UserID, userData.Username, userData.Roles)

	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := middleware.GenerateToken(userData, expiresAt)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	t.Logf("Generated token: %s", token)

	// 将 middleware 转换为具体类型以访问 ParseToken 方法
	impl, ok := middleware.(*core.MiddlewareImpl[TestUserData])
	if !ok {
		t.Fatal("cannot convert middleware to *MiddlewareImpl[TestUserData]")
	}

	// 解析 token
	claims, err := impl.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken returned error: %v", err)
	}

	t.Logf("Parsed claims - ExpiresAt: %v", claims.ExpiresAt)

	// 验证解析出的数据
	retrievedData := claims.GetData()
	t.Logf("Retrieved data: UserID=%q, Username=%q, Roles=%v",
		retrievedData.UserID, retrievedData.Username, retrievedData.Roles)

	if retrievedData.UserID != userData.UserID {
		t.Errorf("expected UserID %q, got %q", userData.UserID, retrievedData.UserID)
	}

	if retrievedData.Username != userData.Username {
		t.Errorf("expected Username %q, got %q", userData.Username, retrievedData.Username)
	}

	if len(retrievedData.Roles) != len(userData.Roles) {
		t.Errorf("expected %d roles, got %d", len(userData.Roles), len(retrievedData.Roles))
	}

	// 验证 token 有效性
	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	} else {
		t.Logf("Token expiration time: %v", claims.ExpiresAt.Time)
	}
}

// TestParseTokenInvalid 测试解析无效 token
func TestParseTokenInvalid(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)
	impl := middleware.(*core.MiddlewareImpl[TestUserData])

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid token", "invalid.token.here"},
		{"wrong format", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIn0.signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := impl.ParseToken(tt.token)
			if err == nil {
				t.Error("expected error for invalid token, got nil")
			}
		})
	}
}

// TestAuthenticate 测试认证中间件
func TestAuthenticate(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	token, _ := middleware.GenerateToken(userData, expiresAt)

	t.Logf("Test token generated: %s", token)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		shouldHaveData bool
	}{
		{
			name:           "valid token",
			token:          token,
			expectedStatus: http.StatusOK,
			shouldHaveData: true,
		},
		{
			name:           "no token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			shouldHaveData: false,
		},
		{
			name:           "invalid token",
			token:          "invalid.token",
			expectedStatus: http.StatusUnauthorized,
			shouldHaveData: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running test case: %s", tt.name)
			if tt.token != "" {
				t.Logf("Using token: %s", tt.token)
			} else {
				t.Log("No token provided")
			}

			// 创建测试处理器
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 检查 context 中是否有用户数据
				data, ok := middleware.GetDataFromContext(r.Context())
				t.Logf("Handler: GetDataFromContext returned ok=%v, data=%+v", ok, data)

				if tt.shouldHaveData {
					if !ok {
						t.Error("expected data in context, got none")
					} else if data.UserID != "123" {
						t.Errorf("expected UserID 123, got %q", data.UserID)
					} else {
						t.Logf("Successfully retrieved user data from context: UserID=%q, Username=%q",
							data.UserID, data.Username)
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			// 包装中间件
			wrapped := middleware.Authenticate(handler)

			// 创建请求
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
				t.Logf("Request header: Authorization: Bearer %s", tt.token[:min(len(tt.token), 20)]+"...")
			}

			// 创建响应记录器
			rec := httptest.NewRecorder()

			// 执行请求
			wrapped.ServeHTTP(rec, req)

			t.Logf("Response status: %d, Body: %s", rec.Code, rec.Body.String())

			// 检查状态码
			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

// TestGetDataFromContext 测试从 context 获取数据
func TestGetDataFromContext(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	ctx := context.Background()
	t.Log("Test 1: Getting data from empty context")

	// 没有 data
	data, ok := middleware.GetDataFromContext(ctx)
	t.Logf("Result: ok=%v, data=%+v", ok, data)
	if ok {
		t.Error("expected ok=false, got true")
	}

	if data.UserID != "" || data.Username != "" {
		t.Error("expected empty data, got some data")
	}
	t.Log("Test 1 passed: empty context returns no data")

	// 有 data
	t.Log("\nTest 2: Getting data from context with data")
	testData := TestUserData{UserID: "123", Username: "test"}
	t.Logf("Setting context with data: %+v", testData)
	ctx = context.WithValue(ctx, core.DEFAULT_CTX_KEY, testData)
	data, ok = middleware.GetDataFromContext(ctx)
	t.Logf("Retrieved: ok=%v, data=%+v", ok, data)

	if !ok {
		t.Error("expected ok=true, got false")
	}

	if data.UserID != "123" {
		t.Errorf("expected UserID 123, got %q", data.UserID)
	}
	t.Log("Test 2 passed: successfully retrieved data from context")
}

// TestGenerateTokenExpiration 测试 token 过期时间设置
func TestGenerateTokenExpiration(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)
	impl := middleware.(*core.MiddlewareImpl[TestUserData])

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
	}

	t.Logf("Test data: %+v", userData)

	expiresAt := time.Now().Add(24 * time.Hour)
	t.Logf("Expected expiration: %v", expiresAt)

	token, _ := middleware.GenerateToken(userData, expiresAt)
	t.Logf("Generated token: %s", token)

	// 解析并验证过期时间
	claims, _ := impl.ParseToken(token)

	// 验证过期时间（允许 1 秒误差）
	if claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt not set")
	}

	t.Logf("Parsed expiration: %v", claims.ExpiresAt.Time)

	diff := claims.ExpiresAt.Time.Sub(expiresAt)
	if diff < 0 {
		diff = -diff
	}
	t.Logf("Time difference: %v", diff)

	if diff > time.Second {
		t.Errorf("expiration time mismatch: expected %v, got %v", expiresAt, claims.ExpiresAt.Time)
	} else {
		t.Log("Expiration time matches expected value (within 1 second tolerance)")
	}
}

// TestSetTokenExtractor 测试设置 token 提取器
func TestSetTokenExtractor(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)
	impl := middleware.(*core.MiddlewareImpl[TestUserData])

	t.Log("Getting initial token extractor")
	initialExtractor := impl.GetTokenExtractor()
	t.Logf("Initial extractor: %v (type: %T)", initialExtractor, initialExtractor)

	customExtractor := &core.BearerTokenExtractor{}
	t.Logf("Setting custom extractor: %T", customExtractor)
	impl.SetTokenExtractor(customExtractor)

	retrievedExtractor := impl.GetTokenExtractor()
	t.Logf("Retrieved extractor after setting: %T", retrievedExtractor)

	if retrievedExtractor != customExtractor {
		t.Errorf("SetTokenExtractor did not set the extractor correctly.\nExpected: %T\nGot: %T",
			customExtractor, retrievedExtractor)
	} else {
		t.Log("Successfully set and retrieved custom token extractor")
	}
}

// TestGetTokenExtractor 测试获取 token 提取器
func TestGetTokenExtractor(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)
	impl := middleware.(*core.MiddlewareImpl[TestUserData])

	t.Log("Getting default token extractor")
	extractor := impl.GetTokenExtractor()
	t.Logf("Extractor: %v (type: %T, name: %s)", extractor, extractor, extractor.Name())

	if extractor == nil {
		t.Error("GetTokenExtractor returned nil")
	} else {
		t.Logf("Default extractor name: %s", extractor.Name())
	}
}

// TestOptionalAuthenticate 测试可选认证中间件
func TestOptionalAuthenticate(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	token, _ := middleware.GenerateToken(userData, expiresAt)

	t.Logf("Test token generated: %s", token)

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		shouldHaveData bool
	}{
		{
			name:           "valid token",
			token:          token,
			expectedStatus: http.StatusOK,
			shouldHaveData: true,
		},
		{
			name:           "no token",
			token:          "",
			expectedStatus: http.StatusOK, // OptionalAuthenticate 应该放行
			shouldHaveData: false,
		},
		{
			name:           "invalid token",
			token:          "invalid.token",
			expectedStatus: http.StatusOK, // OptionalAuthenticate 应该放行
			shouldHaveData: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running test case: %s", tt.name)
			if tt.token != "" {
				t.Logf("Using token: %s", tt.token)
			} else {
				t.Log("No token provided")
			}

			// 创建测试处理器
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 检查 context 中是否有用户数据
				data, ok := middleware.GetDataFromContext(r.Context())
				t.Logf("Handler: GetDataFromContext returned ok=%v, data=%+v", ok, data)

				if tt.shouldHaveData {
					if !ok {
						t.Error("expected data in context, got none")
					} else if data.UserID != "123" {
						t.Errorf("expected UserID 123, got %q", data.UserID)
					} else {
						t.Logf("Successfully retrieved user data from context: UserID=%q, Username=%q",
							data.UserID, data.Username)
					}
				} else {
					if ok {
						t.Errorf("expected no data in context, but got: %+v", data)
					} else {
						t.Log("Correctly no data in context")
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			// 包装中间件
			wrapped := middleware.OptionalAuthenticate(handler)

			// 创建请求
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
				t.Logf("Request header: Authorization: Bearer %s", tt.token[:min(len(tt.token), 20)]+"...")
			}

			// 创建响应记录器
			rec := httptest.NewRecorder()

			// 执行请求
			wrapped.ServeHTTP(rec, req)

			t.Logf("Response status: %d, Body: %s", rec.Code, rec.Body.String())

			// 检查状态码
			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

// TestOptionalAuthenticateWithValidToken 测试可选认证中间件有有效token的情况
func TestOptionalAuthenticateWithValidToken(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	userData := TestUserData{
		UserID:   "123",
		Username: "testuser",
		Roles:    []string{"admin", "user"},
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	token, _ := middleware.GenerateToken(userData, expiresAt)

	t.Logf("Generated token: %s", token)

	// 创建测试处理器
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查 context 中是否有用户数据
		data, ok := middleware.GetDataFromContext(r.Context())

		if !ok {
			t.Error("expected data in context, got none")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if data.UserID != userData.UserID {
			t.Errorf("expected UserID %q, got %q", userData.UserID, data.UserID)
		}
		if data.Username != userData.Username {
			t.Errorf("expected Username %q, got %q", userData.Username, data.Username)
		}
		if len(data.Roles) != len(userData.Roles) {
			t.Errorf("expected %d roles, got %d", len(userData.Roles), len(data.Roles))
		}

		t.Logf("Successfully retrieved user data: UserID=%q, Username=%q, Roles=%v",
			data.UserID, data.Username, data.Roles)
		w.WriteHeader(http.StatusOK)
	})

	// 包装可选认证中间件
	wrapped := middleware.OptionalAuthenticate(handler)

	// 创建请求（带有效 token）
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	t.Logf("Response status: %d", rec.Code)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

// TestOptionalAuthenticateWithoutToken 测试可选认证中间件没有token的情况
func TestOptionalAuthenticateWithoutToken(t *testing.T) {
	middleware := core.NewAuthMiddleware[TestUserData]("secret", time.Hour)

	// 创建测试处理器
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查 context 中是否有用户数据（应该没有）
		data, ok := middleware.GetDataFromContext(r.Context())

		if ok {
			t.Errorf("expected no data in context, but got: %+v", data)
		}

		t.Log("Correctly no data in context, request passed through")
		w.WriteHeader(http.StatusOK)
	})

	// 包装可选认证中间件
	wrapped := middleware.OptionalAuthenticate(handler)

	// 创建请求（不带 token）
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	t.Logf("Response status: %d", rec.Code)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

