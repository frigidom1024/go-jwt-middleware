package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	authmiddle "github.com/frigidom1024/go-jwt-middleware/core"
)

// User 定义用户数据结构
type User struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse token 响应
type TokenResponse struct {
	Token      string `json:"token"`
	ExpiresAt  string `json:"expires_at"`
	Expiration string `json:"expiration"`
}

var (
	// 创建泛型中间件实例，使用 User 类型
	auth = authmiddle.NewAuthMiddleware[User]("your-secret-key", time.Hour*24)
)

func main() {
	// 设置 token 提取器（可选，默认使用链式提取器）
	auth.SetTokenExtractor(authmiddle.NewChainTokenExtractor(
		&authmiddle.BearerTokenExtractor{},
		&authmiddle.DirectTokenExtractor{},
	))

	// 设置路由
	mux := http.NewServeMux()

	// 公开路由 - 登录
	mux.HandleFunc("/login", loginHandler)

	// 受保护路由 - 需要认证
	mux.Handle("/profile", auth.Authenticate(http.HandlerFunc(profileHandler)))
	mux.Handle("/dashboard", auth.Authenticate(http.HandlerFunc(dashboardHandler)))

	// 启动服务器
	fmt.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

// loginHandler 处理登录请求
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 简单的用户验证（实际应用中应该查询数据库）
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// 创建用户数据
	user := User{
		UserID:   "12345",
		Username: req.Username,
		Email:    req.Username + "@example.com",
		Roles:    []string{"user", "admin"},
	}

	// 方式一：使用指定过期时间生成 token
	expiresAt := time.Now().Add(time.Hour * 24)
	token, err := auth.GenerateToken(user, expiresAt)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	// 方式二：使用持续时间生成 token（更方便）
	// token2, err := auth.GenerateTokenWithDuration(user, time.Hour*48)

	response := TokenResponse{
		Token:      token,
		ExpiresAt:  expiresAt.Format(time.RFC3339),
		Expiration: "24h",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// profileHandler 处理个人资料请求
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// 从 context 中获取用户数据
	user, ok := auth.GetDataFromContext(r.Context())
	if !ok {
		http.Error(w, "Failed to get user data", http.StatusInternalServerError)
		return
	}

	// 返回用户资料
	response := map[string]interface{}{
		"message": "Profile access granted",
		"user":    user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// dashboardHandler 处理仪表板请求
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// 从 context 中获取用户数据
	user, ok := auth.GetDataFromContext(r.Context())
	if !ok {
		http.Error(w, "Failed to get user data", http.StatusInternalServerError)
		return
	}

	// 检查角色
	hasAdmin := false
	for _, role := range user.Roles {
		if role == "admin" {
			hasAdmin = true
			break
		}
	}

	response := map[string]interface{}{
		"message":    "Dashboard access granted",
		"user":       user.Username,
		"is_admin":   hasAdmin,
		"roles":      user.Roles,
		"issued_at":  time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ==================== 测试函数 ====================

// testTokenGeneration 测试 token 生成
func testTokenGeneration() {
	fmt.Println("=== Testing Token Generation ===\n")

	// 创建测试用户
	user := User{
		UserID:   "test-123",
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user"},
	}

	// 方式一：使用过期时间生成 token
	expiresAt := time.Now().Add(time.Hour * 2)
	token1, err := auth.GenerateToken(user, expiresAt)
	if err != nil {
		log.Fatalf("GenerateToken failed: %v", err)
	}
	fmt.Printf("Token (with expiresAt): %s\n", token1)
	fmt.Printf("Expires at: %s\n\n", expiresAt.Format(time.RFC3339))

	// 方式二：使用持续时间生成 token
	token2, err := auth.GenerateTokenWithDuration(user, time.Hour*48)
	if err != nil {
		log.Fatalf("GenerateTokenWithDuration failed: %v", err)
	}
	fmt.Printf("Token (with duration): %s\n", token2)
	fmt.Printf("Duration: 48h\n\n")

	fmt.Println("=== Token Generation Test Completed ===\n")
}

// testContextData 测试 context 数据获取
func testContextData() {
	fmt.Println("=== Testing Context Data ===\n")

	// 创建测试用户
	user := User{
		UserID:   "ctx-123",
		Username: "contextuser",
		Email:    "context@example.com",
		Roles:    []string{"admin", "user"},
	}

	// 生成 token
	token, err := auth.GenerateTokenWithDuration(user, time.Hour)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	// 创建一个模拟的 context（实际中通过中间件设置）
	// 这里我们直接使用 token 获取用户数据
	fmt.Printf("Generated token: %s\n", token)
	fmt.Printf("User data: %+v\n", user)
	fmt.Printf("User ID: %s\n", user.UserID)
	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("Email: %s\n", user.Email)
	fmt.Printf("Roles: %v\n", user.Roles)

	fmt.Println("\n=== Context Data Test Completed ===\n")
}

// testDifferentUsers 测试不同用户的 token
func testDifferentUsers() {
	fmt.Println("=== Testing Different Users ===\n")

	users := []User{
		{
			UserID:   "user-001",
			Username: "alice",
			Email:    "alice@example.com",
			Roles:    []string{"user"},
		},
		{
			UserID:   "user-002",
			Username: "bob",
			Email:    "bob@example.com",
			Roles:    []string{"user", "moderator"},
		},
		{
			UserID:   "user-003",
			Username: "charlie",
			Email:    "charlie@example.com",
			Roles:    []string{"user", "admin"},
		},
	}

	for i, user := range users {
		token, err := auth.GenerateTokenWithDuration(user, time.Hour*24)
		if err != nil {
			log.Printf("Failed to generate token for user %s: %v", user.Username, err)
			continue
		}

		fmt.Printf("User %d:\n", i+1)
		fmt.Printf("  Username: %s\n", user.Username)
		fmt.Printf("  Roles: %v\n", user.Roles)
		fmt.Printf("  Token: %s...\n", token[:min(50, len(token))])
		fmt.Println()
	}

	fmt.Println("=== Different Users Test Completed ===\n")
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 使用说明
func printUsage() {
	fmt.Println("Usage Examples:")
	fmt.Println("\n1. Start the server:")
	fmt.Println("   go run examples/main.go")
	fmt.Println("\n2. Login to get token:")
	fmt.Println("   curl -X POST http://localhost:8080/login \\")
	fmt.Println("     -H 'Content-Type: application/json' \\")
	fmt.Println("     -d '{\"username\":\"test\",\"password\":\"password\"}'")
	fmt.Println("\n3. Access protected route with token:")
	fmt.Println("   curl http://localhost:8080/profile \\")
	fmt.Println("     -H 'Authorization: Bearer YOUR_TOKEN'")
	fmt.Println("\n4. Access dashboard:")
	fmt.Println("   curl http://localhost:8080/dashboard \\")
	fmt.Println("     -H 'Authorization: YOUR_TOKEN'")
	fmt.Println("\n5. Test without token (should fail):")
	fmt.Println("   curl http://localhost:8080/profile")
}
