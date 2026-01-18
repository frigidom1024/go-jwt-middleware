package main

import (
	"fmt"
	"net/http"
	"time"

	authmiddle "github.com/frigidom1024/go-jwt-middleware/core"
)

// 定义用户数据结构
type UserData struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func main() {
	// 步骤 1: 创建认证中间件实例
	// 泛型参数 [UserData] 指定要存储在 token 中的数据类型
	auth := authmiddle.NewAuthMiddleware[UserData](
		"my-secret-key",     // JWT 密钥
		time.Hour*24,         // 默认过期时间 24 小时
	)

	// 步骤 2: 配置 token 提取器（可选）
	auth.SetTokenExtractor(authmiddle.NewChainTokenExtractor(
		&authmiddle.BearerTokenExtractor{},
		&authmiddle.DirectTokenExtractor{},
	))

	// 步骤 3: 创建用户数据
	user := UserData{
		UserID:   "123",
		Username: "john_doe",
		Role:     "admin",
	}

	// 步骤 4: 生成 token
	fmt.Println("=== Token Generation ===\n")

	// 方式一：使用持续时间生成 token
	token1, err := auth.GenerateTokenWithDuration(user, time.Hour*2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Token (2 hours): %s\n\n", token1)

	// 方式二：使用具体过期时间生成 token
	expiresAt := time.Now().Add(time.Hour * 48)
	token2, err := auth.GenerateToken(user, expiresAt)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Token (48 hours): %s\n\n", token2)

	// 步骤 5: 使用中间件保护路由
	mux := http.NewServeMux()

	// 公开路由
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// 模拟登录，返回 token
		token, _ := auth.GenerateTokenWithDuration(user, time.Hour*24)
		w.Write([]byte(token))
	})

	// 受保护路由 - 使用 Authenticate 中间件
	mux.Handle("/protected", auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 从 context 中获取用户数据
		data, ok := auth.GetDataFromContext(r.Context())
		if ok {
			fmt.Fprintf(w, "Hello, %s! Your role is: %s\n", data.Username, data.Role)
		} else {
			w.Write([]byte("Failed to get user data"))
		}
	})))

	// 步骤 6: 启动服务器
	fmt.Println("Server starting on :8080...")
	fmt.Println("Try:")
	fmt.Println("  GET /login       - Get a token")
	fmt.Println("  GET /protected   - Access protected route (requires token)")
	http.ListenAndServe(":8080", mux)
}

// ==================== 更多示例 ====================

// 示例：不同角色的用户
func exampleWithDifferentRoles() {
	auth := authmiddle.NewAuthMiddleware[UserData]("secret", time.Hour*24)

	// 普通用户
	normalUser := UserData{UserID: "1", Username: "alice", Role: "user"}
	token, _ := auth.GenerateTokenWithDuration(normalUser, time.Hour*12)
	fmt.Printf("Normal user token: %s\n", token)

	// 管理员
	admin := UserData{UserID: "2", Username: "bob", Role: "admin"}
	token, _ = auth.GenerateTokenWithDuration(admin, time.Hour*24)
	fmt.Printf("Admin user token: %s\n", token)
}

// 示例：自定义数据结构
func exampleWithCustomData() {
	// 定义更复杂的用户数据
	type ExtendedUserData struct {
		UserID    string   `json:"user_id"`
		Username  string   `json:"username"`
		Email     string   `json:"email"`
		Roles     []string `json:"roles"`
		LoginIP   string   `json:"login_ip"`
		UserAgent string   `json:"user_agent"`
	}

	auth := authmiddle.NewAuthMiddleware[ExtendedUserData]("secret", time.Hour*24)

	user := ExtendedUserData{
		UserID:    "123",
		Username:  "charlie",
		Email:     "charlie@example.com",
		Roles:     []string{"user", "editor"},
		LoginIP:   "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	token, _ := auth.GenerateTokenWithDuration(user, time.Hour*8)
	fmt.Printf("Extended user token: %s\n", token)
}

// 示例：API 网关场景
func exampleAPIGateway() {
	// 定义 API 密钥数据
	type APIKey struct {
		KeyID      string `json:"key_id"`
		ServiceName string `json:"service_name"`
		Quota      int    `json:"quota"`
	}

	auth := authmiddle.NewAuthMiddleware[APIKey]("gateway-secret", time.Hour*24)

	apiKey := APIKey{
		KeyID:       "ak_123456",
		ServiceName: "payment-service",
		Quota:       10000,
	}

	token, _ := auth.GenerateTokenWithDuration(apiKey, time.Hour*1)
	fmt.Printf("API Gateway token: %s\n", token)
}
