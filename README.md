# authmiddle

一个简洁且功能完善的 Go JWT 认证中间件，支持多种 Token 提取方式和灵活的认证策略。

## 功能特性

- **双认证模式**：支持必须认证（`Authenticate`）和可选认证（`OptionalAuthenticate`）
- **灵活的 Token 提取**：内置多种 Token 提取器，支持自定义提取器
- **链式提取**：支持按顺序尝试多个提取器，提高兼容性
- **类型安全的 Claims**：支持泛型函数获取自定义 Claims 类型
- **提取器注册表**：动态注册和管理 Token 提取器

## 安装

```bash
go get github.com/frigidom1024/go-jwt-middleware
```

## 快速开始

### 1. 定义用户数据结构

```go
type User struct {
    UserID   string   `json:"user_id"`
    Username string   `json:"username"`
    Roles    []string `json:"roles"`
}
```

### 2. 创建认证中间件

```go
import "github.com/frigidom1024/go-jwt-middleware/core"

// 创建泛型中间件，指定用户数据类型
auth := core.NewAuthMiddleware[User]("your-secret-key", 24*time.Hour)
```

### 3. 使用中间件

```go
// 必须认证 - 未认证返回 401
mux.Handle("/api/protected", auth.Authenticate(myHandler))

// 可选认证 - 未认证请求也会通过
mux.Handle("/api/public", auth.OptionalAuthenticate(myHandler))
```

### 4. 生成 Token

```go
user := User{
    UserID:   "123",
    Username: "john_doe",
    Roles:    []string{"admin", "user"},
}

// 方式一：指定过期时间
expiresAt := time.Now().Add(24 * time.Hour)
token, err := auth.GenerateToken(user, expiresAt)

// 方式二：指定持续时间（更方便）
token, err := auth.GenerateTokenWithDuration(user, 24*time.Hour)
```

### 5. 获取用户数据

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    // 从 Context 中获取用户数据
    user, ok := auth.GetDataFromContext(r.Context())
    if !ok {
        // 未认证
        return
    }

    userID := user.UserID
    username := user.Username
    // ...
}
```

## Token 提取器

### 内置提取器

| 提取器 | 说明 | 示例 |
|--------|------|------|
| `BearerTokenExtractor` | 标准 Bearer Token | `Authorization: Bearer <token>` |
| `DirectTokenExtractor` | 直接从 Authorization 获取 | `Authorization: <token>` |
| `QueryTokenExtractor` | 从 URL 查询参数获取 | `?token=<token>` |
| `HeaderTokenExtractor` | 自定义 Header | 可配置 Header 名称和前缀 |

### 使用内置提取器

```go
// 使用 Query 参数提取器
queryExtractor := &core.QueryTokenExtractor{ParamName: "access_token"}
auth.SetTokenExtractor(queryExtractor)

// 使用自定义 Header 提取器
headerExtractor := &core.HeaderTokenExtractor{
    HeaderName: "X-Auth-Token",
    Prefix:     "Token ",
}
auth.SetTokenExtractor(headerExtractor)
```

### 链式提取器

按顺序尝试多个提取器，任一成功即返回：

```go
auth.SetTokenExtractor(core.NewChainTokenExtractor(
    &core.BearerTokenExtractor{},
    &core.QueryTokenExtractor{ParamName: "token"},
    &core.HeaderTokenExtractor{HeaderName: "X-Access-Token"},
))
```

### 自定义提取器

实现 `TokenExtractor` 接口：

```go
type CustomExtractor struct{}

func (e *CustomExtractor) Extract(r *http.Request) (string, error) {
    // 从 Cookie 中获取 token
    cookie, err := r.Cookie("session_token")
    if err != nil {
        return "", core.ErrMissingToken
    }
    return cookie.Value, nil
}

func (e *CustomExtractor) Name() string {
    return "cookie"
}

// 使用自定义提取器
auth.SetTokenExtractor(&CustomExtractor{})
```

## Token 提取器注册表

管理多个 Token 提取器：

```go
registry := core.NewTokenExtractorRegistry()

// 注册提取器
registry.Register(&core.BearerTokenExtractor{})
registry.Register(&core.QueryTokenExtractor{})
registry.Register(&CustomExtractor{})

// 获取提取器
if extractor, ok := registry.Get("bearer"); ok {
    auth.SetTokenExtractor(extractor)
}

// 列出所有已注册的提取器
names := registry.List() // ["bearer", "query", "cookie"]

// 注销提取器
registry.Unregister("query")
```

### 使用默认注册表

```go
registry := core.GetDefaultRegistry()
// 默认已注册：BearerTokenExtractor, DirectTokenExtractor, QueryTokenExtractor
```

## 示例代码

项目提供了多个示例，展示如何使用 authmiddle 库：

### 运行示例

```bash
# 运行简单示例
go run examples/simple_example.go

# 运行完整示例服务器
go run examples/full_example.go
```

### 示例说明

#### simple_example.go
展示最基本的使用方法，包括：
- 创建认证中间件
- 生成 Token
- 保护路由
- 从 Context 获取用户数据

#### full_example.go
完整的 Web 服务器示例，包含：
- 登录接口（生成 Token）
- 受保护的路由（/profile、/dashboard）
- 角色权限检查
- JSON API 响应

### 测试示例服务器

```bash
# 1. 启动服务器
go run examples/full_example.go

# 2. 登录获取 token
curl -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"password"}'

# 3. 使用 token 访问受保护路由
curl http://localhost:8080/profile \
  -H 'Authorization: Bearer YOUR_TOKEN'

# 4. 访问仪表板
curl http://localhost:8080/dashboard \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

## API 参考

### AuthMiddleware 接口

| 方法 | 说明 |
|------|------|
| `Authenticate(next) http.Handler` | 必须认证中间件，未认证返回 401 |
| `OptionalAuthenticate(next) http.Handler` | 可选认证中间件，未认证也会通过 |
| `GenerateToken(claims, expiresAt) (string, error)` | 生成 JWT Token |

### Context 辅助函数

| 函数 | 说明 |
|------|------|
| `GetClaimsFromContext(ctx)` | 获取 `jwt.MapClaims` |
| `GetCustomClaimsFromContext[T](ctx)` | 获取自定义类型 Claims |
| `ContextWithClaims(ctx, claims)` | 将 Claims 设置到 Context |

### 错误

| 错误 | 说明 |
|------|------|
| `ErrInvalidToken` | Token 无效 |
| `ErrExpiredToken` | Token 已过期 |
| `ErrInvalidClaims` | Claims 无效 |
| `ErrMissingToken` | 缺少 Token |
| `ErrInvalidTokenFormat` | Token 格式错误 |

## 许可证

MIT License
