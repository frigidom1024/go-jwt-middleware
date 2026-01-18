package authmiddle

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	DEFAULT_CTX_KEY = "claimsdata"
)

type AuthMiddleware[T any] interface {
	Authenticate(next http.Handler) http.Handler
	GenerateToken(data T, expiresAt time.Time) (string, error)
	GenerateTokenWithDuration(data T, duration time.Duration) (string, error)
	GetDataFromContext(ctx context.Context) (T, bool)
	SetTokenExtractor(extractor TokenExtractor)
	GetTokenExtractor() TokenExtractor
}

type MiddlewareImpl[T any] struct {
	jwtSecret      string
	expirationTime time.Duration
	tokenExtractor TokenExtractor
}

func NewAuthMiddleware[T any](jwtSecret string, expirationTime time.Duration) AuthMiddleware[T] {
	return &MiddlewareImpl[T]{
		jwtSecret:      jwtSecret,
		expirationTime: expirationTime,
		tokenExtractor: NewChainTokenExtractor(&BearerTokenExtractor{}),
	}
}

func (m *MiddlewareImpl[T]) SetTokenExtractor(extractor TokenExtractor) {

	m.tokenExtractor = extractor

}

func (m *MiddlewareImpl[T]) GetTokenExtractor() TokenExtractor {
	return m.tokenExtractor
}
func (m *MiddlewareImpl[T]) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := m.tokenExtractor.Extract(r)
		if err != nil {
			errstring := fmt.Sprintf("Error extracting token: %v", err)
			http.Error(w, errstring, http.StatusUnauthorized)
			return
		}
		claims, err := m.ParseToken(token)

		if err != nil {

			errstring := fmt.Sprintf("Error parsing token: %v", err)

			http.Error(w, errstring, http.StatusUnauthorized)

			return

		}
		// 检查context中是否已存在claims，避免覆盖
		ctx := r.Context()
		if existing := ctx.Value(DEFAULT_CTX_KEY); existing != nil {
			log.Printf("[WARNING] Context key %q already exists with value %v, overwriting with new claimsdata", DEFAULT_CTX_KEY, existing)
		}
		r = r.WithContext(context.WithValue(ctx, DEFAULT_CTX_KEY, claims.Data))

		next.ServeHTTP(w, r)
	})
}

func (m *MiddlewareImpl[T]) ParseToken(token string) (CustomClaims[T], error) {
	var claims CustomClaims[T]
	parsedToken, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.jwtSecret), nil
	})
	if err != nil {
		return CustomClaims[T]{}, err
	}
	if !parsedToken.Valid {
		return CustomClaims[T]{}, ErrInvalidToken
	}
	return claims, nil
}

func (m *MiddlewareImpl[T]) GenerateToken(data T, expiresAt time.Time) (string, error) {
	claims := CustomClaims[T]{

		Data: data,

		RegisteredClaims: jwt.RegisteredClaims{

			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.jwtSecret))
}

func (m *MiddlewareImpl[T]) GenerateTokenWithDuration(data T, duration time.Duration) (string, error) {

	expiresAt := time.Now().Add(duration)

	return m.GenerateToken(data, expiresAt)

}

func (m *MiddlewareImpl[T]) GetDataFromContext(ctx context.Context) (T, bool) {

	data, ok := ctx.Value(DEFAULT_CTX_KEY).(T)

	return data, ok

}
