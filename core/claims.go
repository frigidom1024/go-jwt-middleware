package authmiddle

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims[T any] struct {
	Data T
	jwt.RegisteredClaims
}

func (c *CustomClaims[T]) SetExpirationTime(t time.Time) {
	c.ExpiresAt = jwt.NewNumericDate(t)
}

func (c *CustomClaims[T]) GetData() T {
	return c.Data
}

func (c *CustomClaims[T]) SetData(data T) {
	c.Data = data
}

func GetClaims[T any](data T, expirationTime time.Time) (CustomClaims[T], error) {
	claims := CustomClaims[T]{
		Data: data,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return claims, nil
}

func GenerateToken[T any](data any, secret string, expirationTime time.Time) (string, error) {
	cc, err := GetClaims(data, expirationTime)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	return token.SignedString([]byte(secret))
}

func GetClaimsFromToken[T any](token *jwt.Token) (CustomClaims[T], error) {
	claims, ok := token.Claims.(*CustomClaims[T])
	if !ok {
		return CustomClaims[T]{}, ErrInvalidTokenFormat
	}
	return *claims, nil
}
