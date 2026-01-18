package authmiddle

import "errors"

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("expired token")
	ErrInvalidClaims      = errors.New("invalid claims")
	ErrMissingToken       = errors.New("missing token")
	ErrInvalidTokenFormat = errors.New("invalid token format")
)
