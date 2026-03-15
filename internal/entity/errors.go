package entity

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrSecretNotFound     = errors.New("secret not found")
	ErrAccessDenied       = errors.New("access denied")
	ErrCurrentSession     = errors.New("cannot terminate current session")
)
