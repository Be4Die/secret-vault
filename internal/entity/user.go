package entity

import (
	"errors"
	"strings"
	"time"
)

type User struct {
	ID           string
	Username     string
	PasswordHash string
	KeySalt      []byte
	CreatedAt    time.Time
}

func (u User) Validate() error {
	if strings.TrimSpace(u.Username) == "" {
		return errors.New("username is required")
	}
	if len(u.Username) < 3 {
		return errors.New("username must be at least 3 characters")
	}
	if len(u.Username) > 32 {
		return errors.New("username must be at most 32 characters")
	}
	return nil
}
