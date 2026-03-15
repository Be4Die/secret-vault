package entity

import "time"

type Session struct {
	ID         string
	UserID     string
	IPAddress  string
	UserAgent  string
	LastUsedAt time.Time
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

func (s Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
