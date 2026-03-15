package entity

import (
	"errors"
	"strings"
	"time"
)

type SecretType string

const (
	SecretTypeCredential SecretType = "credential"
	SecretTypeToken      SecretType = "token"
)

type Secret struct {
	ID               string
	UserID           string
	SecretType       SecretType
	EncryptedPayload []byte
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CredentialPayload struct {
	Title    string `json:"title"`
	Login    string `json:"login"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
	Note     string `json:"note,omitempty"`
}

func (p CredentialPayload) Validate() error {
	if strings.TrimSpace(p.Title) == "" {
		return errors.New("title is required")
	}
	if len(p.Title) > 128 {
		return errors.New("title must be at most 128 characters")
	}
	if strings.TrimSpace(p.Login) == "" {
		return errors.New("login is required")
	}
	if len(p.Login) > 256 {
		return errors.New("login must be at most 256 characters")
	}
	if strings.TrimSpace(p.Password) == "" {
		return errors.New("password is required")
	}
	if len(p.Password) > 1024 {
		return errors.New("password must be at most 1024 characters")
	}
	if len(p.URL) > 2048 {
		return errors.New("URL must be at most 2048 characters")
	}
	if len(p.Note) > 4096 {
		return errors.New("note must be at most 4096 characters")
	}
	return nil
}

type TokenPayload struct {
	Title string `json:"title"`
	Token string `json:"token"`
	URL   string `json:"url,omitempty"`
	Note  string `json:"note,omitempty"`
}

func (p TokenPayload) Validate() error {
	if strings.TrimSpace(p.Title) == "" {
		return errors.New("title is required")
	}
	if len(p.Title) > 128 {
		return errors.New("title must be at most 128 characters")
	}
	if strings.TrimSpace(p.Token) == "" {
		return errors.New("token is required")
	}
	if len(p.Token) > 4096 {
		return errors.New("token must be at most 4096 characters")
	}
	if len(p.URL) > 2048 {
		return errors.New("URL must be at most 2048 characters")
	}
	if len(p.Note) > 4096 {
		return errors.New("note must be at most 4096 characters")
	}
	return nil
}
