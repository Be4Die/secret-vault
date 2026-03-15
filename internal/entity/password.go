package entity

import "errors"

var (
	ErrPasswordLengthTooShort = errors.New("password length must be at least 4")
	ErrPasswordLengthTooLong  = errors.New("password length must be at most 128")
	ErrPasswordNoCharsets     = errors.New("at least one character set must be selected")
)

type PasswordParams struct {
	Length    int
	Uppercase bool
	Lowercase bool
	Digits    bool
	Symbols   bool
}

func (p PasswordParams) Validate() error {
	if p.Length < 4 {
		return ErrPasswordLengthTooShort
	}
	if p.Length > 128 {
		return ErrPasswordLengthTooLong
	}
	if !p.Uppercase && !p.Lowercase && !p.Digits && !p.Symbols {
		return ErrPasswordNoCharsets
	}
	return nil
}
