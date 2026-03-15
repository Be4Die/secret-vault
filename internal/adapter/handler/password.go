package handler

import (
	"net/http"
	"strconv"

	"secret-vault/internal/entity"
	"secret-vault/internal/usecase"
	"secret-vault/templates/components"
	"secret-vault/templates/pages"
)

type PasswordHandler struct {
	passwords *usecase.PasswordUseCase
}

func NewPasswordHandler(passwords *usecase.PasswordUseCase) *PasswordHandler {
	return &PasswordHandler{passwords: passwords}
}

func (h *PasswordHandler) ShowPage(w http.ResponseWriter, r *http.Request) {
	component := pages.PasswordGenerator("", "", entity.PasswordParams{
		Length:    32,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *PasswordHandler) Generate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	length, _ := strconv.Atoi(r.FormValue("length"))
	if length == 0 {
		length = 32
	}

	params := entity.PasswordParams{
		Length:    length,
		Uppercase: r.FormValue("uppercase") == "on",
		Lowercase: r.FormValue("lowercase") == "on",
		Digits:    r.FormValue("digits") == "on",
		Symbols:   r.FormValue("symbols") == "on",
	}

	password, err := h.passwords.Generate(params)
	if err != nil {
		component := components.PasswordResult("", err.Error(), params)
		_ = component.Render(r.Context(), w)
		return
	}

	component := components.PasswordResult(password, "", params)
	_ = component.Render(r.Context(), w)
}
