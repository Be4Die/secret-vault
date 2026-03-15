package handler

import (
	"net/http"

	"secret-vault/templates/pages"
)

type HomeHandler struct{}

func NewHomeHandler() *HomeHandler {
	return &HomeHandler{}
}

func (h *HomeHandler) Show(w http.ResponseWriter, r *http.Request) {
	component := pages.Home()
	_ = component.Render(r.Context(), w)
}
