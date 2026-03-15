package handler

import (
	"net/http"

	"secret-vault/templates/pages"
)

type PageHandler struct{}

func NewPageHandler() *PageHandler {
	return &PageHandler{}
}

func (h *PageHandler) Home(w http.ResponseWriter, r *http.Request) {
	component := pages.Home()
	if err := component.Render(r.Context(), w); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
