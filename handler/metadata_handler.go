package handler

import (
	"encoding/json"
	"net/http"

	"github.com/00MURALI00/goOauth2/service"
)

type MetadataHandler struct {
	metadataService *service.ProviderMetadataService
}

func NewMetadataHandler(
	metadataService *service.ProviderMetadataService,
) *MetadataHandler {

	return &MetadataHandler{
		metadataService: metadataService,
	}
}

func (h *MetadataHandler) Handle(
	w http.ResponseWriter,
	r *http.Request,
) {

	meta := h.metadataService.GetMetadata()

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(meta); err != nil {
    http.Error(w, "Failed to encode response", http.StatusInternalServerError)
    return
}
}
