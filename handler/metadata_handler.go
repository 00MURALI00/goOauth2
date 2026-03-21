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

	json.NewEncoder(w).Encode(meta)
}
