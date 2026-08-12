package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// writeJSON writes v as a JSON response body with the given status code.
// Every handler in this package uses this instead of calling
// json.NewEncoder directly, so the Content-Type header and error handling
// are consistent everywhere.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status code and headers are already written at this point,
		// so there's nothing left to do but log it — the client will just
		// see a truncated/incomplete body, which is an accurate reflection
		// of what actually happened.
		log.Printf("api: failed to write JSON response: %s", err)
	}
}

// errorResponse is the JSON shape every 4xx/5xx response from this
// package uses — one consistent {"error": "..."} shape, rather than a
// different ad-hoc shape per handler.
type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}
