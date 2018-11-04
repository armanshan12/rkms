package main

import (
	"encoding/json"
)

type errorResponse struct {
	ErrorType    string `json:"error_type"`
	ErrorMessage string `json:"error_message"`
}

// ConstructErrorResponse creates a server response for the given error
func ConstructErrorResponse(errorType string, errorMessage string) []byte {
	resp := errorResponse{errorType, errorMessage}
	b, _ := json.Marshal(resp)
	return b
}
