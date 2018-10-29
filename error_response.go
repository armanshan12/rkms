package main

import (
	"encoding/json"
)

type errorResponse struct {
	ErrorType    string `json:"error_type"`
	ErrorMessage string `json:"error_message"`
}

func ConstructErrorResponse(errorType string, errorMessage string) []byte {
	resp := errorResponse{errorType, errorMessage}
	b, _ := json.Marshal(resp)
	return b
}
