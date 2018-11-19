package main

import (
	"encoding/json"
)

type getKeyResponse struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// ConstructGetKeyResponse creates a server response for GET /key endpoint
func ConstructGetKeyResponse(id string, key string) string {
	resp := getKeyResponse{id, key}
	b, _ := json.Marshal(resp)
	return string(b)
}
