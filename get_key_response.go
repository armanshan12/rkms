package main

import (
	"encoding/json"
)

type getKeyResponse struct {
	Key *string `json:"key"`
}

// ConstructGetKeyResponse creates a server response for GET /key endpoint
func ConstructGetKeyResponse(key *string) []byte {
	resp := getKeyResponse{key}
	b, _ := json.Marshal(resp)
	return b
}
