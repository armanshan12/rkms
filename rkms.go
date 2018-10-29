package main

// RKMS - Implementation of redundant KMS logic
type RKMS struct {
}

// GetKey retrieves the key assosicated with the given id.
// If a key is not found in the store, a key is generated for the given id.
func (r *RKMS) GetKey(id string) (string, error) {

	return "dummy key", nil
}
