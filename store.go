package main

// Store - abstract definition of a key/value store for KMS-related data
type Store interface {
	// GetValue retrieves the value for the given key
	GetValue(id string) (map[string]string, error)

	// SetValue sets the value for the given key
	SetValue(id string, encryptedKeysMap map[string]string) error
}
