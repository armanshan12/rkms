package main

// Store - abstract definition of a key/value store for KMS-related data
type Store interface {
	// GetEncryptedDataKeys retrieves the encrypted data keys for the given id
	GetEncryptedDataKeys(id string) (map[string]string, error)

	// SetEncryptedDataKeys sets the encrypted data keys for the given id
	SetEncryptedDataKeys(id string, keys map[string]string) error
}
