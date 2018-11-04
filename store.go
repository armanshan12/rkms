package main

// Store - abstract definition of a key/value store for KMS-related data
type Store interface {
	GetValue(id string) (map[string]string, error)
	SetValue(id string, encryptedKeysMap map[string]string) error
}
