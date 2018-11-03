package main

// Store - abstract definition of a key/value store for KMS-related data
type Store interface {
	GetValue(key string) ([]map[string]string, error)
	SetValue(key string, value []map[string]string) error
}
