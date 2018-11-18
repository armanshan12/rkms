package main

import (
	"context"
	"fmt"
)

// Store - abstract definition of a key/value store for KMS-related data
type Store interface {
	// GetEncryptedDataKeys retrieves the encrypted data keys for the given id
	GetEncryptedDataKeys(ctx context.Context, id string) (map[string]string, error)

	// SetEncryptedDataKeysConditionally sets the encrypted data keys for the given id
	// only if id does not exist in the store already.
	// If the id already exists, an IDAlreadyExistsStoreError error is returned.
	SetEncryptedDataKeysConditionally(ctx context.Context, id string, keys map[string]string) error
}

// IDAlreadyExistsStoreError represents an error type that SetEncryptedDataKeysConditionally
// returns when the id being written already exists in the store
type IDAlreadyExistsStoreError struct {
	ID string
}

func (e IDAlreadyExistsStoreError) Error() string {
	return fmt.Sprintf("id %q already exists in the store", e.ID)
}
