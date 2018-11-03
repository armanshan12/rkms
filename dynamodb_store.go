package main

// DynamoDBStore - a DynamoDB implementation of a key/value store for KMS-related data
type DynamoDBStore struct {
	region    string
	tableName string
}

// NewDynamoDBStore creates a new DynamoDBStore instance
func NewDynamoDBStore(awsConfig AWSConfig, dynamoDBConfig DynamoDBConfig) *DynamoDBStore {
	return &DynamoDBStore{dynamoDBConfig.Region, dynamoDBConfig.TableName}
}

// GetValue retrieves the value for the given key
func (s *DynamoDBStore) GetValue(id string) ([]map[string]string, error) {

	return nil, nil
}

// SetValue sets the value for the given key
func (s *DynamoDBStore) SetValue(key string, value []map[string]string) error {

	return nil
}
