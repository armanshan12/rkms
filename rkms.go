package main

// RKMS - Implementation of redundant KMS logic
type RKMS struct {
	regions []string
	store   Store
}

// NewRKMSWithDynamoDB creates a new RKMS instance with DynamoDB used as its key/value store
func NewRKMSWithDynamoDB(awsConfig AWSConfig, kmsConfig KMSConfig, dynamoDBConfig DynamoDBConfig) RKMS {
	return RKMS{kmsConfig.Regions, NewDynamoDBStore(awsConfig, dynamoDBConfig)}
}

// GetKey retrieves the key assosicated with the given id.
// If a key is not found in the store, a key is generated for the given id.
func (r *RKMS) GetKey(id string) (string, error) {

	return "dummy key", nil
}
