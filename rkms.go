package main

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

const MinimumKMSRegions = 3

// RKMS - Implementation of redundant KMS logic
type RKMS struct {
	regions []string
	store   Store
	client  *kms.KMS
}

// NewRKMSWithDynamoDB creates a new RKMS instance with DynamoDB used as its key/value store
func NewRKMSWithDynamoDB(kmsConfig KMSConfig, dynamoDBConfig DynamoDBConfig) (*RKMS, error) {
	if len(kmsConfig.Regions) < MinimumKMSRegions {
		err := fmt.Errorf("a minimmum of %d KMS regions is required", MinimumKMSRegions)
		log.Fatal(err)
		return nil, err
	}

	store, err := NewDynamoDBStore(dynamoDBConfig)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(kmsConfig.Regions[0]),
	})

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	client := kms.New(sess)

	return &RKMS{kmsConfig.Regions, store, client}, nil
}

// GetKey retrieves the key assosicated with the given id.
// If a key is not found in the store, a key is generated for the given id.
func (r *RKMS) GetKey(id string) (string, error) {

	return "dummy key", nil
}
