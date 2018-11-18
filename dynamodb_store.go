package main

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	logger "github.com/sirupsen/logrus"
)

// DynamoDBStore - a DynamoDB implementation of a key/value store for KMS-related data
type DynamoDBStore struct {
	region    string
	tableName *string
	client    *dynamodb.DynamoDB
}

type item struct {
	ID   string            `json:"id"`
	Keys map[string]string `json:"keys"`
}

// NewDynamoDBStore creates a new DynamoDBStore instance
func NewDynamoDBStore(dynamoDBConfig DynamoDBConfig) (*DynamoDBStore, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(dynamoDBConfig.Region),
	})

	if err != nil {
		logger.Print(err)
		return nil, err
	}

	client := dynamodb.New(sess)
	return &DynamoDBStore{dynamoDBConfig.Region, aws.String(dynamoDBConfig.TableName), client}, nil
}

// GetEncryptedDataKeys retrieves the encrypted data keys for the given id
func (s *DynamoDBStore) GetEncryptedDataKeys(ctx context.Context, id string) (map[string]string, error) {
	input := &dynamodb.GetItemInput{
		TableName: s.tableName,
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
		ConsistentRead: aws.Bool(true),
	}

	result, err := s.client.GetItemWithContext(ctx, input)
	if err != nil {
		logger.Print(err)
		return nil, err
	}

	if result.Item == nil {
		return nil, nil
	}

	item := item{}
	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		logger.Print(err)
		return nil, err
	}

	return item.Keys, nil
}

// SetEncryptedDataKeysConditionally sets the encrypted data keys for the given id
// only if id does not exist in the store already.
// If the id already exists, an error is returned.
func (s *DynamoDBStore) SetEncryptedDataKeysConditionally(ctx context.Context, id string, encryptedKeysMap map[string]string) error {
	item := item{ID: id, Keys: encryptedKeysMap}
	marshalledItem, err := dynamodbattribute.MarshalMap(item)

	conditionExpression := "attribute_not_exists(id)"

	input := &dynamodb.PutItemInput{
		TableName:           s.tableName,
		Item:                marshalledItem,
		ConditionExpression: aws.String(conditionExpression),
	}

	_, err = s.client.PutItemWithContext(ctx, input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
				return IDAlreadyExistsStoreError{ID: id}
			}
		}

		logger.Print(err)
		return err
	}

	return nil
}
