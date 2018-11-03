package main

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// DynamoDBStore - a DynamoDB implementation of a key/value store for KMS-related data
type DynamoDBStore struct {
	region    string
	tableName string
	client    *dynamodb.DynamoDB
}

// NewDynamoDBStore creates a new DynamoDBStore instance
func NewDynamoDBStore(dynamoDBConfig DynamoDBConfig) (*DynamoDBStore, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(dynamoDBConfig.Region),
	})

	if err != nil {
		log.Print(err)
		return nil, err
	}

	client := dynamodb.New(sess)
	return &DynamoDBStore{dynamoDBConfig.Region, dynamoDBConfig.TableName, client}, nil
}

// GetValue retrieves the value for the given key
func (s *DynamoDBStore) GetValue(id string) ([]map[string]string, error) {
	input := &dynamodb.DescribeTableInput{TableName: &s.tableName}
	output, err := s.client.DescribeTable(input)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	log.Printf("Table's ARN is %s\n", *output.Table.TableArn)
	return nil, nil
}

// SetValue sets the value for the given key
func (s *DynamoDBStore) SetValue(key string, value []map[string]string) error {

	return nil
}
