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
	keyIds  map[string]*string
	clients map[string]*kms.KMS
	store   Store
}

// NewRKMSWithDynamoDB creates a new RKMS instance with DynamoDB used as its key/value store
func NewRKMSWithDynamoDB(kmsConfig KMSConfig, dynamoDBConfig DynamoDBConfig) (*RKMS, error) {
	store, err := NewDynamoDBStore(dynamoDBConfig)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	clients, err := getKMSClientsForRegions(kmsConfig.Regions)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	return &RKMS{kmsConfig.Regions, kmsConfig.KeyIds, clients, store}, nil
}

func getKMSClientsForRegions(regions []string) (map[string]*kms.KMS, error) {
	clients := make(map[string]*kms.KMS)

	for _, region := range regions {
		client, err := getKMSClientForRegion(region)
		if err != nil {
			return nil, err
		}
		clients[region] = client
	}

	return clients, nil
}

func getKMSClientForRegion(region string) (*kms.KMS, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		return nil, err
	}

	return kms.New(sess), nil
}

// GetKey retrieves the key assosicated with the given id.
// If a key is not found in the store, a key is generated for the given id.
func (r *RKMS) GetKey(id string) (*string, error) {
	value, err := r.store.GetValue(id)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	if value != nil { //a data key already exist for the given id
		//TODO: make parallelism configurable (e.g. request all KMS regions at the same time for the decrypted data key)
		for _, region := range r.regions {
			client := r.clients[region]
			result, err := client.Decrypt(&kms.DecryptInput{
				CiphertextBlob: []byte(value[region]),
			})

			if err != nil { //failed to decrypt in this region
				log.Print(err)
				continue
			}

			dataKey := string(result.Plaintext)
			return &dataKey, nil
		}
	}

	//need to create the data key
	//encrypt the data key in every region
	//save in dynamoDB
	//return the data key

	res := fmt.Sprintf("%+v\n", value)
	return &res, nil
}
