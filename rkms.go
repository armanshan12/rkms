package main

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	logger "github.com/sirupsen/logrus"
)

// MinimumKMSRegions is the minimum number of KMS regions needed to run a RKMS service
const MinimumKMSRegions = 3

// DataKeySizeInBytes is the length of the data encryption key in bytes
//TODO: make this configurable
const DataKeySizeInBytes int64 = 32

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
		logger.Print(err)
		return nil, err
	}

	clients, err := getKMSClientsForRegions(kmsConfig.Regions)
	if err != nil {
		logger.Print(err)
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
		logger.Print(err)
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
				logger.Print(err)
				continue
			}

			dataKey := string(result.Plaintext)
			return &dataKey, nil
		}

		return nil, fmt.Errorf("failed to decrypt data key in every region")
	}

	//create the data key
	firstRegion, plaintextDataKey, firstRegionCiphertext, err := r.createDataKey()
	if err != nil {
		logger.Errorf("failed to create a data key: %s", err)
		return nil, err
	}

	var encryptedDataKeys = make(map[string]string)
	encryptedDataKeys[*firstRegion] = *firstRegionCiphertext

	//encrypt the data key in every region
	for _, region := range r.regions {
		if strings.Compare(region, *firstRegion) == 0 { //we have already encrypted in this region and have the ciphertext
			continue
		}

		//TODO: parallelize encryptDataKey calls to every region
		ciphertext, err := r.encryptDataKey(plaintextDataKey, &region)
		if err != nil {
			logger.Errorf("failed to encrypt data key in %s region: %s", region, err)
			return nil, err
		}

		encryptedDataKeys[region] = *ciphertext
	}

	//save in dynamoDB
	err = r.store.SetValue(id, encryptedDataKeys)
	if err != nil {
		logger.Errorf("failed to save encrypted data keys in key/value store: %s", err)
		return nil, err
	}

	//return the data key
	return plaintextDataKey, nil
}

func (r *RKMS) createDataKey() (*string, *string, *string, error) {
	for _, region := range r.regions {
		client := r.clients[region]
		result, err := client.GenerateDataKey(&kms.GenerateDataKeyInput{
			KeyId:         r.keyIds[region],
			NumberOfBytes: aws.Int64(DataKeySizeInBytes),
		})

		if err != nil { //failed to create data key in this region
			logger.Print(err)
			continue
		}

		plaintext := string(result.Plaintext)
		ciphertext := string(result.CiphertextBlob)
		return &region, &plaintext, &ciphertext, nil
	}

	return nil, nil, nil, fmt.Errorf("failed to create a data key in every region")
}

func (r *RKMS) encryptDataKey(dataKey *string, region *string) (*string, error) {
	client := r.clients[*region]
	result, err := client.Encrypt(&kms.EncryptInput{
		KeyId:     r.keyIds[*region],
		Plaintext: []byte(*dataKey),
	})

	if err != nil { //failed to create data key in this region
		logger.Print(err)
		return nil, err
	}

	ciphertext := string(result.CiphertextBlob)
	return &ciphertext, nil
}
