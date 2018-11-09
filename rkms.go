package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
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
	clients map[string]kmsiface.KMSAPI
	store   Store
}

// NewRKMSWithDynamoDB creates a new RKMS instance with DynamoDB used as its key/value store
func NewRKMSWithDynamoDB(kmsConfig KMSConfig, dynamoDBConfig DynamoDBConfig) (*RKMS, error) {
	store, err := NewDynamoDBStore(dynamoDBConfig)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	clients, err := getKMSClientsForRegions(kmsConfig.Regions)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	return &RKMS{kmsConfig.Regions, kmsConfig.KeyIds, clients, store}, nil
}

func getKMSClientsForRegions(regions []string) (map[string]kmsiface.KMSAPI, error) {
	clients := make(map[string]kmsiface.KMSAPI)

	for _, region := range regions {
		client, err := getKMSClientForRegion(region)
		if err != nil {
			return nil, err
		}
		clients[region] = client
	}

	return clients, nil
}

func getKMSClientForRegion(region string) (kmsiface.KMSAPI, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		return nil, err
	}

	return kms.New(sess), nil
}

// GetPlaintextDataKey retrieves the key assosicated with the given id.
// If a key is not found in the store, a key is generated for the given id.
func (r *RKMS) GetPlaintextDataKey(id string) (*string, error) {
	plaintextDataKey, err := r.lookInStoreForDataKey(id)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if plaintextDataKey != nil {
		logger.Debugln("a data key was found in the store for the given id")
		return plaintextDataKey, nil
	}

	plaintextDataKey, err = r.createDataKeyForID(id)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	//return the data key
	return plaintextDataKey, nil
}

func (r *RKMS) lookInStoreForDataKey(id string) (*string, error) {
	encryptedDataKeys, err := r.store.GetEncryptedDataKeys(id)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if encryptedDataKeys == nil {
		logger.Debugln("no data key exists in the store for the given id")
		return nil, nil
	}

	plaintextDataKey, err := r.decryptDataKey(encryptedDataKeys)
	if err != nil {
		err := fmt.Errorf("failed to decrypt data key in every region: %s", err)
		logger.Error(err)
		return nil, err
	}

	return plaintextDataKey, err
}

func (r *RKMS) createDataKeyForID(id string) (*string, error) {
	logger.Debugln("creating data key...")
	firstRegion, plaintextDataKey, firstRegionCiphertext, err := r.createDataKey()
	if err != nil {
		logger.Errorf("failed to create a data key: %s", err)
		return nil, err
	}

	encryptedDataKeys := make(map[string]string)
	encryptedDataKeys[*firstRegion] = *firstRegionCiphertext

	logger.Debugln("encrypting generated data key in every region...")
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

	logger.Debugln("saving encrypted data keys in store...")
	err = r.store.SetEncryptedDataKeys(id, encryptedDataKeys)
	if err != nil {
		logger.Errorf("failed to save encrypted data keys in key/value store: %s", err)
		return nil, err
	}

	logger.Debugln("done creating and saving encrypted data keys")
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
			logger.Error(err)
			continue
		}

		plaintext := base64.StdEncoding.EncodeToString(result.Plaintext)
		ciphertext := base64.StdEncoding.EncodeToString(result.CiphertextBlob)
		return &region, &plaintext, &ciphertext, nil
	}

	return nil, nil, nil, fmt.Errorf("failed to create a data key in every region")
}

func (r *RKMS) encryptDataKey(dataKey *string, region *string) (*string, error) {
	plaintext, err := base64.StdEncoding.DecodeString(*dataKey)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	client := r.clients[*region]
	result, err := client.Encrypt(&kms.EncryptInput{
		KeyId:     r.keyIds[*region],
		Plaintext: plaintext,
	})

	if err != nil { //failed to create data key in this region
		logger.Error(err)
		return nil, err
	}

	ciphertext := base64.StdEncoding.EncodeToString(result.CiphertextBlob)
	return &ciphertext, nil
}

func (r *RKMS) decryptDataKey(encryptedDataKeys map[string]string) (*string, error) {
	var lastError error

	//TODO: make parallelism configurable (e.g. request all KMS regions at the same time for the decrypted data key)
	for _, region := range r.regions {
		client := r.clients[region]

		ciphertext, err := base64.StdEncoding.DecodeString(encryptedDataKeys[region])
		if err != nil {
			//TODO(enhancement): ciphertext value in database is corrupted. fix it asyncrounously
			logger.Error(err)
			lastError = err
			continue
		}

		result, err := client.Decrypt(&kms.DecryptInput{
			CiphertextBlob: ciphertext,
		})

		if err != nil { //failed to decrypt in this region
			logger.Error(err)
			lastError = err
			continue
		}

		dataKey := base64.StdEncoding.EncodeToString(result.Plaintext)
		return &dataKey, nil
	}

	return nil, lastError
}
