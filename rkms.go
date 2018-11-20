package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	logger "github.com/sirupsen/logrus"
)

// MinimumKMSRegions is the minimum number of KMS regions needed to run a RKMS service
const MinimumKMSRegions = 3

// MaxNumberOfGetPlaintextDataKeyTries is the number of attempts to get/create data key before quitting
const MaxNumberOfGetPlaintextDataKeyTries = 3

// RKMS - Implementation of reliable KMS logic
type RKMS struct {
	regions []string
	keyIds  map[string]*string
	clients map[string]kmsiface.KMSAPI
	store   Store

	// the length of the data encryption key in bytes
	dataKeySizeInBytes int64
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

	return &RKMS{kmsConfig.Regions, kmsConfig.KeyIds, clients, store, kmsConfig.DataKeySizeInBytes}, nil
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
func (r *RKMS) GetPlaintextDataKey(ctx context.Context, id string) (*string, error) {
	return r.getPlaintextDataKey(ctx, id, MaxNumberOfGetPlaintextDataKeyTries, nil)
}

func (r *RKMS) getPlaintextDataKey(ctx context.Context, id string, triesLeft int, lastErr error) (*string, error) {
	if triesLeft == 0 {
		return nil, lastErr
	}

	plaintextDataKey, err := r.lookInStoreForDataKey(ctx, id)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if plaintextDataKey != nil {
		logger.Debugln("a data key was found in the store for the given id")
		return plaintextDataKey, nil
	}

	plaintextDataKey, err = r.createDataKeyForID(ctx, id)
	if err != nil {
		if _, ok := err.(IDAlreadyExistsStoreError); ok {
			//retry the whole process which will retry fetching data from store
			return r.getPlaintextDataKey(ctx, id, triesLeft-1, err)
		}

		logger.Error(err)
		return nil, err
	}

	//return the data key
	return plaintextDataKey, nil
}

func (r *RKMS) lookInStoreForDataKey(ctx context.Context, id string) (*string, error) {
	encryptedDataKeys, err := r.store.GetEncryptedDataKeys(ctx, id)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	if encryptedDataKeys == nil {
		logger.Debugln("no data key exists in the store for the given id")
		return nil, nil
	}

	plaintextDataKey, err := r.decryptDataKey(ctx, encryptedDataKeys)
	if err != nil {
		err := fmt.Errorf("failed to decrypt data key in every region: %s", err)
		logger.Error(err)
		return nil, err
	}

	return plaintextDataKey, err
}

type encryptDataKeyResult struct {
	region     string
	ciphertext *string
	err        error
}

func (r *RKMS) createDataKeyForID(ctx context.Context, id string) (*string, error) {
	logger.Debugln("creating data key...")
	firstRegion, plaintextDataKey, firstRegionCiphertext, err := r.createDataKey(ctx)
	if err != nil {
		logger.Errorf("failed to create a data key: %s", err)
		return nil, err
	}

	encryptedDataKeys := make(map[string]string)
	encryptedDataKeys[*firstRegion] = *firstRegionCiphertext

	resultsChannel := make(chan encryptDataKeyResult, len(r.regions)-1)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger.Debugln("encrypting generated data key in every region...")
	for _, region := range r.regions {
		if strings.Compare(region, *firstRegion) == 0 { //we have already encrypted in this region and have the ciphertext
			continue
		}

		go func(ctx context.Context, resultsChannel chan<- encryptDataKeyResult, plaintextDataKey string, region string) {
			logger.Debugf("encrypting data key in %s region", region)
			ciphertext, err := r.encryptDataKey(ctx, plaintextDataKey, region)
			resultsChannel <- encryptDataKeyResult{region, ciphertext, err}
		}(childCtx, resultsChannel, *plaintextDataKey, region)
	}

	for i := 0; i < len(r.regions)-1; i++ {
		select {
		case result := <-resultsChannel:
			if result.err != nil {
				logger.Errorf("failed to encrypt data key in %s region: %s", result.region, result.err)
				return nil, result.err
			}

			encryptedDataKeys[result.region] = *result.ciphertext
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while encrypting data key in all regions")
		}
	}

	logger.Debugln("saving encrypted data keys in store...")
	err = r.store.SetEncryptedDataKeysConditionally(ctx, id, encryptedDataKeys)
	if err != nil {
		logger.Errorf("failed to save encrypted data keys in key/value store: %s", err)
		return nil, err
	}

	logger.Debugln("done creating and saving encrypted data keys")
	return plaintextDataKey, nil
}

func (r *RKMS) createDataKey(ctx context.Context) (*string, *string, *string, error) {
	for _, region := range r.regions {
		input := &kms.GenerateDataKeyInput{
			KeyId:         r.keyIds[region],
			NumberOfBytes: aws.Int64(r.dataKeySizeInBytes),
		}

		result, err := r.clients[region].GenerateDataKeyWithContext(ctx, input)
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

func (r *RKMS) encryptDataKey(ctx context.Context, dataKey string, region string) (*string, error) {
	plaintext, err := base64.StdEncoding.DecodeString(dataKey)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	input := &kms.EncryptInput{
		KeyId:     r.keyIds[region],
		Plaintext: plaintext,
	}

	result, err := r.clients[region].EncryptWithContext(ctx, input)
	if err != nil { //failed to create data key in this region
		logger.Error(err)
		return nil, err
	}

	ciphertext := base64.StdEncoding.EncodeToString(result.CiphertextBlob)
	return &ciphertext, nil
}

type decryptDataKeyResult struct {
	region    string
	plaintext *string
	err       error
}

func (r *RKMS) decryptDataKey(ctx context.Context, encryptedDataKeys map[string]string) (*string, error) {
	resultsChannel := make(chan decryptDataKeyResult, len(r.regions))
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	//TODO(enhancement): add config param to run this serially if wanted
	for _, region := range r.regions {
		go func(ctx context.Context, resultsChannel chan<- decryptDataKeyResult, ciphertext string, region string) {
			ciphertextBlob, err := base64.StdEncoding.DecodeString(ciphertext)
			if err != nil {
				//TODO(enhancement): fix it asyncrounously
				logger.Errorf("ciphertext value is corrupted in the store for %s region: %s", region, err)
				resultsChannel <- decryptDataKeyResult{region, nil, err}
				return
			}

			input := &kms.DecryptInput{
				CiphertextBlob: ciphertextBlob,
			}

			logger.Debugf("decrypting data key in %s region", region)
			result, err := r.clients[region].DecryptWithContext(ctx, input)
			if err != nil { //failed to decrypt in this region
				if aerr, ok := err.(awserr.Error); ok && aerr.Code() != request.CanceledErrorCode {
					logger.Errorf("failed to decrypt in %s region: %s", region, err)
				}
				resultsChannel <- decryptDataKeyResult{region, nil, err}
				return
			}

			dataKey := base64.StdEncoding.EncodeToString(result.Plaintext)
			resultsChannel <- decryptDataKeyResult{region, &dataKey, nil}
		}(childCtx, resultsChannel, encryptedDataKeys[region], region)
	}

	for i := 0; i < len(r.regions); i++ {
		select {
		case result := <-resultsChannel:
			if result.err != nil {
				logger.Infof("failed to decrypt data key in %s region: %s", result.region, result.err)
				continue
			}

			logger.Debugf("successfully decrypted data key in %s region", result.region)
			return result.plaintext, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while decrypting data key in all regions")
		}
	}

	return nil, fmt.Errorf("failed to decrypt data key in all regions")
}
