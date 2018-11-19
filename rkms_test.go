package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	logger "github.com/sirupsen/logrus"
)

const (
	unavailableKMSGenerateDataKeyCallCount = "unavailableKMS:GenerateDataKey"
	unavailableKMSEncryptCallCount         = "unavailableKMS:Encrypt"
	unavailableKMSDecryptCallCount         = "unavailableKMS:Decrypt"

	availableKMSGenerateDataKeyCallCount = "availableKMS:GenerateDataKey"
	availableKMSEncryptCallCount         = "availableKMS:Encrypt"
	availableKMSDecryptCallCount         = "availableKMS:Decrypt"

	mockStoreGetEncryptedDataKeysCallCount  = "mockStore:GetEncryptedDataKeys"
	mockStoreSetEncryptionDataKeysCallCount = "mockStore:SetEncryptionDataKeys"
)

var counters map[string]int

type unavailableKMSClient struct {
	kmsiface.KMSAPI
}

func (c *unavailableKMSClient) GenerateDataKeyWithContext(aws.Context, *kms.GenerateDataKeyInput, ...request.Option) (*kms.GenerateDataKeyOutput, error) {
	counters[unavailableKMSGenerateDataKeyCallCount] = counters[unavailableKMSGenerateDataKeyCallCount] + 1
	return nil, fmt.Errorf("server is unavailable")
}

func (c *unavailableKMSClient) EncryptWithContext(aws.Context, *kms.EncryptInput, ...request.Option) (*kms.EncryptOutput, error) {
	counters[unavailableKMSEncryptCallCount] = counters[unavailableKMSEncryptCallCount] + 1
	return nil, fmt.Errorf("server is unavailable")
}

func (c *unavailableKMSClient) DecryptWithContext(aws.Context, *kms.DecryptInput, ...request.Option) (*kms.DecryptOutput, error) {
	counters[unavailableKMSDecryptCallCount] = counters[unavailableKMSDecryptCallCount] + 1
	return nil, fmt.Errorf("server is unavailable")
}

type availableKMSClient struct {
	kmsiface.KMSAPI
}

func (c *availableKMSClient) GenerateDataKeyWithContext(ctx aws.Context, input *kms.GenerateDataKeyInput, opts ...request.Option) (*kms.GenerateDataKeyOutput, error) {
	counters[availableKMSGenerateDataKeyCallCount] = counters[availableKMSGenerateDataKeyCallCount] + 1
	return &kms.GenerateDataKeyOutput{
		KeyId:          input.KeyId,
		Plaintext:      []byte("plaintext"),
		CiphertextBlob: []byte("ciphertext"),
	}, nil
}

func (c *availableKMSClient) EncryptWithContext(ctx aws.Context, input *kms.EncryptInput, opts ...request.Option) (*kms.EncryptOutput, error) {
	counters[availableKMSEncryptCallCount] = counters[availableKMSEncryptCallCount] + 1
	return &kms.EncryptOutput{
		KeyId:          input.KeyId,
		CiphertextBlob: []byte("ciphertext"),
	}, nil
}

func (c *availableKMSClient) DecryptWithContext(ctx aws.Context, input *kms.DecryptInput, opts ...request.Option) (*kms.DecryptOutput, error) {
	counters[availableKMSDecryptCallCount] = counters[availableKMSDecryptCallCount] + 1

	keyID := "keyId"
	return &kms.DecryptOutput{
		KeyId:     &keyID,
		Plaintext: []byte("plaintext"),
	}, nil
}

type mockStore struct {
	Store
	numberOfRegions                     int
	dataShouldExist                     bool
	numberOfTimesToFailSetConditionally int
}

func (s *mockStore) GetEncryptedDataKeys(ctx context.Context, id string) (map[string]string, error) {
	counters[mockStoreGetEncryptedDataKeysCallCount] = counters[mockStoreGetEncryptedDataKeysCallCount] + 1

	if !s.dataShouldExist {
		return nil, nil
	}

	keys := make(map[string]string)
	for i := 0; i < s.numberOfRegions; i++ {
		keys[getTestRegionName(i)] = base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	}

	return keys, nil
}

func (s *mockStore) SetEncryptedDataKeysConditionally(ctx context.Context, id string, keys map[string]string) error {
	counters[mockStoreSetEncryptionDataKeysCallCount] = counters[mockStoreSetEncryptionDataKeysCallCount] + 1

	if s.numberOfTimesToFailSetConditionally > 0 {
		s.numberOfTimesToFailSetConditionally--
		if s.numberOfTimesToFailSetConditionally == 0 {
			s.dataShouldExist = true
		}
		return IDAlreadyExistsStoreError{ID: id}
	}

	return nil
}

// getRKMS returns an RKMS object with mock KMS clients.
// The clients will be avialable if the value for their index is set to true.
// Otherwise, the mock client will fail on every call.
func getRKMS(regionsAvailable []bool) *RKMS {
	regions := make([]string, len(regionsAvailable))
	keyIds := make(map[string]*string)
	clients := make(map[string]kmsiface.KMSAPI)

	for i, regionAvailable := range regionsAvailable {
		regionName := getTestRegionName(i)
		regions[i] = regionName

		keyID := getTestKeyID(regionName)
		keyIds[regionName] = &keyID

		if regionAvailable {
			clients[regionName] = &availableKMSClient{}
		} else {
			clients[regionName] = &unavailableKMSClient{}
		}
	}

	store := new(mockStore)
	store.numberOfRegions = len(regionsAvailable)
	return &RKMS{regions, keyIds, clients, store, int64(32)}
}

func getTestRegionName(regionIndex int) string {
	return fmt.Sprintf("region-%d", regionIndex)
}

func getTestKeyID(regionName string) string {
	return fmt.Sprintf("alias/kms-%s", regionName)
}

func verifyCounters(t *testing.T, actualCountersValues map[string]int, expectedCountersValues map[string]int) {
	//iterating over expected values instead of actual values in case
	//we don't care for all the values captured
	for counterName, expectedValue := range expectedCountersValues {
		actualValue := actualCountersValues[counterName]
		if actualValue != expectedValue {
			t.Fatalf("actual value (%d) does not match expected value (%d) for %s counter", actualValue, expectedValue, counterName)
		}
	}
}

func beforeTest() {
	logger.SetLevel(logger.DebugLevel)
	counters = make(map[string]int)
}
func TestServersUpEmptyStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{true, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
	}

	base64Plaintext, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err != nil {
		t.Fatalf("was not able to get plaintext: %s", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(*base64Plaintext)
	if err != nil {
		t.Fatalf("failed to decode base64 plaintext: %s", err)
	}

	if strings.Compare(string(plaintext), "plaintext") != 0 {
		t.Fatalf("returned plaintext data key is wrong: %s", plaintext)
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[unavailableKMSEncryptCallCount] = 0
	expectedCountersValues[unavailableKMSDecryptCallCount] = 0

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 1
	expectedCountersValues[availableKMSEncryptCallCount] = 2
	expectedCountersValues[availableKMSDecryptCallCount] = 0

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 1

	verifyCounters(t, counters, expectedCountersValues)
}

func TestServersUpFilledStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{true, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = true
	}

	base64Plaintext, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err != nil {
		t.Fatalf("was not able to get plaintext: %s", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(*base64Plaintext)
	if err != nil {
		t.Fatalf("failed to decode base64 plaintext: %s", err)
	}

	if strings.Compare(string(plaintext), "plaintext") != 0 {
		t.Fatalf("returned plaintext data key is wrong: %s", plaintext)
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[unavailableKMSEncryptCallCount] = 0
	expectedCountersValues[unavailableKMSDecryptCallCount] = 0

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[availableKMSEncryptCallCount] = 0
	expectedCountersValues[availableKMSDecryptCallCount] = 1

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestFirstServerDownEmptyStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{false, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
	}

	_, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err == nil {
		t.Fatalf("should not have received a data key back")
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 1
	expectedCountersValues[unavailableKMSEncryptCallCount] = 1
	expectedCountersValues[unavailableKMSDecryptCallCount] = 0

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 1
	expectedCountersValues[availableKMSDecryptCallCount] = 0

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestFirstServerDownFilledStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{false, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = true
	}

	base64Plaintext, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err != nil {
		t.Fatalf("was not able to get plaintext: %s", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(*base64Plaintext)
	if err != nil {
		t.Fatalf("failed to decode base64 plaintext: %s", err)
	}

	if strings.Compare(string(plaintext), "plaintext") != 0 {
		t.Fatalf("returned plaintext data key is wrong: %s", plaintext)
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[unavailableKMSEncryptCallCount] = 0
	expectedCountersValues[unavailableKMSDecryptCallCount] = 1

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[availableKMSDecryptCallCount] = 1

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestFirstTwoServersDownEmptyStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{false, false, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
	}

	_, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err == nil {
		t.Fatalf("should not have received a data key back")
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 2
	expectedCountersValues[unavailableKMSDecryptCallCount] = 0

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 1
	expectedCountersValues[availableKMSEncryptCallCount] = 0
	expectedCountersValues[availableKMSDecryptCallCount] = 0

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestFirstTwoServersDownFilledStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{false, false, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = true
	}

	base64Plaintext, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err != nil {
		t.Fatalf("was not able to get plaintext: %s", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(*base64Plaintext)
	if err != nil {
		t.Fatalf("failed to decode base64 plaintext: %s", err)
	}

	if strings.Compare(string(plaintext), "plaintext") != 0 {
		t.Fatalf("returned plaintext data key is wrong: %s", plaintext)
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[unavailableKMSDecryptCallCount] = 2

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[availableKMSEncryptCallCount] = 0
	expectedCountersValues[availableKMSDecryptCallCount] = 1

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestAllServersDownEmptyStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{false, false, false}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
	}

	_, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err == nil {
		t.Fatalf("should not have received a data key back")
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 3
	expectedCountersValues[unavailableKMSDecryptCallCount] = 0

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[availableKMSEncryptCallCount] = 0
	expectedCountersValues[availableKMSDecryptCallCount] = 0

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestAllServersDownFilledStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{false, false, false}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = true
	}

	_, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err == nil {
		t.Fatalf("should not have received a data key back")
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[unavailableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[unavailableKMSEncryptCallCount] = 0
	expectedCountersValues[unavailableKMSDecryptCallCount] = 3

	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 0
	expectedCountersValues[availableKMSEncryptCallCount] = 0
	expectedCountersValues[availableKMSDecryptCallCount] = 0

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 1
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 0

	verifyCounters(t, counters, expectedCountersValues)
}

func TestConditionalWriteToStore(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{true, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
		mockStore.numberOfTimesToFailSetConditionally = 1
	}

	base64Plaintext, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err != nil {
		t.Fatalf("was not able to get plaintext: %s", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(*base64Plaintext)
	if err != nil {
		t.Fatalf("failed to decode base64 plaintext: %s", err)
	}

	if strings.Compare(string(plaintext), "plaintext") != 0 {
		t.Fatalf("returned plaintext data key is wrong: %s", plaintext)
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 1
	expectedCountersValues[availableKMSEncryptCallCount] = 2
	expectedCountersValues[availableKMSDecryptCallCount] = 1

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 2
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 1

	verifyCounters(t, counters, expectedCountersValues)
}

func TestGetPLaintextDataKeyRetrySuccess(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{true, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
		mockStore.numberOfTimesToFailSetConditionally = MaxNumberOfGetPlaintextDataKeyTries - 1
	}

	base64Plaintext, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err != nil {
		t.Fatalf("was not able to get plaintext: %s", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(*base64Plaintext)
	if err != nil {
		t.Fatalf("failed to decode base64 plaintext: %s", err)
	}

	if strings.Compare(string(plaintext), "plaintext") != 0 {
		t.Fatalf("returned plaintext data key is wrong: %s", plaintext)
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 2
	expectedCountersValues[availableKMSEncryptCallCount] = 4
	expectedCountersValues[availableKMSDecryptCallCount] = 1

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 3
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 2

	verifyCounters(t, counters, expectedCountersValues)
}

func TestGetPLaintextDataKeyRetryFail(t *testing.T) {
	beforeTest()

	regionsAvailable := []bool{true, true, true}
	r := getRKMS(regionsAvailable)
	if mockStore, ok := r.store.(*mockStore); ok {
		mockStore.dataShouldExist = false
		mockStore.numberOfTimesToFailSetConditionally = MaxNumberOfGetPlaintextDataKeyTries
	}

	_, err := r.GetPlaintextDataKey(context.Background(), "id")
	if err == nil {
		t.Fatalf("should not have received a data key back")
	}

	expectedCountersValues := make(map[string]int)
	expectedCountersValues[availableKMSGenerateDataKeyCallCount] = 3
	expectedCountersValues[availableKMSEncryptCallCount] = 6
	expectedCountersValues[availableKMSDecryptCallCount] = 0

	expectedCountersValues[mockStoreGetEncryptedDataKeysCallCount] = 3
	expectedCountersValues[mockStoreSetEncryptionDataKeysCallCount] = 3

	verifyCounters(t, counters, expectedCountersValues)
}
