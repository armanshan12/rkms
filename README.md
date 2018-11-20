# RKMS (Reliable Key Management Service)
RKMS is a highly available key management service, built on top of AWS's KMS.


## Objective
While AWS's KMS is an amazing service, it does not have an SLA. As a result, if KMS goes down in the region you are using it in, your application also goes down as it can't encrypt/decrypt data. The idea of RKMS is to replicate your application's data keys across multiple regions, so you can fallback on another region if your main region goes down.


## Architecture
Before we look at how RKMS is designed, let's go over the main functionalities AWS's KMS provides:
- `GenerateDataKey()`: creates and returns a random data key to encrypt/decrypt data with
- `Encrypt(data, kmsKeyId)`: encrypts data with the specified KMS key
- `Decrypt(data, kmsKeyId)`: decrypts data with the specified KMS key

RKMS's main endpoint is `GET /key?id=<id>`, which roughly does the following:
  1. Look in the key/value store for a value for `id`
  2. If found, the value will contain mappings from KMS regions to encrypted data key
    - Pick a region
    - Decrypt encrypted data key in the selected region and return the plaintext data key returned by KMS
    - If call to KMS fails, try other regions
  3. If not found, a new key has to be created for the given `id`
    - Ask one of the KMS regions to generate a data key
    - Encrypt the data key in every region
    - Save all the encrypted data keys in the store for key `id`
  4. Return plaintext data key

Notes:
- RKMS is AWS specific
- It is not an implementation of a key management service from ground up
- It currently uses DynamoDB as the key/value store, but other stores can easily be swapped in; just need to implement the `Store` interface.

## Get Started
- (Optional) Use Terraform code in the `terraform` folder to create necessary resources
- Update `config.toml` file with values specific to your needs and environment. 
- Execute the following:
  ```
  go build
  ./rkms
  ```


## Contributing
Contributions to this project are very welcome! You can even contribute by simply requesting features or reporting bugs.

Things I would like to do in the future (which you can help with!) are:
- Write more tests
- Create a Makefile
- Create a Dockerfile
- Create Helm chart
