package main

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

type ServerConfig struct {
	Port       string
	APIVersion string `mapstructure:"api_version"`
}

type KMSConfig struct {
	Regions []string
	KeyIds  map[string]*string `mapstructure:"key_ids"`
}

type DynamoDBConfig struct {
	Region    string `mapstructure:"region"`
	TableName string `mapstructure:"table_name"`
}

type Configuration struct {
	Server   ServerConfig
	KMS      KMSConfig
	DynamoDB DynamoDBConfig
}

func LoadConfiguration() *Configuration {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("toml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("fatal error while reading config file: %s", err)
	}

	config := new(Configuration)
	viper.Unmarshal(&config)
	log.Printf("Loaded configuration: %s\n", *config)

	if err := verifyKMSConfig(config.KMS); err != nil {
		log.Fatal(err)
	}

	return config
}

func verifyKMSConfig(kmsConfig KMSConfig) error {
	if len(kmsConfig.Regions) < MinimumKMSRegions {
		return fmt.Errorf("a minimmum of %d KMS regions is required", MinimumKMSRegions)
	}

	if len(kmsConfig.Regions) != len(kmsConfig.KeyIds) {
		return fmt.Errorf("the size of KMS regions array (%d) does not match the number of keyIds in KMS KeyIds map (%d)", len(kmsConfig.Regions), len(kmsConfig.KeyIds))
	}

	for _, region := range kmsConfig.Regions {
		if kmsConfig.KeyIds[region] == nil {
			return fmt.Errorf("region %s exists in KMS regions array but not in the KMS KeyIds map")
		}
	}

	return nil
}
