package main

import (
	"fmt"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ServerConfig represents the configuration needed for the server
type ServerConfig struct {
	Port       string
	APIVersion string `mapstructure:"api_version"`
}

// KMSConfig contains information for KMS services
type KMSConfig struct {
	Regions []string
	KeyIds  map[string]*string `mapstructure:"key_ids"`
}

// DynamoDBConfig contains information for DynamoDB used for RKMS
type DynamoDBConfig struct {
	Region    string `mapstructure:"region"`
	TableName string `mapstructure:"table_name"`
}

// Configuration represents all the configuration information this application needss
type Configuration struct {
	Server   ServerConfig
	KMS      KMSConfig
	DynamoDB DynamoDBConfig
}

// LoadConfiguration loads config file into memory and creates a Configuration object out of the information
func LoadConfiguration() *Configuration {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("toml")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatalf("fatal error while reading config file: %s", err)
	}

	config := new(Configuration)
	viper.Unmarshal(&config)
	logger.Infof("loaded configuration: %+v\n", *config)

	if err := verifyKMSConfig(config.KMS); err != nil {
		logger.Fatal(err)
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
			return fmt.Errorf("region %s exists in KMS regions array but not in the KMS KeyIds map", region)
		}
	}

	return nil
}
