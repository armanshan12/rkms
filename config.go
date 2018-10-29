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
	MainRegion    string   `mapstructure:"main_region"`
	BackupRegions []string `mapstructure:"backup_regions"`
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

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error while reading config file: %s", err))
	}

	config := new(Configuration)
	viper.Unmarshal(&config)
	log.Printf("Loaded configuration: %s\n", *config)
	return config
}
