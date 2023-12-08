package configs

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

type MongoDBConfig struct {
	URI  string
	Port string
}

// EnvMongoConfig loads MongoDB configuration from the .env file
func EnvMongoConfig() MongoDBConfig {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return MongoDBConfig{
		URI:  os.Getenv("MONGOURI"),
		Port: os.Getenv("PORT"),
	}
}
