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

type JWTConfig struct {
	SecretKey string
}

// EnvJWTConfig reads JWT configuration from environment variables
func EnvJWTConfig() JWTConfig {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return JWTConfig{
		SecretKey: os.Getenv("JWT_SECRET_KEY"),
	}
}
func FireBaseBucket() string{
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error Retiveing Bucket")
	}
	return os.Getenv("BUCKET_LINK")
}
