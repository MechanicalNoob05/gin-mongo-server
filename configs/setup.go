package configs

import (
	"context"
	"fmt"
	"log"

	firebase "firebase.google.com/go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/api/option"
)

func ConnectDB() *mongo.Client {
	mongoConfig := EnvMongoConfig()

	clientOptions := options.Client().ApplyURI(mongoConfig.URI)
	// Connect to MongoDB using the configuration

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)

	if err != nil {
		log.Fatal(err)
	}

	log.Println("\n->Connected to MongoDB!")

	return client
}

var firebaseApp *firebase.App

func SetupFirebase() (*firebase.App, error) {
	opt := option.WithCredentialsFile("firebase.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firebase app: %v", err)
	}
	return app, nil
}

// Client instance
var DB *mongo.Client = ConnectDB()

// getting database collections
func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	collection := client.Database("golangAPI").Collection(collectionName)
	return collection
}
