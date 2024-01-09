package configs

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConnectDB() *mongo.Client {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(EnvMongoURI()))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	//ping the database
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer cancel() // Call the cancel function to avoid a context leak
	fmt.Println("Connected to MongoDB")
	return client
}

// // Client instance
var DB *mongo.Client = ConnectDB()

// getting database collections
func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	collection := client.Database("apiTetapAda").Collection(collectionName)
	return collection
}

var APPLICATION_NAME = os.Getenv("APPLICATION_NAME")
var LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
var JWT_SIGNING_METHOD = jwt.SigningMethodHS256
var JWT_KEY_STRING = os.Getenv("JWT_KEY_STRING")
var JWT_SIGNATURE_KEY = []byte(JWT_KEY_STRING)

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}
