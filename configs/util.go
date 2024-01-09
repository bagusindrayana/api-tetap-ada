package configs

import (
	"api-tetap-ada/models"
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func ConvertToInt(value string) int {
	var intValue int
	for _, char := range value {
		intValue = intValue*10 + int(char-'0')
	}
	return intValue
}

// convert to int64
func ConvertToInt64(value string) int64 {
	var intValue int64
	for _, char := range value {
		intValue = intValue*10 + int64(char-'0')
	}
	return intValue
}

func CheckAuth(token string) Claims {
	//validate token
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return JWT_SIGNATURE_KEY, nil
	})

	if err != nil {
		return Claims{}
	}

	if !tkn.Valid {
		return Claims{}
	}

	return *claims
}

type CheckAuthUserResponse struct {
	Success bool         `json:"status"`
	Message string       `json:"message"`
	User    *models.User `json:"data"`
}

func CheckAuthUser(token string) CheckAuthUserResponse {
	var response CheckAuthUserResponse
	//get token from header

	//validate token
	claims := CheckAuth(token)

	if claims.Email == "" {
		response = CheckAuthUserResponse{Success: false, Message: "unauthorized", User: nil}
		return response
	}

	//get data user
	var userCollection *mongo.Collection = GetCollection(DB, "users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	var email = claims.Email

	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			response = CheckAuthUserResponse{Success: false, Message: "user not found", User: nil}
		}
		response = CheckAuthUserResponse{Success: false, Message: err.Error(), User: nil}
	} else {
		response = CheckAuthUserResponse{Success: true, Message: "Success", User: &user}
	}
	return response
}
