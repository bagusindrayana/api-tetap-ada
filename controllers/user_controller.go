package controllers

import (
	"context"
	"net/http"
	"time"

	"api-tetap-ada/configs"
	"api-tetap-ada/models"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetUser(c *fiber.Ctx) error {

	//get token from header
	token := c.Get("Authorization")
	//remove bearer
	token = token[7:]
	//validate token
	claims := configs.CheckAuth(token)

	if claims.Email == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"message": "unauthorized"})
	}

	//get data user
	var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	var email = claims.Email

	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"message": "user not found"})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"message": "error"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "success", "data": user})
}
