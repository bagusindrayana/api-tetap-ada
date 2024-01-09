package controllers

import (
	"api-tetap-ada/configs"
	"api-tetap-ada/models"
	"api-tetap-ada/responses"
	"context"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func HandlerLogin(c *fiber.Ctx) error {
	var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//login with email and password

	var user models.User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	var dbUser models.User
	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusNotFound).JSON(responses.WebsiteResponse{Message: "user not found"})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: "error"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password))
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.WebsiteResponse{Message: "invalid password"})
	}

	expirationTime := time.Now().Add(configs.LOGIN_EXPIRATION_DURATION)

	claims := &configs.Claims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(configs.JWT_SIGNATURE_KEY)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: "error"})
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"token": tokenString}})

}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func HandlerRegister(c *fiber.Ctx) error {
	var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
	var validate = validator.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var user models.User
	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: validationErr.Error()})
	}

	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//check if user already exist with email
	var dbUser models.User
	errFind := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if errFind == nil && dbUser.Email != "" {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: "user already exist"})
	}

	user.ID = primitive.NewObjectID()

	//create new user
	user.Password, _ = HashPassword(user.Password)
	user.Role = "user"
	user.Provider = "email"
	user.Verified = true
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err := userCollection.InsertOne(ctx, user)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	expirationTime := time.Now().Add(configs.LOGIN_EXPIRATION_DURATION)

	claims := &configs.Claims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(configs.JWT_SIGNATURE_KEY)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: "error"})
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"token": tokenString}})
}
