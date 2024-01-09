package main

import (
	"api-tetap-ada/configs"
	"api-tetap-ada/routes"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	fmt.Println("Test")
	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3000, http://localhost:3001",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	//run databases
	configs.ConnectDB()

	//routes
	routes.WebsiteRoute(app)
	routes.CronJobRoute(app)
	routes.AuthRoute(app)
	routes.UserRoute(app)
	routes.GoogleRoute(app)

	app.Listen(":" + configs.EnvPort())
}
