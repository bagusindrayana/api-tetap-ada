package routes

import (
	"api-tetap-ada/controllers"

	"github.com/gofiber/fiber/v2"
)

func AuthRoute(app *fiber.App) {
	app.Post("/login", controllers.HandlerLogin)
	app.Post("/register", controllers.HandlerRegister)
}
