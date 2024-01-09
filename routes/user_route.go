package routes

import (
	"api-tetap-ada/controllers"

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	app.Get("/user-profile", controllers.GetUser)
}
