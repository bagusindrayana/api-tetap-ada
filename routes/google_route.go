package routes

import (
	"api-tetap-ada/controllers"

	"github.com/gofiber/fiber/v2"
)

func GoogleRoute(app *fiber.App) {

	app.Get("/sessions/oauth/google", controllers.GoogleOAuth)

}
