package routes

import (
	"api-tetap-ada/controllers"

	"github.com/gofiber/fiber/v2"
)

func WebsiteRoute(app *fiber.App) {
	app.Post("/website", controllers.CreateWebsite)
	app.Get("/website/:websiteId", controllers.GetAWebsite)
	app.Get("/websites", controllers.GetAllWebsites)
	app.Post("/websites/check-all", controllers.CheckAllWebsites)
	app.Put("/website/:websiteId", controllers.UpdateWebsite)
	app.Delete("/website/:websiteId", controllers.DeleteWebsite)
	app.Post("/website/:websiteId/check", controllers.CheckWebsite)

}
