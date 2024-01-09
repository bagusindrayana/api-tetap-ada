package routes

import (
	"api-tetap-ada/controllers"

	"github.com/gofiber/fiber/v2"
)

func CronJobRoute(app *fiber.App) {

	app.Get("/schedule-check-website", controllers.SchedulCheckWebsite)
	app.Get("/schedule-check-website/stop", controllers.StopSchedulCheckWebsite)
	app.Get("/jobs", controllers.GetJobs)

}
