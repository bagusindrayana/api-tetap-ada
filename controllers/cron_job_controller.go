package controllers

import (
	"api-tetap-ada/responses"
	"api-tetap-ada/schedules"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func SchedulCheckWebsite(c *fiber.Ctx) error {
	schedules.SetCronJob()
	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": "success"}})
}

func StopSchedulCheckWebsite(c *fiber.Ctx) error {
	schedules.StopCronJob()
	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": "success"}})
}

func GetJobs(c *fiber.Ctx) error {
	jobs := schedules.ListJobs()
	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": jobs}})
}
