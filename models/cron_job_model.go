package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type CronJob struct {
	Id                 primitive.ObjectID `json:"id,omitempty"`
	CronJobId          string             `json:"url,omitempty" validate:"required"`
	CronJobCreatedTime int64              `json:"last_request_time,omitempty"`
}
