package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Website struct {
	Id               primitive.ObjectID `json:"id,omitempty"`
	UserId           primitive.ObjectID `json:"user_id,omitempty"` // user id
	Url              string             `json:"url,omitempty" validate:"required"`
	LastStatus       int                `json:"last_status,omitempty"`
	LastResponseTime int                `json:"last_response_time,omitempty"`
	LastCertCheck    string             `json:"last_cert_check,omitempty"`
	LastRequestTime  int64              `json:"last_request_time,omitempty"`
}
