package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Name      string             `json:"name,omitempty" validate:"required"`
	UserName  string             `json:"username,omitempty" validate:"required"`
	Password  string             `json:"password,omitempty" validate:"required"`
	Location  string             `json:"location,omitempty" validate:"required"`
	Title     string             `json:"title,omitempty" validate:"required"`
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
}
