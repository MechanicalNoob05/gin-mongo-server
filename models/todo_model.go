package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Todo struct {
	ID        primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Owner     primitive.ObjectID `json:"owner" bson:"owner"`
	Title     string             `json:"title" bson:"title" validate:"required"`
	Content   string             `json:"content" bson:"content" validate:"required"`
	CreatedAt time.Time          `json:"createdAt,omitempty" bson:"createdAt"`
}
