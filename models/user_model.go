package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID         primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	FirstName  string             `json:"fname,omitempty" validate:"required"`
	LastName   string             `json:"lname,omitempty" validate:"required"`
	UserName   string             `json:"username,omitempty" validate:"required"`
	Password   string             `json:"password,omitempty" validate:"required"`
	ProfilePic string             `json:"profilepic,omitempty"`
	Email      string             `json:"email" validate:"email,required"`
	CreatedAt  time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt  time.Time          `json:"updatedAt" bson:"updatedAt"`
}
