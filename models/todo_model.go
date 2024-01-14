package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Collaborator struct {
	ID         primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	UserName   string             `json:"username,omitempty" bson:"username,omitempty"`
	FirstName  string             `json:"fname,omitempty" validate:"required"`
	ProfilePic string             `json:"profilepic"`
	// Add other fields from the User struct that you want to include in the Todo response
}

type Todo struct {
	ID            primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Owner         primitive.ObjectID `json:"owner" bson:"owner"`
	Title         string             `json:"title" bson:"title" validate:"required"`
	Content       string             `json:"content" bson:"content" validate:"required"`
	Completed     bool               `json:"completed" bson:"completed"`
	Important     bool               `json:"important" bson:"important"`
	Collaborators []Collaborator     `json:"collaborators,omitempty" bson:"collaborators"`
	CreatedAt     time.Time          `json:"createdAt,omitempty" bson:"createdAt"`
	UpdatedAt     time.Time          `json:"updatedAt" bson:"updatedAt"`
}
