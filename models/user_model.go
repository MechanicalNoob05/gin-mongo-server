package models

import "time"

type User struct {
	Name      string    `json:"name,omitempty" validate:"required"`
	UserName  string    `json:"username,omitempty" validate:"required"`
	Password  string    `json:"password,omitempty" validate:"required"`
	Location  string    `json:"location,omitempty" validate:"required"`
	Title     string    `json:"title,omitempty" validate:"required"`
	CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt" bson:"updatedAt"`
}
