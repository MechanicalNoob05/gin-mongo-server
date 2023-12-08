package models


type User struct {
    Name     string             `json:"name,omitempty" validate:"required"`
    UserName     string         `json:"username,omitempty" validate:"required"`
    Password     string         `json:"password,omitempty" validate:"required"`
    Location string             `json:"location,omitempty" validate:"required"`
    Title    string             `json:"title,omitempty" validate:"required"`
}
