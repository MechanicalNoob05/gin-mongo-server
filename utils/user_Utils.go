package utils

import (
	"mime/multipart"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

)

func IsJPG(fileHeader *multipart.FileHeader) bool {
	// Open the file
	file, err := fileHeader.Open()
	if err != nil {
		return false
	}
	defer file.Close()

	// Read the first 512 bytes to identify the file type
	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return false
	}

	// Check if the file has a JPG signature
	return strings.HasPrefix(http.DetectContentType(buffer), "image/jpeg")
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
// Function to verify the entered password against the hashed password
func VerifyPassword(enteredPassword, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
}


