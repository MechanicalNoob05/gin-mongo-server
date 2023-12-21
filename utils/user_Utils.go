package utils

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
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


func HandleUnknownRoute(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{
		"error":   "Not Found",
		"message": "The requested resource does not exist",
	})
}

func ConvertGoogleStorageURL(originalURL string, token string) (string, error) {
	// Parse the original URL
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", err
	}

	// Extract the path components
	pathComponents := strings.Split(parsedURL.Path, "/")

	// Modify the URL components
	newURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s?alt=media&token=%s",
		pathComponents[5], // Extracting the bucket name
		pathComponents[7], // Extracting the object path
		token,
	)

	return newURL, nil
}
