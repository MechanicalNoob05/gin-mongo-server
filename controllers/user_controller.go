package controllers

import (
	"context"
	"fmt"
	"gin-mongo-server/configs"
	"gin-mongo-server/middleware"
	"gin-mongo-server/models"
	"gin-mongo-server/responses"
	"gin-mongo-server/utils"
	util "gin-mongo-server/utils"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var todoCollection *mongo.Collection = configs.GetCollection(configs.DB, "todos")
var validate = validator.New()

// Define a secret key for signing the JWT token

func CreateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var user models.User
		defer cancel()

		// Validate the request body
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		// Use the validator library to validate required fields
		if validationErr := validate.Struct(&user); validationErr != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": validationErr.Error()}})
			return
		}

		// Hash the password
		hashedPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		// Create a new user with the encrypted password
		newUser := models.User{
			UserName:  user.UserName,
			Password:  hashedPassword,
			Name:      user.Name,
			Location:  user.Location,
			Title:     user.Title,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		result, err := userCollection.InsertOne(ctx, newUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		c.JSON(http.StatusCreated, responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: map[string]interface{}{"data": result}})
	}
}
func GetAUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("New login")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		userId := c.Param("userId")
		var user models.User
		defer cancel()

		objId, _ := primitive.ObjectIDFromHex(userId)

		err := userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": user}})
	}
}
func LoginAUser() gin.HandlerFunc {

	return func(c *gin.Context) {
		log.Printf("New login")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var loginCredentials models.User
		// Validate the request body
		if err := c.BindJSON(&loginCredentials); err != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		// Retrieve the user from the database by username
		filter := bson.M{"username": loginCredentials.UserName}
		var existingUser models.User
		err := userCollection.FindOne(ctx, filter).Decode(&existingUser)
		if err != nil {
			c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: map[string]interface{}{"data": "Invalid credentials User"}})
			return
		}

		// Compare the entered password with the hashed password from the database
		// err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginCredentials.Password))
		err = util.VerifyPassword(loginCredentials.Password, existingUser.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: map[string]interface{}{"data": "Invalid credentials Pass"}})
			return
		}

		// Generate a JWT token upon successful login
		token, err := middleware.GenerateToken(existingUser.ID.Hex())
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": "Internal Server Error"}})
			return
		}

		// Return the JWT token in the response
		c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"token": token}})
	}

}
func EditAUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Retrieve the user ID from the JWT token obtained through middleware
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: map[string]interface{}{"data": "User not authenticated"}})
			return
		}

		// Convert user ID to ObjectID
		objID, ok := userID.(primitive.ObjectID)
		if !ok {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": "Internal Server Error"}})
			return
		}

		// Validate the request body
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		// Use the validator library to validate required fields
		if validationErr := validate.Struct(&user); validationErr != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": validationErr.Error()}})
			return
		}

		// Create update data
		update := bson.M{
			"name":      user.Name,
			"location":  user.Location,
			"username":  user.UserName,
			"password":  user.Password,
			"title":     user.Title,
			"updatedAt": time.Now(),
		}

		// Update the user in the database
		result, err := userCollection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": update})
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		// Get the updated user details
		var updatedUser models.User
		if result.MatchedCount == 1 {
			err := userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&updatedUser)
			if err != nil {
				c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
				return
			}
		}

		c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": updatedUser}})
	}
}
func DeleteAUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		userId := c.Param("userId")
		defer cancel()

		objId, _ := primitive.ObjectIDFromHex(userId)

		result, err := userCollection.DeleteOne(ctx, bson.M{"_id": objId})
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		if result.DeletedCount < 1 {
			c.JSON(http.StatusNotFound,
				responses.UserResponse{Status: http.StatusNotFound, Message: "error", Data: map[string]interface{}{"data": "User with specified ID not found!"}},
			)
			return
		}

		c.JSON(http.StatusOK,
			responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": "User successfully deleted!"}},
		)
	}
}

func GetAllUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var users []models.User
		defer cancel()

		results, err := userCollection.Find(ctx, bson.M{})

		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		//reading from the db in an optimal way
		defer results.Close(ctx)
		for results.Next(ctx) {
			var singleUser models.User
			if err = results.Decode(&singleUser); err != nil {
				c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			}

			users = append(users, singleUser)
		}

		c.JSON(http.StatusOK,
			responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": users}},
		)
	}

}

func UploadImage() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Parse our multipart form, 10 << 20 specifies a maximum
		// upload of 10 MB files.
		err := c.Request.ParseMultipartForm(10 << 20)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		// FormFile returns the first file for the given key `myFile`
		// it also returns the FileHeader so we can get the Filename,
		// the Header, and the size of the file
		file, handler, err := c.Request.FormFile("myFile")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
			return
		}
		defer file.Close()

		// Check if the uploaded file is a JPG image
		if !util.IsJPG(handler) {
			c.JSON(http.StatusNotAcceptable, gin.H{"error": "Invalid file format. Only JPG images are allowed."})
			return
		}

		// Create a temporary file within our temp-images directory that follows
		// a particular naming pattern
		tempFile, err := os.CreateTemp("./images", "upload-*.jpg")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}
		defer tempFile.Close()

		// read all of the contents of our uploaded file into a
		// byte array
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}
		// write this byte array to our temporary file
		tempFile.Write(fileBytes)

		// Construct metadata response
		metadata := map[string]interface{}{
			"Filename": handler.Filename,
			"Size":     handler.Size,
		}

		// Return metadata as JSON in the response
		c.JSON(http.StatusOK,
			responses.UserResponse{Status: http.StatusOK, Message: "Testing for upload ", Data: map[string]interface{}{"Image-Upload": metadata}},
		)
	}
}
func GetAllImages() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Specify the directory path
		dirPath := "./images"

		// Read the directory
		files, err := os.ReadDir(dirPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		// Extract filenames from the file info
		var imageNames []string
		for _, file := range files {
			imageNames = append(imageNames, file.Name())
		}

		// Return the list of image names
		c.JSON(http.StatusOK, gin.H{"imageNames": imageNames})
	}
}

func RetrieveImage() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse the JSON request body
		var requestBody map[string]string
		if err := c.BindJSON(&requestBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			return
		}

		// Get the filename from the request body
		filename, exists := requestBody["filename"]
		if !exists || filename == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Filename is required"})
			return
		}

		// Specify the directory path
		dirPath := "./images"

		// Construct the file path
		filePath := filepath.Join(dirPath, filename)

		// Serve the file
		c.File(filePath)
	}
}
func AddTodo() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from the request context (assuming it was set during authentication)
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// Parse the JSON request body
		var todo models.Todo
		if err := c.BindJSON(&todo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			return
		}

		// Set user ID for the TODO item
		objID, err := primitive.ObjectIDFromHex(userID.(string))
		if err != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": "Invalid user ID format"}})
			return
		}
		todo.Owner = objID
		todo.CreatedAt = time.Now()

		// Add TODO to the database
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := todoCollection.InsertOne(ctx, todo)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		// Construct response
		response := responses.TodoResponse{
			Status:  http.StatusCreated,
			Message: "Todo added successfully",
			Data: map[string]interface{}{
				"todoID": result.InsertedID,
			},
		}

		c.JSON(http.StatusCreated, response)
	}
}
func GetAllTodosForUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Retrieve the user ID from the JWT token obtained through middleware
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: map[string]interface{}{"data": "User not authenticated"}})
			return
		}

		// Convert user ID to ObjectID
		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": "Internal Server Error"}})
			return
		}

		objID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": "Invalid user ID format"}})
			return
		}

		// Query the database for todos associated with the user
		findOptions := options.Find()
		findOptions.SetSort(primitive.D{{Key: "createdAt", Value: -1}})

		filter := bson.M{"owner": objID}
		cursor, err := todoCollection.Find(ctx, filter, findOptions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}
		defer cursor.Close(ctx)

		var todos []models.Todo
		for cursor.Next(ctx) {
			var todo models.Todo
			if err := cursor.Decode(&todo); err != nil {
				c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
				return
			}
			todos = append(todos, todo)
		}

		c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"todos": todos}})
	}
}

func UploadToFirebase() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var Bucket = configs.FireBaseBucket()
		var firebaseApp, err = configs.SetupFirebase()
		if err != nil {
			c.JSON(http.StatusInternalServerError, responses.UserResponse{
				Status:  http.StatusInternalServerError,
				Message: "error",
				Data:    map[string]interface{}{"data": err.Error()},
			})
			return
		}

		client, err := firebaseApp.Storage(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create Firebase storage client",
			})
			return
		}

		bucketHandle, err := client.Bucket(Bucket)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get Firebase storage bucket handle",
			})
			return
		}

		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to get file from request",
			})
			return
		}

		src, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to open file",
			})
			return
		}
		defer src.Close()

		objectHandle := bucketHandle.Object(file.Filename)

		writer := objectHandle.NewWriter(ctx)
		id := uuid.New()
		writer.ObjectAttrs.Metadata = map[string]string{"firebaseStorageDownloadTokens": id.String()}
		defer writer.Close()

		if _, err := io.Copy(writer, src); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to upload file to Firebase storage",
			})
			return
		}

		// Get the download URL for the uploaded file
		downloadURL, err := objectHandle.Attrs(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get download URL",
			})
			return
		}

		newURL, err := util.ConvertGoogleStorageURL(downloadURL.MediaLink, id.String())
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "File uploaded successfully to Firebase storage",
			"url":     newURL,
		})
	}
}
