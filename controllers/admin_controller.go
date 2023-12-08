package controllers

import (
    "context"
    "gin-mongo-server/configs"
    "gin-mongo-server/models"
    "gin-mongo-server/responses"
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/go-playground/validator/v10"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "go.mongodb.org/mongo-driver/mongo"

    "go.mongodb.org/mongo-driver/bson"
)

var adminUserCollection *mongo.Collection = configs.GetCollection(configs.DB, "admin")
var validateAdmin = validator.New()

func CreateAdminUser() gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        var user models.User
        defer cancel()

        //validate the request body
        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
            return
        }

        //use the validator library to validate required fields
        if validationErr := validate.Struct(&user); validationErr != nil {
            c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": validationErr.Error()}})
            return
        }

        newUser := models.User{
            Name:     user.Name,
            UserName: user.UserName,
            Password: user.Password,
            Location: user.Location,
            Title:    user.Title,
        }

        result, err := adminUserCollection.InsertOne(ctx, newUser)
        if err != nil {
            c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
            return
        }

        c.JSON(http.StatusCreated, responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: map[string]interface{}{"data": result}})
    }
}
func GetAAdminUser() gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        userId := c.Param("userId")
        var user models.User
        defer cancel()

        objId, _ := primitive.ObjectIDFromHex(userId)

        err := adminUserCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
        if err != nil {
            c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
            return
        }

        c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": user}})
    }
}
func EditAAdminUser() gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        userId := c.Param("userId")
        var user models.User
        defer cancel()
        objId, _ := primitive.ObjectIDFromHex(userId)

        //validate the request body
        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
            return
        }

        //use the validator library to validate required fields
        if validationErr := validate.Struct(&user); validationErr != nil {
            c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": validationErr.Error()}})
            return
        }

        update := bson.M{"name": user.Name, "location": user.Location,"username":user.UserName,"password":user.Password, "title": user.Title}
        result, err := adminUserCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": update})
        if err != nil {
            c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
            return
        }

        //get updated user details
        var updatedUser models.User
        if result.MatchedCount == 1 {
            err := adminUserCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&updatedUser)
            if err != nil {
                c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
                return
            }
        }

        c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": updatedUser}})
    }
}
func DeleteAAdminUser() gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        userId := c.Param("userId")
        defer cancel()

        objId, _ := primitive.ObjectIDFromHex(userId)

        result, err := adminUserCollection.DeleteOne(ctx, bson.M{"_id": objId})
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

func DeleteARegularUser() gin.HandlerFunc {
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
func GetAllAdminUsers() gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        var users []models.User
        defer cancel()

        results, err := adminUserCollection.Find(ctx, bson.M{})

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

