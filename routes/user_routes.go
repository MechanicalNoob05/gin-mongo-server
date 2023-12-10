package routes

import (
    "gin-mongo-server/controllers" //add this
    "github.com/gin-gonic/gin"
    "fmt"
)

func UserRouter(router *gin.Engine)  {
    fmt.Println("\n-> Setting User Routes")
    userGroup := router.Group("/user")
    {
        userGroup.POST("", controllers.CreateUser())
        userGroup.POST("/login", controllers.LoginAUser())
        userGroup.POST("/uploadFile", controllers.UploadImage())
        userGroup.GET("/:userId", controllers.GetAUser())
        userGroup.GET("/images", controllers.GetAllImages())
        userGroup.GET("/image/", controllers.RetrieveImage())
        userGroup.PUT("/:userId", controllers.EditAUser())
        userGroup.DELETE("/:userId", controllers.DeleteAUser())
    }

    router.GET("/users", controllers.GetAllUsers())
}
