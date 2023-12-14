package routes

import (
	"fmt"
	"gin-mongo-server/controllers"
	"gin-mongo-server/middleware"

	"github.com/gin-gonic/gin"
)

func UserRouter(router *gin.Engine) {
	fmt.Println("\n-> Setting User Routes")
	userGroup := router.Group("")
	{
		userGroup.POST("/signup", controllers.CreateUser())
		userGroup.POST("/login", controllers.LoginAUser())
		userGroup.GET("/:userId", controllers.GetAUser())
		userGroup.GET("/users", controllers.GetAllUsers())
		userGroup.POST("/fire",controllers.UploadToFirebase())
	}
	fmt.Println("\n-> Setting Auth User Routes")
	sudoUserGroup := router.Group("/user").Use(middleware.JWTMiddleware())
	{
		sudoUserGroup.GET("/images", controllers.GetAllImages())
		sudoUserGroup.POST("/uploadFile", controllers.UploadImage())
		sudoUserGroup.POST("/addTodo",controllers.AddTodo())
		sudoUserGroup.GET("/getTodo",controllers.GetAllTodosForUser())
		sudoUserGroup.GET("/image/", controllers.RetrieveImage())
		sudoUserGroup.PUT("", controllers.EditAUser())
		sudoUserGroup.DELETE("/:userId", controllers.DeleteAUser())
		sudoUserGroup.POST("/fire", controllers.UploadToFirebase())
	}

}
