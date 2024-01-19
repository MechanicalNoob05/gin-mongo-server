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
		userGroup.GET("/users", controllers.GetAllUsers())
		// userGroup.POST("/fire", controllers.AddProfilePic())
	}
	fmt.Println("\n-> Setting Auth User Routes")
	sudoUserGroup := router.Group("/user").Use(middleware.JWTMiddleware())
	{
		sudoUserGroup.GET("/profileInfo", controllers.GetAUser())
		sudoUserGroup.POST("/addTodo", controllers.AddTodo())
		sudoUserGroup.GET("/getTodo", controllers.GetAllTodosForUser())
		sudoUserGroup.DELETE("/deleteTodo/:todoId", controllers.DeleteAUserTodo())
		sudoUserGroup.PUT("/editTodo/:todoId", controllers.EditATodo())
		sudoUserGroup.PUT("/editUserProfile", controllers.EditAUser())
		sudoUserGroup.DELETE("/deleteAccount", controllers.DeleteAUser())
		sudoUserGroup.POST("/addProfilePic", controllers.AddProfilePic())
		sudoUserGroup.POST("/addcollaborator", controllers.AddCollaboratorToTodo())
		sudoUserGroup.GET("/search/:query", controllers.IncrementalSearchUsers())
	}

}
