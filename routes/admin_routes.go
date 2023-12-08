package routes

import (
    "gin-mongo-server/controllers" //add this
    "github.com/gin-gonic/gin"
    "fmt"
)

func AdminRouter(router *gin.Engine)  {
    fmt.Println("\n-> Setting Admin Routes\n")
    adminGroup := router.Group("/admin")
    {
        adminGroup.POST("", controllers.CreateAdminUser())
        adminGroup.GET("/:userId", controllers.GetAAdminUser())
        adminGroup.PUT("/:userId", controllers.EditAAdminUser())
        adminGroup.DELETE("/user/:userId", controllers.DeleteARegularUser())
        adminGroup.DELETE("/:userId", controllers.DeleteAAdminUser())
    }
    router.GET("/admins", controllers.GetAllAdminUsers())
}
