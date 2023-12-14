package main

import (
	"fmt"
	"gin-mongo-server/configs"
	"gin-mongo-server/routes"
	"gin-mongo-server/utils"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"PUT", "POST", "DELETE", "GET"},
		AllowHeaders:     []string{"Origin"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	//run database
	configs.ConnectDB()
	mongoConfig := configs.EnvMongoConfig()
	router.NoRoute(utils.HandleUnknownRoute)

	routes.UserRouter(router)
	routes.AdminRouter(router)

	serverAddress := fmt.Sprintf("%s:%s", "localhost", mongoConfig.Port)
	fmt.Println("\n-> Server up and running on", serverAddress)
	router.Run(serverAddress)
}
