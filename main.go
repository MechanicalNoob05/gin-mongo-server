package main

import (
	"fmt"
	"gin-mongo-server/configs"
	"gin-mongo-server/routes"
	"gin-mongo-server/utils"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/cors"
)

func main() {
	router := gin.Default()

	//run database
	configs.ConnectDB()
	mongoConfig := configs.EnvMongoConfig()
	router.NoRoute(utils.HandleUnknownRoute)

	// router.Use(cors.Default())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"PUT", "PATCH", "GET", "POST"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "Authorization", "accept", "origin", "Cache-Control", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://github.com"
		},
		MaxAge: 12 * time.Hour,
	}))
	routes.UserRouter(router)
	routes.AdminRouter(router)

	serverAddress := fmt.Sprintf("%s:%s", "localhost", mongoConfig.Port)
	fmt.Println("\n-> Server up and running on", serverAddress)
	router.Run(serverAddress)
}
