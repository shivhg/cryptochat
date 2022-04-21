// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-contrib/sessions"
	sessionpostgres "github.com/gin-contrib/sessions/postgres"
	"github.com/gin-gonic/gin"
	chat "github.com/p2p-chat/chat"
	"github.com/p2p-chat/model"
	"github.com/p2p-chat/service"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
)

const userkey = "user"

var secret = []byte("secret")

var addr = flag.String("addr", ":8080", "http service address")

func main() {
	dsn := "host=ec2-18-214-134-226.compute-1.amazonaws.com port=5432 user=ywcynxdtjidmeb dbname=dhma7b9b9h0kc password=0b23ba38cf4d940516888b95eb44929a0795120c46b0c2604aaaa7924971e7a1"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Info)})
	if err != nil {
		log.Fatal(err)
	}
	//err = db.AutoMigrate(&model.Message{})
	//err = db.AutoMigrate(&model.User{})
	if err != nil {
		panic(err)
	}
	var jwtService = service.JWTAuthService()
	var blockChainAuthenticator = service.BlockChainAuthenticator{Db: db}

	database, _ := db.DB()
	store, err := sessionpostgres.NewStore(database, []byte("secret"))
	if err != nil {
		panic("failed to create sessions")
	}

	r := gin.Default()
	r.Use(CORSMiddleware())
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/logout", logout)

	r.POST("/auth-jwt", func(c *gin.Context) {
		data, err := ioutil.ReadAll(c.Request.Body)
		if err != nil || len(data) == 0 {
			c.JSON(http.StatusUnauthorized, "")
		}
		var loginRequest LoginRequest
		json.Unmarshal(data, &loginRequest)

		verified := blockChainAuthenticator.Authenticate(loginRequest.WalletAddress, loginRequest.Signature)

		if verified {
			token := jwtService.GenerateToken(loginRequest.WalletAddress)
			c.JSON(http.StatusOK, map[string]string{"token": token})
			return
		}

		c.JSON(http.StatusUnauthorized, "")
	})

	r.POST("/auth", func(c *gin.Context) {
		data, _ := ioutil.ReadAll(c.Request.Body)
		var loginRequest LoginRequest
		json.Unmarshal(data, &loginRequest)
		var user model.User
		tx := db.Find(&user, model.User{Address: loginRequest.WalletAddress})
		if tx.Error != nil {
			return
		}

		verified := verifySig(loginRequest.WalletAddress, loginRequest.Signature, []byte("I am signing my one-time nonce: "+user.Nonce))
		if verified {
			session := sessions.Default(c)
			session.Set(userkey, loginRequest.WalletAddress)
			session.Save()
			c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
		}
	})

	r.GET("/accounts/:account", func(c *gin.Context) {
		var user model.User
		db.Find(&user, model.User{Address: c.Param("account")})
		if user.Address != "" {
			c.JSON(http.StatusOK, user)
			return
		}
		int63 := rand.Int()
		value := model.User{Address: c.Param("account"), Nonce: strconv.Itoa(int63)}
		tx := db.Create(&value)
		if tx.Error == nil {
			c.JSON(http.StatusOK, value)
			return
		}
		c.JSON(http.StatusBadRequest, "")
		return
	})

	hub := chat.NewHub()
	go hub.Run()

	private := r.Group("")
	private.Use(func(context *gin.Context) {
		header := context.GetHeader("Authorization")
		if header == "" {
			var err bool
			header, err = context.GetQuery("Authorization")

			if header == "" || !err {
				context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
		}

		token, err := jwtService.ValidateToken(header)
		if err != nil {
			context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			context.Set("loggedInAddress", claims["name"])
			context.Next()
		} else {
			context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		}
	})

	{
		private.GET("/ws", func(context *gin.Context) {
			chat.ServeWs(hub, context.Writer, context.Request,
				db, context.GetString("loggedInAddress"))
		})

		private.GET("/messages", fetchMessages(db))
	}

	err = r.Run()
	if err != nil {
		panic(err)
	}
}

func fetchMessages(db *gorm.DB) func(context *gin.Context) {
	return func(context *gin.Context) {
		address := context.GetString("loggedInAddress")
		var messages []model.Message
		var userMessage = make(map[string][]model.Message)

		db.Where("\"from\" = ?", address).Or("\"to\" = ?", address).Find(&messages)
		for _, message := range messages {
			if message.From == address {
				userMessage[message.To] = append(userMessage[message.To], message)
			}
			if message.To == address {
				userMessage[message.From] = append(userMessage[message.From], message)
			}
		}

		context.JSON(http.StatusOK, userMessage)
	}
}

func AuthRequired(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userkey)
	if user == nil {
		// Abort the request with the appropriate error code
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	// Continue down the chain to handler etc
	c.Set("loggedInAddress", user)
	c.Next()
}

func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Options(sessions.Options{MaxAge: -1})
	session.Save()
}

func verifySig(from, sigHex string, msg []byte) bool {
	sig := hexutil.MustDecode(sigHex)
	msg = accounts.TextHash(msg)
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return from == recoveredAddr.Hex()
}

type LoginRequest struct {
	WalletAddress string `json:"account"`
	Signature     string `json:"signature"`
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
