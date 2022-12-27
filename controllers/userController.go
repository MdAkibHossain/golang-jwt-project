package controllers

import (
	"context"
	"fmt"
	"golang-jwt-project/database"
	helper "golang-jwt-project/helpers"
	"golang-jwt-project/models"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {

	err := bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(providedPassword))
	fmt.Println("\nCheck P")
	check := true
	msg := ""
	fmt.Println("\nCheck P", err)
	fmt.Println("\n user p", string([]byte(userPassword)))
	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect")

		check = false
	}
	fmt.Println("\n", userPassword)

	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Print("start................")
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		err := c.BindJSON(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validatorErr := validate.Struct(&user)
		if validatorErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validatorErr.Error()})
			return
		}
		fmt.Print("Check 1111111111111")
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		fmt.Print("Check 222222222222")

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while checking for the email"})
			return
		}

		fmt.Print("Check 333333333")

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This email already exist"})
			return
		}
		fmt.Print("Check 3333333333")
		password := HashPassword(user.Password)
		user.Password = password
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		fmt.Print("Check 4444444")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while checking for the phone"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This phone number already exist"})
			return
		}
		fmt.Print("Check 555555")
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		fmt.Print("Check 666666")
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
		fmt.Print("Check 77777")
		user.Token = &token
		user.Refresh_token = &refreshToken
		fmt.Print("Check 8888888")
		resultInsertNumber, inserterr := userCollection.InsertOne(ctx, user)
		fmt.Print("Check 99999999")
		if inserterr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertNumber)
	}
}
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("\nStart")
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			defer cancel()
			return

		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}
		fmt.Println("\nuserPassword", user.Password)
		fmt.Println("\nfoundPassword", foundUser.Password)
		passwordIsValid, msg := VerifyPassword(foundUser.Password, user.Password)
		defer cancel()
		fmt.Println("\nCheck")
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		//
		//extra
		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
			return
		}
		//

		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		//
		//extra
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"erroe": err.Error()})
			return
		}
		//
		c.JSON(http.StatusOK, foundUser)

	}
}
func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))

		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage

		startIndex, err = strconv.Atoi(c.Query("startIndex"))
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}

		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
		}}}

		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		result, err := userCollection.Aggregate(
			ctx, mongo.Pipeline{
				matchStage, groupStage, projectStage,
			},
		)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while listing user items"})
			return
		}
		var allUsers []bson.M
		if err := result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")
		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// database connection
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
