package controllers

import (
	"api-tetap-ada/configs"
	"api-tetap-ada/models"
	"api-tetap-ada/responses"
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var websiteCollection *mongo.Collection = configs.GetCollection(configs.DB, "websites")
var validate = validator.New()

func CreateWebsite(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	token = token[7:]
	var response configs.CheckAuthUserResponse = configs.CheckAuthUser(token)
	if response.Success == false || response.User == nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.WebsiteResponse{Message: "error", Data: &fiber.Map{"data": response.Message}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var website models.Website
	defer cancel()

	//validate the request bodys
	if err := c.BodyParser(&website); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//use the validator library to validate required fields
	if validationErr := validate.Struct(&website); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: "error", Data: &fiber.Map{"data": validationErr.Error()}})
	}
	newId := primitive.NewObjectID()
	newWebsite := models.Website{
		Id:     newId,
		UserId: response.User.ID,
		Url:    website.Url,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	//make request to the website url
	start := time.Now()
	resp, _ := client.Get(website.Url)

	elapsed := time.Since(start)

	//update the website data
	newWebsite.LastStatus = resp.StatusCode
	newWebsite.LastResponseTime = int(elapsed.Milliseconds())
	newWebsite.LastRequestTime = time.Now().Unix()

	certStatus := ""
	if resp.TLS != nil {
		for _, cert := range resp.TLS.PeerCertificates {
			certStatus = "Issuer: " + cert.Issuer.String() + "\nExpiry: " + cert.NotAfter.Format(time.RFC850) + "\n"
		}
	}

	newWebsite.LastCertCheck = certStatus

	_, err := websiteCollection.InsertOne(ctx, newWebsite)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": newWebsite}})
}

func GetAWebsite(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	token = token[7:]
	var response configs.CheckAuthUserResponse = configs.CheckAuthUser(token)
	if response.Success == false || response.User == nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.WebsiteResponse{Message: "error", Data: &fiber.Map{"data": response.Message}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	websiteId := c.Params("websiteId")
	var website models.Website
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(websiteId)

	err := websiteCollection.FindOne(ctx, bson.M{"id": objId, "user_id": response.User.ID}).Decode(&website)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": website}})
}

func UpdateWebsite(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	token = token[7:]
	var responseAuth configs.CheckAuthUserResponse = configs.CheckAuthUser(token)
	if responseAuth.Success == false || responseAuth.User == nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.WebsiteResponse{Message: "error", Data: &fiber.Map{"data": responseAuth.Message}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	websiteId := c.Params("websiteId")
	var website models.Website
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(websiteId)

	//validate the request body
	if err := c.BodyParser(&website); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//use the validator library to validate required fields
	if validationErr := validate.Struct(&website); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.WebsiteResponse{Message: "error", Data: &fiber.Map{"data": validationErr.Error()}})
	}

	//convert the request body to bson
	websiteBson := bson.M{
		"url":                website.Url,
		"last_status":        website.LastStatus,
		"last_response_time": website.LastResponseTime,
		"last_cert_check":    website.LastCertCheck,
		"last_request_time":  website.LastRequestTime,
	}

	result, err := websiteCollection.UpdateOne(ctx, bson.M{"id": objId, "userid": responseAuth.User.ID}, bson.M{"$set": websiteBson})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	var updatedWebsite models.Website
	if result.ModifiedCount == 1 {
		err := websiteCollection.FindOne(ctx, bson.M{"id": objId, "userid": responseAuth.User.ID}).Decode(&updatedWebsite)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
		}
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": updatedWebsite}})
}

func DeleteWebsite(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	token = token[7:]
	var responseAuth configs.CheckAuthUserResponse = configs.CheckAuthUser(token)
	if responseAuth.Success == false || responseAuth.User == nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.WebsiteResponse{Message: "error", Data: &fiber.Map{"data": responseAuth.Message}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	websiteId := c.Params("websiteId")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(websiteId)

	result, err := websiteCollection.DeleteOne(ctx, bson.M{"id": objId, "userid": responseAuth.User.ID})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": result}})
}

// get all with search and pagination
func GetAllWebsites(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	token = token[7:]
	var responseAuth configs.CheckAuthUserResponse = configs.CheckAuthUser(token)
	if responseAuth.Success == false || responseAuth.User == nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.WebsiteResponse{Message: responseAuth.Message})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//get the query params
	searchQuery := c.Query("search")
	pageQuery := c.Query("page")
	limitQuery := c.Query("limit")

	//convert the query params to int
	var page int64
	var limit int64
	page = 1
	limit = 10
	if pageQuery != "" {
		page = configs.ConvertToInt64(pageQuery)
	}
	if limitQuery != "" {
		limit = configs.ConvertToInt64(limitQuery)
	}

	//set the offset
	offset := (page - 1) * limit

	//set the filter
	filter := bson.M{}
	if searchQuery != "" {

		// filter/search by website url and status
		filter = bson.M{
			"$or": []bson.M{
				{"url": bson.M{"$regex": searchQuery, "$options": "i"}},
				{"laststatus": bson.M{"$regex": searchQuery, "$options": "i"}},
			},
		}

	}

	//by user id
	filter["userid"] = responseAuth.User.ID

	//get the data
	cursor, err := websiteCollection.Find(ctx, filter, &options.FindOptions{
		Skip:  &offset,
		Limit: &limit,
	})
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: err.Error(), Data: &fiber.Map{"data": []models.Website{}}})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//get the total count
	totalCount, err := websiteCollection.CountDocuments(ctx, filter)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//get the total pages
	totalPages := totalCount / int64(limit)
	if totalCount%int64(limit) > 0 {
		totalPages++
	}

	//get the data from the cursor and convert it to an array
	var websites []models.Website = make([]models.Website, 0)
	if err := cursor.All(ctx, &websites); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//prepare the response
	var response = make(map[string]interface{})
	response["data"] = websites
	response["total_data"] = totalCount
	response["current_page"] = page
	response["total_pages"] = totalPages

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": response}})
}

// find website by id, make request to website url, measeure the response time, and update the website data
func CheckWebsite(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	websiteId := c.Params("websiteId")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(websiteId)

	var website models.Website
	err := websiteCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&website)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	//make request to the website url
	start := time.Now()
	resp, _ := client.Get(website.Url)
	// if err != nil {
	// 	return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	// }
	elapsed := time.Since(start)

	//update the website data
	website.LastStatus = resp.StatusCode
	website.LastResponseTime = int(elapsed.Milliseconds())
	website.LastRequestTime = time.Now().Unix()

	// conn, err := tls.Dial("tcp", "blog.umesh.wtf:443", nil)
	// if err != nil {
	// 	panic("Server doesn't support SSL certificate err: " + err.Error())
	// }

	// err = conn.VerifyHostname("blog.umesh.wtf")
	// if err != nil {
	// 	panic("Hostname doesn't match with certificate: " + err.Error())
	// }
	// expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	// fmt.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))
	certStatus := ""
	for _, cert := range resp.TLS.PeerCertificates {
		certStatus = "Issuer: " + cert.Issuer.String() + "\nExpiry: " + cert.NotAfter.Format(time.RFC850) + "\n"
		// peerCertificate := CertificateInfo{
		//  Subject: cert.Subject.String(),
		//  Issuer: cert.Issuer.String(),
		//  NotBefore: cert.NotBefore,
		//  NotAfter: cert.NotAfter,
		//  SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		//  PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		// }
		// sslInfo.PeerCertificates = append(sslInfo.PeerCertificates, peerCertificate)
	}

	website.LastCertCheck = certStatus

	//update the website data in the database
	result, err := websiteCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": website})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	var updatedWebsite models.Website
	if result.ModifiedCount == 1 {
		err := websiteCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&updatedWebsite)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
		}
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": updatedWebsite}})
}

// check all website
func CheckAllWebsites(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//get the data
	cursor, err := websiteCollection.Find(ctx, bson.M{})
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	//get the data from the cursor and convert it to an array
	var websites []models.Website = make([]models.Website, 0)
	if err := cursor.All(ctx, &websites); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
	}

	for _, website := range websites {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		//make request to the website url
		start := time.Now()
		resp, _ := client.Get(website.Url)
		// if err != nil {
		// 	return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
		// }
		elapsed := time.Since(start)

		//update the website data
		website.LastStatus = resp.StatusCode
		website.LastResponseTime = int(elapsed.Milliseconds())
		website.LastRequestTime = time.Now().Unix()
		certStatus := ""
		if resp.TLS != nil {
			for _, cert := range resp.TLS.PeerCertificates {
				certStatus = "Issuer: " + cert.Issuer.String() + "\nExpiry: " + cert.NotAfter.Format(time.RFC850) + "\n"
			}
		}

		website.LastCertCheck = certStatus

		//update the website data in the database
		result, err := websiteCollection.UpdateOne(ctx, bson.M{"id": website.Id}, bson.M{"$set": website})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
		}

		var updatedWebsite models.Website
		if result.ModifiedCount == 1 {
			err := websiteCollection.FindOne(ctx, bson.M{"id": website.Id}).Decode(&updatedWebsite)
			if err != nil {
				return c.Status(http.StatusInternalServerError).JSON(responses.WebsiteResponse{Message: err.Error()})
			}
		}
	}

	return c.Status(http.StatusOK).JSON(responses.WebsiteResponse{Message: "success", Data: &fiber.Map{"data": len(websites)}})
}
