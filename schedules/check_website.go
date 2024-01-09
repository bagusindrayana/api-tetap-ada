package schedules

import (
	"api-tetap-ada/configs"
	"api-tetap-ada/models"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-co-op/gocron/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var MyScheduler = initScheduler()

func initScheduler() gocron.Scheduler {
	s, _ := gocron.NewScheduler()
	return s
}

func checkWebsite(limit int64, skip int64) {
	var websiteCollection *mongo.Collection = configs.GetCollection(configs.DB, "websites")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//get data websites with limit and skip
	opts := options.Find().SetLimit(limit).SetSkip(skip * limit)
	cursor, err := websiteCollection.Find(ctx, bson.D{}, opts)
	if err != nil {
		fmt.Println(err)
	}
	var websites []models.Website = make([]models.Website, 0)
	if err = cursor.All(ctx, &websites); err != nil {
		fmt.Println(err)
	}
	for _, website := range websites {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		//make request to the website url
		start := time.Now()
		resp, err := client.Get(website.Url)
		if err != nil {
			fmt.Println(err)
		}
		elapsed := time.Since(start)

		//update the website data
		website.LastStatus = resp.StatusCode
		website.LastResponseTime = int(elapsed.Milliseconds())
		website.LastRequestTime = time.Now().Unix()
		certStatus := ""
		for _, cert := range resp.TLS.PeerCertificates {
			certStatus = "Issuer: " + cert.Issuer.String() + "\nExpiry: " + cert.NotAfter.Format(time.RFC850) + "\n"
		}

		website.LastCertCheck = certStatus

		//update the website data in the database
		result, err := websiteCollection.UpdateOne(ctx, bson.M{"id": website.Id}, bson.M{"$set": website})
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(result)
	}
}

func SetCronJob() {
	var cronJobCollection *mongo.Collection = configs.GetCollection(configs.DB, "cron_jobs")
	var websiteCollection *mongo.Collection = configs.GetCollection(configs.DB, "websites")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//count websites data
	opts := options.Count().SetHint("_id_")
	totalWebsites, err := websiteCollection.CountDocuments(ctx, bson.D{}, opts)

	if err != nil {
		panic(err)
	}

	totalCronJobs, err := cronJobCollection.CountDocuments(ctx, bson.D{}, opts)
	if err != nil {
		panic(err)
	}

	_loop := totalWebsites / 10

	if _loop == 0 {
		_loop = 1

	}
	if _loop <= totalCronJobs {
		return
	}

	if totalCronJobs == 0 {
		totalCronJobs = 1
	}
	fmt.Println(totalWebsites)
	fmt.Println(_loop)
	for i := totalCronJobs - 1; int64(i) < _loop; i++ {

		j, err := MyScheduler.NewJob(
			gocron.DurationJob(
				2*time.Minute,
			),
			gocron.NewTask(
				checkWebsite,
				int64(10),
				i,
			),
		)

		if err != nil {
			// handle error
			fmt.Println(err)
		}
		// fmt.Println(j.ID().String())

		newId := primitive.NewObjectID()
		newCronJob := models.CronJob{
			Id:                 newId,
			CronJobId:          j.ID().String(),
			CronJobCreatedTime: time.Now().Unix(),
		}

		_, err = cronJobCollection.InsertOne(ctx, newCronJob)
		if err != nil {
			panic(err)
		}

	}
	// start the scheduler
	MyScheduler.Start()

}

func StopCronJob() {
	if MyScheduler != nil {
		MyScheduler.Shutdown()
	}
	var cronJobCollection *mongo.Collection = configs.GetCollection(configs.DB, "cron_jobs")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//delete all cron jobs
	_, err := cronJobCollection.DeleteMany(ctx, bson.D{})
	if err != nil {
		panic(err)
	}
}

func ListJobs() []string {
	// list all jobs
	jobs := MyScheduler.Jobs()
	var resutl []string = make([]string, 0)
	for _, job := range jobs {
		resutl = append(resutl, job.ID().String())
	}
	return resutl
}
