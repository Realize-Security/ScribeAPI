package cache

import (
	"context"
	"github.com/valkey-io/valkey-go"
	"log"
	"os"
)

var Client valkey.Client
var Ctx context.Context

func ConnectCache() valkey.Client {
	var h = os.Getenv("CACHE_HOST")
	var p = os.Getenv("CACHE_PORT")

	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{h + ":" + p}})
	if err != nil {
		log.Printf("Failed to connect to cache: %s", err.Error())
		return nil
	}
	log.Println("Connected to cache")
	return client
}

func InitCache() {
	log.Println("Initializing cache")
	Client = ConnectCache()
	Ctx = context.Background()
}
