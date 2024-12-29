package cache

import (
	"context"
	"github.com/valkey-io/valkey-go"
	"log"
	"os"
	"time"
)

var (
	Client valkey.Client
	ctx    context.Context
	cancel context.CancelFunc
)

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
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	Client = ConnectCache()
	if Client == nil {
		log.Println("[!] Failed to connect to cache")
		os.Exit(1)
	}
}
