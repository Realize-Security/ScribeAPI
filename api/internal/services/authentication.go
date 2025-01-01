package services

import (
	"Scribe/pkg/config"
	"github.com/alexedwards/argon2id"
	"log"
)

func HashPassword(pwd string) (string, error) {
	params := &argon2id.Params{
		Memory:      128 * 1024,
		Iterations:  4,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := argon2id.CreateHash(pwd, params)
	if err != nil {
		log.Println(config.LogHashingError)
		return "", err
	}
	return hash, nil
}
