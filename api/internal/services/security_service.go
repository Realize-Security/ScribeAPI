package services

import (
	"Scribe/pkg/config"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// CertManager handles the generation and loading of cryptographic keys
type CertManager struct {
	AuthPrivateKey *rsa.PrivateKey
	AuthPublicKey  *rsa.PublicKey
	RefreshSecret  []byte
}

// NewCertManager creates a new certificate manager and ensures keys exist
func NewCertManager() (*CertManager, error) {
	// Ensure key directory exists
	if err := os.MkdirAll(config.DefaultKeyPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	cm := &CertManager{}
	if err := cm.ensureKeys(); err != nil {
		return nil, err
	}

	return cm, nil
}

// ensureKeys checks if keys exist and generates them if they don't
func (cm *CertManager) ensureKeys() error {
	// Check if keys already exist
	if !cm.keysExist() {
		if err := cm.generateKeys(); err != nil {
			return fmt.Errorf(config.LogKeyGenerationError, err)
		}
	}

	// Load the keys
	if err := cm.loadKeys(); err != nil {
		return fmt.Errorf(config.LogKeyLoadError, err)
	}

	return nil
}

// keysExist checks if all necessary key files exist
func (cm *CertManager) keysExist() bool {
	files := []string{
		config.AuthPrivateKeyPath,
		config.AuthPublicKeyPath,
		config.RefreshKeyPath,
	}

	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// generateKeys creates new keys and saves them to disk
func (cm *CertManager) generateKeys() error {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, config.RSAKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate refresh secret
	refreshSecret := make([]byte, config.RefreshKeySize)
	if _, err := rand.Read(refreshSecret); err != nil {
		return fmt.Errorf("failed to generate refresh secret: %w", err)
	}

	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(config.AuthPrivateKeyPath, privatePEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(config.AuthPublicKeyPath, publicPEM, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Save refresh secret
	if err := os.WriteFile(config.RefreshKeyPath, refreshSecret, 0600); err != nil {
		return fmt.Errorf("failed to save refresh secret: %w", err)
	}

	return nil
}

// loadKeys reads the keys from disk and initializes the CertManager
func (cm *CertManager) loadKeys() error {
	// Load private key
	privateKeyBytes, err := os.ReadFile(config.AuthPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}
	privateBlock, _ := pem.Decode(privateKeyBytes)
	if privateBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load refresh secret
	refreshSecret, err := os.ReadFile(config.RefreshKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read refresh secret: %w", err)
	}

	cm.AuthPrivateKey = privateKey
	cm.AuthPublicKey = &privateKey.PublicKey
	cm.RefreshSecret = refreshSecret

	return nil
}

// GetKeys returns the current set of keys
func (cm *CertManager) GetKeys() (*rsa.PrivateKey, *rsa.PublicKey, []byte) {
	return cm.AuthPrivateKey, cm.AuthPublicKey, cm.RefreshSecret
}
