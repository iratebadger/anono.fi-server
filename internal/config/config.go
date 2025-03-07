package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	Server struct {
		Address string
		Port    int
	}
	CA struct {
		CertPath     string
		KeyPath      string
		Organization string
	}
	BinManager struct {
		InitialMask     uint64
		MessageRetention time.Duration
	}
}

// LoadConfig loads the configuration from a file
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")
	
	// Set defaults
	viper.SetDefault("server.address", "0.0.0.0")
	viper.SetDefault("server.port", 8443)
	viper.SetDefault("ca.cert_path", "certs/ca.crt")
	viper.SetDefault("ca.key_path", "certs/ca.key")
	viper.SetDefault("ca.organization", "Secure Messaging POC")
	viper.SetDefault("bin_manager.initial_mask", "0xFFFFFFFFFFFFF000")
	viper.SetDefault("bin_manager.message_retention", "24h")
	
	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		// It's okay if config file doesn't exist, we'll use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}
	
	// Parse configuration
	var cfg Config
	
	// Server configuration
	cfg.Server.Address = viper.GetString("server.address")
	cfg.Server.Port = viper.GetInt("server.port")
	
	// CA configuration
	cfg.CA.CertPath = viper.GetString("ca.cert_path")
	cfg.CA.KeyPath = viper.GetString("ca.key_path")
	cfg.CA.Organization = viper.GetString("ca.organization")
	
	// Bin manager configuration
	maskStr := viper.GetString("bin_manager.initial_mask")
	if _, err := fmt.Sscanf(maskStr, "0x%X", &cfg.BinManager.InitialMask); err != nil {
		return nil, fmt.Errorf("invalid bin mask format: %s", maskStr)
	}
	
	cfg.BinManager.MessageRetention = viper.GetDuration("bin_manager.message_retention")
	
	return &cfg, nil
}