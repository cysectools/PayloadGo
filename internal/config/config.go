package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	Threads   int    `mapstructure:"threads"`
	Timeout   int    `mapstructure:"timeout"`
	Proxy     string `mapstructure:"proxy"`
	UserAgent string `mapstructure:"user_agent"`
	Verbose   bool   `mapstructure:"verbose"`
}

var AppConfig *Config

func Init() {
	viper.SetConfigName(".payloadgo")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME")
	viper.AddConfigPath("/etc/payloadgo")

	// Set defaults
	viper.SetDefault("threads", 10)
	viper.SetDefault("timeout", 10)
	viper.SetDefault("user_agent", "PayloadGo/1.0")
	viper.SetDefault("verbose", false)

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			panic(err)
		}
	}

	AppConfig = &Config{}
	viper.Unmarshal(AppConfig)
}

func BindFlags(cmd *cobra.Command) {
	viper.BindPFlag("threads", cmd.PersistentFlags().Lookup("threads"))
	viper.BindPFlag("timeout", cmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("proxy", cmd.PersistentFlags().Lookup("proxy"))
	viper.BindPFlag("user_agent", cmd.PersistentFlags().Lookup("user_agent"))
	viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose"))
}

func GetConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".payloadgo.yaml"
	}
	return filepath.Join(home, ".payloadgo.yaml")
}
