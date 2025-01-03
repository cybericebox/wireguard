package config

import (
	"flag"
	"fmt"
	"github.com/cybericebox/lib/pkg/wgKeyGen"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

const (
	VPNKeyPair = "vpn-keypair"
)

// Environments
const (
	Local      = "local"
	Stage      = "stage"
	Production = "production"
)

var MigrationPath string

type (
	Config struct {
		Environment string           `yaml:"environment" env:"ENV" env-default:"production" env-description:"Environment"`
		Controller  ControllerConfig `yaml:"controller"`
		Service     ServiceConfig    `yaml:"service"`
		Repository  RepositoryConfig `yaml:"repository"`
	}

	ControllerConfig struct {
		GRPC GRPCConfig `yaml:"grpc"`
	}

	GRPCConfig struct {
		Host string     `yaml:"host" env:"WG_GRPC_HOST" env-default:"0.0.0.0" env-description:"Host of GRPC server"`
		Port string     `yaml:"port" env:"WG_GRPC_PORT" env-default:"5454" env-description:"Port of GRPC server"`
		Auth AuthConfig `yaml:"auth"`
		TLS  TLSConfig  `yaml:"tls"`
	}

	TLSConfig struct {
		Enabled  bool   `yaml:"enabled" env:"WG_GRPC_TLS_ENABLED" env-default:"false" env-description:"Enabled TLS of GRPC server"`
		CertFile string `yaml:"certFile" env:"WG_GRPC_TLS_CERT" env-default:"" env-description:"CertFile of GRPC server"`
		CertKey  string `yaml:"certKey" env:"WG_GRPC_TLS_KEY" env-default:"" env-description:"CertKey of GRPC server"`
		CAFile   string `yaml:"caFile" env:"WG_GRPC_TLS_CA" env-default:"" env-description:"CaFile of GRPC server"`
	}

	AuthConfig struct {
		AuthKey string `yaml:"authKey" env:"WG_GRPC_AUTH_KEY" env-description:"Auth key of GRPC server"`
		SignKey string `yaml:"signKey" env:"WG_GRPC_SIGN_KEY" env-description:"Sign key of GRPC server"`
	}

	ServiceConfig struct {
		VPN VPNConfig `yaml:"vpn"`
	}

	RepositoryConfig struct {
		Postgres PostgresConfig `yaml:"postgres"`
	}

	VPNConfig struct {
		Endpoint string `yaml:"endpoint" env:"VPN_ENDPOINT" env-default:"" env-description:"VPN server endpoint"`
		CIDR     string `yaml:"cidr" env:"VPN_CIDR" env-default:"10.128.0.0/16" env-description:"VPN clients CIDR"`
		Address  string
		Port     string `yaml:"port" env:"VPN_PORT" env-default:"51820" env-description:"VPN server listen port"`
		KeyPair  *wgKeyGen.KeyPair
	}

	// PostgresConfig is the configuration for the Postgres database
	PostgresConfig struct {
		Host     string `yaml:"host" env:"POSTGRES_HOSTNAME" env-description:"Host of Postgres"`
		Port     string `yaml:"port" env:"POSTGRES_PORT" env-default:"5432" env-description:"Port of Postgres"`
		Username string `yaml:"username" env:"POSTGRES_USER" env-description:"Username of Postgres"`
		Password string `yaml:"password" env:"POSTGRES_PASSWORD" env-description:"Password of Postgres"`
		Database string `yaml:"database" env:"POSTGRES_DB" env-description:"Database of Postgres"`
		SSLMode  string `yaml:"sslMode" env:"POSTGRES_SSL_MODE" env-default:"require" env-description:"SSL mode of Postgres"`
	}
)

func MustGetConfig() *Config {
	path := flag.String("config", "", "Path to config file")
	flag.Parse()

	log.Info().Msg("Reading wireguard configuration")

	instance := &Config{}
	header := "Config variables:"
	help, _ := cleanenv.GetDescription(instance, &header)

	var err error

	if path != nil && *path != "" {
		err = cleanenv.ReadConfig(*path, instance)
	} else {
		err = cleanenv.ReadEnv(instance)
	}

	if err != nil {
		fmt.Println(help)
		log.Fatal().Err(err).Msg("Failed to read config")
		return nil
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// set log mode
	if instance.Environment != Production {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	MigrationPath = "migrations"
	if instance.Environment == Local {
		MigrationPath = "internal/delivery/repository/postgres/migrations"
	}

	// create VPN key pair
	instance.Service.VPN.KeyPair = &wgKeyGen.KeyPair{}

	return instance
}
