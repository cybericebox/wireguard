package controller

import (
	"fmt"
	"github.com/cybericebox/wireguard/internal/config"
	grpcController "github.com/cybericebox/wireguard/internal/delivery/controller/grpc"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"net"
)

type (
	// Controller is the API for the application
	Controller struct {
		config *config.ControllerConfig
		// grpcController is the controller for the grpc server
		grpcController *grpc.Server
	}

	// Service is the API for the service layer
	Service interface {

		// IService is dependencies for the grpc controller
		grpcController.IService
	}

	// Dependencies for the controller
	Dependencies struct {
		Config  *config.ControllerConfig
		Service Service
	}
)

// NewController creates a new controller
func NewController(deps Dependencies) *Controller {
	grpcCont, err := grpcController.New(grpcController.Dependencies{
		Config:  &deps.Config.GRPC,
		Service: deps.Service,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to setup grpc server")
	}
	return &Controller{
		grpcController: grpcCont,
		config:         deps.Config,
	}
}

// Start starts the controller
func (c *Controller) Start() {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%s", c.config.GRPC.Host, c.config.GRPC.Port))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to listen")
	}
	go func() {
		if err = c.grpcController.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("Failed to serve")
		}
	}()
	log.Info().Msgf("gRPC server is running at %s...\n", fmt.Sprintf("%s:%s", c.config.GRPC.Host, c.config.GRPC.Port))
}

// Stop stops the controller
func (c *Controller) Stop() {
	c.grpcController.GracefulStop()
}
