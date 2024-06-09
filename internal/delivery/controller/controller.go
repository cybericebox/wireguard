package controller

import (
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

		// Service is dependencies for the grpc controller
		grpcController.Service
	}

	// Dependencies for the controller
	Dependencies struct {
		Config  *config.ControllerConfig
		Service Service
	}
)

// NewController creates a new controller
func NewController(deps Dependencies) *Controller {
	grpcCont, err := grpcController.New(&deps.Config.GRPC, deps.Service)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to setup grpc server")
	}
	return &Controller{
		grpcController: grpcCont,
		config:         deps.Config,
	}
}

// Start starts the controller
func (c *Controller) Start() {
	lis, err := net.Listen("tcp", c.config.GRPC.Endpoint)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}
	go func() {
		if err = c.grpcController.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("failed to serve")
		}
	}()
	log.Info().Msgf("gRPC server is running at %s...\n", c.config.GRPC.Endpoint)
}

// Stop stops the controller
func (c *Controller) Stop() {
	c.grpcController.GracefulStop()
}
