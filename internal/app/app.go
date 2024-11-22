package app

import (
	"context"
	"github.com/cybericebox/lib/pkg/ipam"
	"github.com/cybericebox/lib/pkg/wgKeyGen"
	"github.com/cybericebox/wireguard/internal/config"
	"github.com/cybericebox/wireguard/internal/delivery/controller"
	"github.com/cybericebox/wireguard/internal/delivery/repository"
	"github.com/cybericebox/wireguard/internal/service"
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
	"syscall"
)

// Run initializes whole application.
func Run() {
	cfg := config.MustGetConfig()

	repo := repository.NewRepository(repository.Dependencies{Config: &cfg.Repository})

	ipaManager, err := ipam.NewIPAManager(ipam.Dependencies{
		PostgresConfig: ipam.PostgresConfig(cfg.Repository.Postgres),
		CIDR:           cfg.Service.VPN.CIDR,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create IPAManager")
	}

	keyGen := wgKeyGen.NewKeyGenerator()

	wgService := service.NewService(service.Dependencies{
		Repository:   repo,
		IPAManager:   ipaManager,
		KeyGenerator: keyGen,
		Config:       &cfg.Service.VPN,
	})

	ctx := context.Background()

	if err = wgService.InitServer(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to init server")
	}

	if err = wgService.InitServerClients(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to init server users")
	}

	ctrl := controller.NewController(controller.Dependencies{
		Config:  &cfg.Controller,
		Service: wgService,
	})

	ctrl.Start()

	if _, err = os.Create("/ready"); err != nil {
		log.Fatal().Err(err).Msg("Failed to create ready file")
	}

	log.Info().Msg("Application started")

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	<-quit

	// Stop the controller
	ctrl.Stop()
	log.Info().Msg("Controller stopped")
	// Stop the repository
	repo.Close()
	log.Info().Msg("Repository closed")

	log.Info().Msg("Application stopped")
}
