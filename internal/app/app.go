package app

import (
	"context"
	"github.com/cybericebox/wireguard/internal/config"
	"github.com/cybericebox/wireguard/internal/delivery/controller"
	"github.com/cybericebox/wireguard/internal/delivery/repository"
	"github.com/cybericebox/wireguard/internal/service"
	"github.com/cybericebox/wireguard/pkg/ipam"
	"github.com/cybericebox/wireguard/pkg/wg-key-gen"
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
	"syscall"
)

// Run initializes whole application.
func Run() {
	cfg := config.GetConfig()

	repo := repository.NewRepository(repository.Dependencies{Config: &cfg.Repository})

	ipaManager, err := ipam.NewIPAManager(ipam.Dependencies{
		PostgresConfig: ipam.PostgresConfig(cfg.Repository.Postgres),
		CIDR:           cfg.Service.VPN.CIDR,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create IPAManager")
	}

	keyGen := wg_key_gen.NewKeyGenerator()

	wgService := service.NewService(service.Dependencies{
		Repository:   repo,
		IPAManager:   ipaManager,
		KeyGenerator: keyGen,
		Config:       &cfg.Service.VPN,
	})

	ctx := context.Background()

	if err = wgService.InitServer(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to init server")
	}

	if err = wgService.InitServerClients(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to init server users")
	}

	ctrl := controller.NewController(controller.Dependencies{
		Config:  &cfg.Controller,
		Service: wgService,
	})

	ctrl.Start()

	if _, err = os.Create("/ready"); err != nil {
		log.Fatal().Err(err).Msg("failed to create ready file")
	}

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	<-quit

	ctrl.Stop()
}
