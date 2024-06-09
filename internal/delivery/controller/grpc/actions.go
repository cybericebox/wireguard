package grpc

import (
	"context"
	"github.com/cybericebox/wireguard/pkg/controller/grpc/protobuf"
	"github.com/rs/zerolog/log"
)

type Service interface {
	GetClientConfig(ctx context.Context, clientID, destCIDR string) (string, error)
	DeleteClient(ctx context.Context, clientID string) error

	BanClient(ctx context.Context, clientID string) error
	UnBanClient(ctx context.Context, clientID string) error
}

func (w *Wireguard) GetClientConfig(ctx context.Context, request *protobuf.ClientConfigRequest) (*protobuf.ConfigResponse, error) {
	config, err := w.service.GetClientConfig(ctx, request.GetId(), request.GetDestCIDR())
	if err != nil {
		log.Error().Err(err).Msg("Getting client config")
		return &protobuf.ConfigResponse{}, err
	}
	return &protobuf.ConfigResponse{Config: config}, nil
}

func (w *Wireguard) DeleteClient(ctx context.Context, request *protobuf.ClientRequest) (*protobuf.EmptyResponse, error) {
	if err := w.service.DeleteClient(ctx, request.GetId()); err != nil {
		log.Error().Err(err).Msg("Deleting client")
		return &protobuf.EmptyResponse{}, err
	}
	return &protobuf.EmptyResponse{}, nil
}

func (w *Wireguard) BanClient(ctx context.Context, request *protobuf.ClientRequest) (*protobuf.EmptyResponse, error) {
	if err := w.service.BanClient(ctx, request.GetId()); err != nil {
		log.Error().Err(err).Msg("Banning client")
		return &protobuf.EmptyResponse{}, err
	}
	return &protobuf.EmptyResponse{}, nil
}

func (w *Wireguard) UnBanClient(ctx context.Context, request *protobuf.ClientRequest) (*protobuf.EmptyResponse, error) {
	if err := w.service.UnBanClient(ctx, request.GetId()); err != nil {
		log.Error().Err(err).Msg("Unbanning client")
		return &protobuf.EmptyResponse{}, err
	}
	return &protobuf.EmptyResponse{}, nil
}
