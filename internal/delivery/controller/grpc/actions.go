package grpc

import (
	"context"
	"github.com/cybericebox/wireguard/pkg/controller/grpc/protobuf"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type Service interface {
	GetClientConfig(ctx context.Context, userID, groupID uuid.UUID, destCIDR string) (string, error)
	DeleteClients(ctx context.Context, userID, groupID uuid.UUID) error
	BanClients(ctx context.Context, userID, groupID uuid.UUID) error
	UnBanClients(ctx context.Context, userID, groupID uuid.UUID) error
}

func (w *Wireguard) GetClientConfig(ctx context.Context, request *protobuf.ClientConfigRequest) (*protobuf.ConfigResponse, error) {
	log.Info().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Str("destCIDR", request.GetDestCIDR()).Msg("Get client config")

	log.Debug().Str("userID", request.GetUserID()).Msg("Parsing user ID")
	userID, err := uuid.FromString(request.GetUserID())
	if err != nil {
		log.Error().Err(err).Msg("Parsing user ID")
		return &protobuf.ConfigResponse{}, err
	}

	log.Debug().Str("groupID", request.GetGroupID()).Msg("Parsing group ID")
	groupID, err := uuid.FromString(request.GetGroupID())
	if err != nil {
		log.Error().Err(err).Msg("Parsing group ID")
		return &protobuf.ConfigResponse{}, err
	}

	log.Debug().Str("destCIDR", request.GetDestCIDR()).Msg("Getting client config")
	config, err := w.service.GetClientConfig(ctx, userID, groupID, request.GetDestCIDR())
	if err != nil {
		log.Error().Err(err).Msg("Getting client config")
		return &protobuf.ConfigResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Str("destCIDR", request.GetDestCIDR()).Msg("Returning client config")
	return &protobuf.ConfigResponse{Config: config}, nil
}

func (w *Wireguard) DeleteClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.EmptyResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Deleting clients")
	if err := w.service.DeleteClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID())); err != nil {
		log.Error().Err(err).Msg("Deleting client")
		return &protobuf.EmptyResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Clients are deleted")
	return &protobuf.EmptyResponse{}, nil
}

func (w *Wireguard) BanClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.EmptyResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Banning clients")
	if err := w.service.BanClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID())); err != nil {
		log.Error().Err(err).Msg("Banning client")
		return &protobuf.EmptyResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Clients are banned")
	return &protobuf.EmptyResponse{}, nil
}

func (w *Wireguard) UnBanClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.EmptyResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Unbanning clients")
	if err := w.service.UnBanClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID())); err != nil {
		log.Error().Err(err).Msg("Unbanning client")
		return &protobuf.EmptyResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Clients are unbanned")
	return &protobuf.EmptyResponse{}, nil
}
