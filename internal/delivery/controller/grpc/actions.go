package grpc

import (
	"context"
	"github.com/cybericebox/wireguard/internal/model"
	"github.com/cybericebox/wireguard/pkg/appError"
	"github.com/cybericebox/wireguard/pkg/controller/grpc/protobuf"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type IActionsService interface {
	GetClients(ctx context.Context, userID, groupID uuid.UUID) ([]*model.Client, error)
	GetClientConfig(ctx context.Context, userID, groupID uuid.UUID, destCIDR string) (string, error)
	DeleteClients(ctx context.Context, userID, groupID uuid.UUID) (int64, error)
	BanClients(ctx context.Context, userID, groupID uuid.UUID) (int64, error)
	UnBanClients(ctx context.Context, userID, groupID uuid.UUID) (int64, error)
}

func (w *Wireguard) GetClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.ClientsResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Getting clients")
	clients, err := w.service.GetClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID()))
	if err != nil {
		log.Error().Err(err).Msg("Getting clients")
		return &protobuf.ClientsResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Returning clients")
	pClients := make([]*protobuf.Client, 0, len(clients))
	for _, client := range clients {
		pClients = append(pClients, &protobuf.Client{
			UserID:   client.UserID.String(),
			GroupID:  client.GroupID.String(),
			Banned:   client.Banned,
			LastSeen: client.LastSeen,
		})
	}

	return &protobuf.ClientsResponse{
		Clients: pClients,
	}, nil
}

func (w *Wireguard) GetClientConfig(ctx context.Context, request *protobuf.ClientConfigRequest) (*protobuf.ConfigResponse, error) {
	log.Info().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Str("destCIDR", request.GetDestCIDR()).Msg("Get client config")

	log.Debug().Str("userID", request.GetUserID()).Msg("Parsing user ID")
	userID, err := uuid.FromString(request.GetUserID())
	if err != nil {
		log.Error().Err(err).Msg("Parsing user ID")
		return &protobuf.ConfigResponse{}, appError.ErrClientInvalidUserID.Err()
	}

	log.Debug().Str("groupID", request.GetGroupID()).Msg("Parsing group ID")
	groupID, err := uuid.FromString(request.GetGroupID())
	if err != nil {
		log.Error().Err(err).Msg("Parsing group ID")
		return &protobuf.ConfigResponse{}, appError.ErrClientInvalidGroupID.Err()
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

func (w *Wireguard) DeleteClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.ClientsAffectedResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Deleting clients")
	affected, err := w.service.DeleteClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID()))
	if err != nil {
		log.Error().Err(err).Msg("Deleting clients")
		return &protobuf.ClientsAffectedResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Clients are deleted")
	return &protobuf.ClientsAffectedResponse{
		ClientsAffected: affected,
	}, nil
}

func (w *Wireguard) BanClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.ClientsAffectedResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Banning clients")
	affected, err := w.service.BanClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID()))
	if err != nil {
		log.Error().Err(err).Msg("Banning clients")
		return &protobuf.ClientsAffectedResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Clients are banned")
	return &protobuf.ClientsAffectedResponse{
		ClientsAffected: affected,
	}, nil
}

func (w *Wireguard) UnBanClients(ctx context.Context, request *protobuf.ClientsRequest) (*protobuf.ClientsAffectedResponse, error) {
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Unbanning clients")
	affected, err := w.service.UnBanClients(ctx, uuid.FromStringOrNil(request.GetUserID()), uuid.FromStringOrNil(request.GetGroupID()))
	if err != nil {
		log.Error().Err(err).Msg("Unbanning clients")
		return &protobuf.ClientsAffectedResponse{}, err
	}
	log.Debug().Str("userID", request.GetUserID()).Str("groupID", request.GetGroupID()).Msg("Clients are unbanned")
	return &protobuf.ClientsAffectedResponse{
		ClientsAffected: affected,
	}, nil
}
