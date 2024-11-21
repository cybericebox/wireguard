package grpc

import (
	"context"
	"errors"
	"github.com/cybericebox/wireguard/internal/model"
	"github.com/cybericebox/wireguard/pkg/controller/grpc/protobuf"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
	"io"
)

type (
	IMonitoringService interface {
		GetClients(ctx context.Context, userID, groupID uuid.UUID) ([]*model.Client, error)
	}
)

func (w *Wireguard) Ping(_ context.Context, _ *protobuf.EmptyRequest) (*protobuf.EmptyResponse, error) {
	return &protobuf.EmptyResponse{}, nil
}

func (w *Wireguard) Monitoring(stream protobuf.Wireguard_MonitoringServer) error {
	log.Debug().Msg("Client connected to monitoring")
	for {
		select {
		case <-stream.Context().Done():
			log.Debug().Msg("Client disconnected from monitoring")
			return nil
		default:
			break
		}
		_, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debug().Msg("Client disconnected from monitoring")
				return nil
			}
			log.Error().Err(err).Msg("Failed to receive monitoring request")
			continue
		}

		clients, err := w.service.GetClients(stream.Context(), uuid.Nil, uuid.Nil)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get clients")
			continue
		}

		pClients := make([]*protobuf.Client, 0, len(clients))
		for _, client := range clients {
			pClients = append(pClients, &protobuf.Client{
				UserID:   client.UserID.String(),
				GroupID:  client.GroupID.String(),
				Banned:   client.Banned,
				LastSeen: client.LastSeen,
			})
		}

		if err = stream.Send(&protobuf.MonitoringResponse{
			Clients: pClients,
		}); err != nil {
			log.Error().Err(err).Msg("Failed to send monitoring response")
		}
	}
}
