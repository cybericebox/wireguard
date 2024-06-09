// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package postgres

import (
	"context"

	"github.com/gofrs/uuid"
)

type Querier interface {
	CreateVpnClient(ctx context.Context, arg CreateVpnClientParams) error
	DeleteVPNClient(ctx context.Context, id uuid.UUID) error
	GetVPNClients(ctx context.Context) ([]VpnClient, error)
	UpdateVPNClientBanStatus(ctx context.Context, arg UpdateVPNClientBanStatusParams) error
}

var _ Querier = (*Queries)(nil)