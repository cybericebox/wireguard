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
	GetVPNPrivateKey(ctx context.Context) (string, error)
	GetVPNPublicKey(ctx context.Context) (string, error)
	SetVPNPrivateKey(ctx context.Context, value string) error
	SetVPNPublicKey(ctx context.Context, value string) error
	UpdateVPNClientBanStatus(ctx context.Context, arg UpdateVPNClientBanStatusParams) error
}

var _ Querier = (*Queries)(nil)
