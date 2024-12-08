// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package postgres

import (
	"context"
)

type Querier interface {
	CreateVpnClient(ctx context.Context, arg CreateVpnClientParams) error
	DeleteVPNClients(ctx context.Context, arg DeleteVPNClientsParams) (int64, error)
	GetVPNClients(ctx context.Context) ([]VpnClient, error)
	GetVPNServerPrivateKey(ctx context.Context) (string, error)
	GetVPNServerPublicKey(ctx context.Context) (string, error)
	SetVPNServerPrivateKey(ctx context.Context, value string) error
	SetVPNServerPublicKey(ctx context.Context, value string) error
	UpdateVPNClientsBanStatus(ctx context.Context, arg UpdateVPNClientsBanStatusParams) (int64, error)
}

var _ Querier = (*Queries)(nil)
