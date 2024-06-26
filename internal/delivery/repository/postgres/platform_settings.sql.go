// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: platform_settings.sql

package postgres

import (
	"context"
)

const getVPNPrivateKey = `-- name: GetVPNPrivateKey :one
select value
from platform_settings
where type = 'vpn'
  and key = 'private_key'
`

func (q *Queries) GetVPNPrivateKey(ctx context.Context) (string, error) {
	row := q.queryRow(ctx, q.getVPNPrivateKeyStmt, getVPNPrivateKey)
	var value string
	err := row.Scan(&value)
	return value, err
}

const getVPNPublicKey = `-- name: GetVPNPublicKey :one
select value
from platform_settings
where type = 'vpn'
  and key = 'public_key'
`

func (q *Queries) GetVPNPublicKey(ctx context.Context) (string, error) {
	row := q.queryRow(ctx, q.getVPNPublicKeyStmt, getVPNPublicKey)
	var value string
	err := row.Scan(&value)
	return value, err
}

const setVPNPrivateKey = `-- name: SetVPNPrivateKey :exec
insert into platform_settings (type, key, value)
values ('vpn', 'private_key', $1)
`

func (q *Queries) SetVPNPrivateKey(ctx context.Context, value string) error {
	_, err := q.exec(ctx, q.setVPNPrivateKeyStmt, setVPNPrivateKey, value)
	return err
}

const setVPNPublicKey = `-- name: SetVPNPublicKey :exec
insert into platform_settings (type, key, value)
values ('vpn', 'public_key', $1)
`

func (q *Queries) SetVPNPublicKey(ctx context.Context, value string) error {
	_, err := q.exec(ctx, q.setVPNPublicKeyStmt, setVPNPublicKey, value)
	return err
}
