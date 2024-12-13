// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: platform_settings.sql

package postgres

import (
	"context"
)

const getPlatformSettings = `-- name: GetPlatformSettings :one
select value
from platform_settings
where key = $1
`

func (q *Queries) GetPlatformSettings(ctx context.Context, key string) ([]byte, error) {
	row := q.db.QueryRow(ctx, getPlatformSettings, key)
	var value []byte
	err := row.Scan(&value)
	return value, err
}

const updatePlatformSettings = `-- name: UpdatePlatformSettings :execrows
update platform_settings
set value      = $2,
key = $1
`

type UpdatePlatformSettingsParams struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

func (q *Queries) UpdatePlatformSettings(ctx context.Context, arg UpdatePlatformSettingsParams) (int64, error) {
	result, err := q.db.Exec(ctx, updatePlatformSettings, arg.Key, arg.Value)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
