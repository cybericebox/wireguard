// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

func Prepare(ctx context.Context, db DBTX) (*Queries, error) {
	q := Queries{db: db}
	var err error
	if q.createVpnClientStmt, err = db.PrepareContext(ctx, createVpnClient); err != nil {
		return nil, fmt.Errorf("error preparing query CreateVpnClient: %w", err)
	}
	if q.deleteVPNClientStmt, err = db.PrepareContext(ctx, deleteVPNClient); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteVPNClient: %w", err)
	}
	if q.getVPNClientsStmt, err = db.PrepareContext(ctx, getVPNClients); err != nil {
		return nil, fmt.Errorf("error preparing query GetVPNClients: %w", err)
	}
	if q.updateVPNClientBanStatusStmt, err = db.PrepareContext(ctx, updateVPNClientBanStatus); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateVPNClientBanStatus: %w", err)
	}
	return &q, nil
}

func (q *Queries) Close() error {
	var err error
	if q.createVpnClientStmt != nil {
		if cerr := q.createVpnClientStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createVpnClientStmt: %w", cerr)
		}
	}
	if q.deleteVPNClientStmt != nil {
		if cerr := q.deleteVPNClientStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteVPNClientStmt: %w", cerr)
		}
	}
	if q.getVPNClientsStmt != nil {
		if cerr := q.getVPNClientsStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getVPNClientsStmt: %w", cerr)
		}
	}
	if q.updateVPNClientBanStatusStmt != nil {
		if cerr := q.updateVPNClientBanStatusStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateVPNClientBanStatusStmt: %w", cerr)
		}
	}
	return err
}

func (q *Queries) exec(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (sql.Result, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
	case stmt != nil:
		return stmt.ExecContext(ctx, args...)
	default:
		return q.db.ExecContext(ctx, query, args...)
	}
}

func (q *Queries) query(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (*sql.Rows, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryContext(ctx, args...)
	default:
		return q.db.QueryContext(ctx, query, args...)
	}
}

func (q *Queries) queryRow(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) *sql.Row {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryRowContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryRowContext(ctx, args...)
	default:
		return q.db.QueryRowContext(ctx, query, args...)
	}
}

type Queries struct {
	db                           DBTX
	tx                           *sql.Tx
	createVpnClientStmt          *sql.Stmt
	deleteVPNClientStmt          *sql.Stmt
	getVPNClientsStmt            *sql.Stmt
	updateVPNClientBanStatusStmt *sql.Stmt
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{
		db:                           tx,
		tx:                           tx,
		createVpnClientStmt:          q.createVpnClientStmt,
		deleteVPNClientStmt:          q.deleteVPNClientStmt,
		getVPNClientsStmt:            q.getVPNClientsStmt,
		updateVPNClientBanStatusStmt: q.updateVPNClientBanStatusStmt,
	}
}
