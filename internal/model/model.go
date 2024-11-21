package model

import "github.com/gofrs/uuid"

type (
	Client struct {
		UserID     uuid.UUID
		GroupID    uuid.UUID
		Address    string
		DNS        string
		PrivateKey string
		PublicKey  string
		AllowedIPs string
		Endpoint   string
		Banned     bool
		LastSeen   int64
	}
)
