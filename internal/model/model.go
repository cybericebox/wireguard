package model

type (
	Client struct {
		ID         string
		Address    string
		DNS        string
		PrivateKey string
		PublicKey  string
		AllowedIPs string
		Endpoint   string
		Banned     bool
	}
)
