package appError

import "github.com/cybericebox/lib/pkg/err"

// Object codes
const (
	platformObjectCode = iota
	postgresObjectCode
	gRPCObjectCode
	iptablesObjectCode
	wireguardObjectCode
	clientObjectCode
)

// base object errors
var (
	ErrPlatform  = err.ErrInternal.WithObjectCode(platformObjectCode)
	ErrPostgres  = err.ErrInternal.WithObjectCode(postgresObjectCode)
	ErrIptables  = err.ErrInternal.WithObjectCode(iptablesObjectCode)
	ErrWireguard = err.ErrInternal.WithObjectCode(wireguardObjectCode)
)
