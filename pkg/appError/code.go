package appError

import "github.com/cybericebox/wireguard/pkg/err"

// Object codes
const (
	platformObjectCode = iota
	postgresObjectCode
	gRPCObjectCode
	iptablesObjectCode
	wireguardObjectCode
	ipamObjectCode
	wgKeyGenObjectCode
	clientObjectCode
)

// base object errors
var (
	ErrPlatform  = err.ErrInternal.WithObjectCode(platformObjectCode)
	ErrPostgres  = err.ErrInternal.WithObjectCode(postgresObjectCode)
	ErrIptables  = err.ErrInternal.WithObjectCode(iptablesObjectCode)
	ErrWireguard = err.ErrInternal.WithObjectCode(wireguardObjectCode)
	ErrIPAM      = err.ErrInternal.WithObjectCode(ipamObjectCode)
	ErrWgKeyGen  = err.ErrInternal.WithObjectCode(wgKeyGenObjectCode)
)
