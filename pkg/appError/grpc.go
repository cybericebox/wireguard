package appError

import "github.com/cybericebox/lib/pkg/err"

var (
	ErrGRPC = err.ErrInternal.WithObjectCode(gRPCObjectCode)

	ErrGRPCUnauthenticated    = err.ErrUnauthenticated.WithObjectCode(gRPCObjectCode)
	ErrGRPCMissingKey         = err.ErrInvalidData.WithObjectCode(gRPCObjectCode).WithDetailCode(1).WithMessage("Missing key")
	ErrGRPCInvalidKey         = err.ErrInvalidData.WithObjectCode(gRPCObjectCode).WithDetailCode(2).WithMessage("Invalid key")
	ErrGRPCInvalidTokenFormat = err.ErrInvalidData.WithObjectCode(gRPCObjectCode).WithDetailCode(3).WithMessage("Invalid token format")
)
