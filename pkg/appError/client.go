package appError

import "github.com/cybericebox/lib/pkg/err"

var (
	ErrClient = err.ErrInternal.WithObjectCode(clientObjectCode)

	ErrClientInvalidAllowedIPs = err.ErrInvalidData.WithObjectCode(clientObjectCode).WithMessage("Invalid allowed IPs").WithDetailCode(1)
	ErrClientInvalidUserID     = err.ErrInvalidData.WithObjectCode(clientObjectCode).WithMessage("Invalid user ID").WithDetailCode(2)
	ErrClientInvalidGroupID    = err.ErrInvalidData.WithObjectCode(clientObjectCode).WithMessage("Invalid group ID").WithDetailCode(3)
)
