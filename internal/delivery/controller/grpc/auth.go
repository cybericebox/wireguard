package grpc

import (
	"context"
	"github.com/cybericebox/wireguard/pkg/appError"

	"github.com/cybericebox/wireguard/pkg/controller/grpc/client"
	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/metadata"
)

type Authenticator interface {
	AuthenticateContext(context.Context) error
}

type auth struct {
	signKey string // Sign Key
	authKey string // Auth Key
}

func NewAuthenticator(SignKey, AuthKey string) Authenticator {
	return &auth{signKey: SignKey, authKey: AuthKey}
}

func (a *auth) AuthenticateContext(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return appError.ErrGRPCMissingKey.Raise()
	}

	if len(md["token"]) == 0 {
		return appError.ErrGRPCMissingKey.Raise()
	}

	token := md["token"][0]
	if token == "" {
		return appError.ErrGRPCMissingKey.Raise()
	}

	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok = token.Method.(*jwt.SigningMethodHMAC); !ok {
			return ctx, appError.ErrGRPCInvalidTokenFormat.Raise()
		}

		return []byte(a.signKey), nil
	})
	if err != nil {
		return err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return appError.ErrGRPCInvalidTokenFormat.Raise()
	}

	authKey, ok := claims[client.AuthKey].(string)
	if !ok {
		return appError.ErrGRPCInvalidTokenFormat.Raise()
	}

	if authKey != a.authKey {
		return appError.ErrGRPCInvalidKey.Raise()
	}

	return nil
}
