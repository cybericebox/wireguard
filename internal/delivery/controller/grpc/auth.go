package grpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/cybericebox/wireguard/pkg/controller/grpc/client"
	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/metadata"
)

var (
	InvalidAuthKey        = errors.New("invalid Authentication Key")
	InvalidTokenFormatErr = errors.New("invalid token format")
	MissingKeyErr         = errors.New("no Authentication Key provided")
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
		return MissingKeyErr
	}

	if len(md["token"]) == 0 {
		return MissingKeyErr
	}

	token := md["token"][0]
	if token == "" {
		return MissingKeyErr
	}

	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok = token.Method.(*jwt.SigningMethodHMAC); !ok {
			return ctx, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(a.signKey), nil
	})
	if err != nil {
		return err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok || !jwtToken.Valid {
		return InvalidTokenFormatErr
	}

	authKey, ok := claims[client.AuthKey].(string)
	if !ok {
		return InvalidTokenFormatErr
	}

	if authKey != a.authKey {
		return InvalidAuthKey
	}

	return nil
}
