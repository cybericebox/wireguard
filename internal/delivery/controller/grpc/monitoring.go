package grpc

import (
	"context"
	"github.com/cybericebox/wireguard/pkg/controller/grpc/protobuf"
)

func (w *Wireguard) Ping(ctx context.Context, _ *protobuf.EmptyRequest) (*protobuf.EmptyResponse, error) {
	return &protobuf.EmptyResponse{}, nil
}
