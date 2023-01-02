package bamp_cosigner

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/equitas-foundation/bamp-ocean/api-spec/protobuf/gen/go/bamp/v1"
	"github.com/equitas-foundation/bamp-ocean/internal/core/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type service struct {
	addr   string
	conn   *grpc.ClientConn
	client pb.CosignerServiceClient
}

func NewService(addr string) (ports.Cosigner, error) {
	withTls := false
	if strings.HasPrefix(addr, "http") {
		prefix := "http://"
		defaultPort := 80
		if !strings.HasPrefix(addr, prefix) {
			prefix = "https://"
			defaultPort = 443
			withTls = true
		}
		addr = strings.TrimPrefix(addr, prefix)
		split := strings.Split(addr, ":")
		if len(split) == 1 {
			addr = fmt.Sprintf("%s:%d", addr, defaultPort)
		}
	}
	creds := insecure.NewCredentials()
	if withTls {
		creds = credentials.NewTLS(nil)
	}
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	client := pb.NewCosignerServiceClient(conn)
	healthClient := grpchealth.NewHealthClient(conn)
	res, err := healthClient.Check(
		context.Background(), &grpchealth.HealthCheckRequest{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cosigner: %s", err)
	}
	if res.GetStatus() != grpchealth.HealthCheckResponse_SERVING {
		return nil, fmt.Errorf("cosigner invalid status: %s", res.GetStatus())
	}

	return &service{addr, conn, client}, nil
}

func (s *service) GetXpub(ctx context.Context) (string, error) {
	resp, err := s.client.GetXpub(ctx, &pb.GetXpubRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetXpub(), nil
}

func (s *service) RegisterMultiSig(
	ctx context.Context, descriptor string,
) error {
	_, err := s.client.RegisterMultiSig(
		ctx, &pb.RegisterMultiSigRequest{
			WalletDescriptor: descriptor,
		},
	)
	return err
}

func (s *service) SignTx(ctx context.Context, tx string) (string, error) {
	resp, err := s.client.SignTransaction(ctx, &pb.SignTransactionRequest{
		Tx: tx,
	},
	)
	if err != nil {
		return "", err
	}
	return resp.GetSignedTx(), nil
}
