package manager

import (
	"context"

	pb "github.com/deislabs/ratify/experimental/proto/v2/verifier"
	"github.com/sirupsen/logrus"
)

type VerifierServer struct {
	pb.UnimplementedVerifierPluginServer
}

func (v *VerifierServer) VerifyReference(context.Context, *pb.VerifyReferenceRequest) (*pb.VerifyReferenceResponse, error) {
	logrus.Info("hi, this is susan from notary grpc impl")
	test := pb.VerifyReferenceResponse{
		Subject: "SusanSub",
	}
	return &test, nil
}
