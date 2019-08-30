package server

import (
	"context"
	"fmt"
	"log"
	"net"

	mb "daad/protos/master"

	"google.golang.org/grpc"
)

// struct to maintain the state
type validationServer struct {
}

// Get a new instance of validationServer
func NewValidationServer() *validationServer {
	return &validationServer{}
}

// Implementation of the ValidationServer.SubmitRequest() RPC call
func (vs *validationServer) SubmitRequest(ctx context.Context, vrequest *mb.ValidationRequest) (*mb.ValidationResponse, error) {
	// DO NOT CHANGE THIS PRINTF STATEMENT
	log.Printf("Validated [MSGID:%d, MSG:%s]", vrequest.MsgId, vrequest.Msg)


	return &mb.ValidationResponse{
		Msg:         vrequest.Msg,
		MsgId:       vrequest.MsgId,
		ReturnValue: mb.ValidationResponse_SUCCESS,
	}, nil
}

func Main(host string, port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))

	if err != nil {
		log.Fatalf("Failed to listen to port: %d, on host: %s", port, host)
	}

	// server option TLS or no TLS
	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)

	vServer := NewValidationServer()

	mb.RegisterValidationServer(grpcServer, vServer)

	log.Printf("Started validation server on port:%d, host:%s", port, host)
	grpcServer.Serve(lis)
}
