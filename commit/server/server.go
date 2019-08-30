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
type commitServer struct {
}

// Get a new instance of commitServer
func NewCommitServer() *commitServer {
	return &commitServer{}
}

// Implementation of the CommitServer.SubmitRequest() RPC call
func (vs *commitServer) SubmitRequest(ctx context.Context, crequest *mb.ValidationResponse) (*mb.CommitResponse, error) {
	// DO NOT CHANGE THIS PRINTF STATEMENT

	log.Println(crequest.ReturnValue)
	log.Printf("Committed[MSGID:%d, MSG:%s]", crequest.MsgId, crequest.Msg)

	// INSERT CODE HERE


	return &mb.CommitResponse{
		ReturnValue: mb.CommitResponse_SUCCESS,
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

	vServer := NewCommitServer()

	mb.RegisterCommitServer(grpcServer, vServer)

	log.Printf("Started commit server on port:%d, host:%s", port, host)
	grpcServer.Serve(lis)
}
