package server

import (
	"context"
	"fmt"
	"log"
	"net"

	mb "daad/protos/master"

	"google.golang.org/grpc"
    "bufio"
  	"crypto/rsa"
   	"crypto/rand"
    "crypto/x509"
	"crypto/sha256"
    "encoding/pem"
    "os"

	"strconv"

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

	//encrypt the message with public key of Commit Server and make it msg id

	publicKeyFile, err := os.Open("/home/hrishabh/go/src/daad/pkiCommit/public_key.pem")
	if err != nil {
    fmt.Println(err)
    os.Exit(1)
	}


	pemfileinfoPublic, _ := publicKeyFile.Stat()
	var sizePublic int64 = pemfileinfoPublic.Size()
	pembytesPublic := make([]byte, sizePublic)
	bufferPublic := bufio.NewReader(publicKeyFile)
	_, err = bufferPublic.Read(pembytesPublic)
	dataPublic, _ := pem.Decode([]byte(pembytesPublic))
	publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKCS1PublicKey(dataPublic.Bytes)
	if err != nil {
	    fmt.Println(err)
	    os.Exit(1)
	}
	// log.Println("Public Key : ", publicKeyImported)



	message := []byte(vrequest.Msg)
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(
    hash, 
    rand.Reader, 
    publicKeyImported, 
    message, 
    label,
	)
	if err != nil {
    fmt.Println(err)
    os.Exit(1)
	}

	id,err := strconv.ParseInt(string(ciphertext),10,64)	

	return &mb.ValidationResponse{
		Msg:         vrequest.Msg,
		MsgId:       id,
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
