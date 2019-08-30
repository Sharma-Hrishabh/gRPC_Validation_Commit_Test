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
	// "crypto/sha256"
    "encoding/pem"
    "os"
	"crypto/sha512"
   	"strconv"
)

// struct to maintain the state
type commitServer struct {
}

// Get a new instance of commitServer
func NewCommitServer() *commitServer {
	return &commitServer{}
}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		// log.Error(err)
	}
	return ciphertext
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		// log.Error(err)
	}
	return plaintext
} 


// Implementation of the CommitServer.SubmitRequest() RPC call
func (vs *commitServer) SubmitRequest(ctx context.Context, crequest *mb.ValidationResponse) (*mb.CommitResponse, error) {
	// DO NOT CHANGE THIS PRINTF STATEMENT

	log.Printf("Committed[MSGID:%d, MSG:%s]", crequest.MsgId, crequest.Msg)

	// INSERT CODE HERE

	//loading private key

	privateKeyFile, err := os.Open("/home/hrishabh/go/src/daad/pkiCommit/private_key.pem")
	if err != nil {
	    fmt.Println(err)
	    os.Exit(1)
	}


	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
	    fmt.Println(err)
	    os.Exit(1)
	}
	// log.Println("Private Key : ", privateKeyImported)

	//decrypt the message

	ciphertext := []byte(strconv.Itoa(int(crequest.MsgId)))
	// label := []byte("")
	// hash := sha256.New()

	// plainText, err := rsa.DecryptOAEP(
 //    hash, 
 //    rand.Reader, 
 //    privateKeyImported, 
 //    ciphertext, 
 //    label,
	// )
	// if err != nil {
 //    fmt.Println(err)
 //    os.Exit(1)
	// }


	plainText := DecryptWithPrivateKey(ciphertext,privateKeyImported)

	//compare plaintext with message
	if string(plainText) != crequest.Msg {

	log.Println("Not commited")
	return &mb.CommitResponse{
	ReturnValue: mb.CommitResponse_FAILURE,
	}, nil

	}	

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
