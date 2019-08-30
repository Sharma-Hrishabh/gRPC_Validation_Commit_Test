package server

import (
	"context"
	"fmt"
	"log"
	"net"

	mb "daad/protos/master"
	"crypto"
	"google.golang.org/grpc"
    "bufio"
  	"crypto/rsa"
   	"crypto/rand"
    "crypto/x509"
	// "crypto/sha256"
    "encoding/pem"
    "os"
    "reflect"
	// "strconv"
	"unsafe"
	// "bytes"

)

// struct to maintain the state
type validationServer struct {
}

// Get a new instance of validationServer
func NewValidationServer() *validationServer {
	return &validationServer{}
}

func BytesToString(b []byte) string {
    bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
    sh := reflect.StringHeader{bh.Data, bh.Len}
    return *(*string)(unsafe.Pointer(&sh))
}


// Implementation of the ValidationServer.SubmitRequest() RPC call
func (vs *validationServer) SubmitRequest(ctx context.Context, vrequest *mb.ValidationRequest) (*mb.ValidationResponse, error) {
	// DO NOT CHANGE THIS PRINTF STATEMENT
	log.Printf("Validated [MSGID:%d, MSG:%s]", vrequest.MsgId, vrequest.Msg)

	//encrypt the message with public key of Commit Server and make it msg id

	privateKeyFile, err := os.Open("/home/hrishabh/go/src/daad/pkiValidator/private_key.pem")
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



	// message := []byte(vrequest.Msg)
	// label := []byte("")
	// hash := sha256.New()
	// ciphertext, err := rsa.EncryptOAEP(
 //    hash, 
 //    rand.Reader, 
 //    publicKeyImported, 
 //    message, 
 //    label,
	// )
	// if err != nil {
 //    fmt.Println(err)
 //    os.Exit(1)
	// }

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := []byte(vrequest.Msg)
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)
	signature, err := rsa.SignPSS(
	    rand.Reader, 
	    privateKeyImported, 
	    newhash, 
	    hashed, 
	    &opts,
	)
	if err != nil {
	    fmt.Println(err)
	    os.Exit(1)
	}
	fmt.Printf("PSS Signature : %x\n", signature)
	// sig := string([]byte(signature[:]))
	sig := BytesToString(signature)
	// sig := string(signature)
	fmt.Printf("PSS Signature : %s\n", reflect.TypeOf(sig))
	fmt.Printf("PSS Signature : %s\n", sig)
	newStr := []uint8(sig)
	fmt.Println("*********************")
	fmt.Printf("PSS Signature : %x\n", newStr)


	return &mb.ValidationResponse{
		Msg:         sig,
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
