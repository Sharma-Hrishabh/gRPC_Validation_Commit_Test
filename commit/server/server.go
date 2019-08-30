package server

import (
	"context"
	"fmt"
	"log"
	"net"

	mb "daad/protos/master"

	"google.golang.org/grpc"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

// struct to maintain the state
type commitServer struct {
}

// Get a new instance of commitServer
func NewCommitServer() *commitServer {
	return &commitServer{}
}









// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPublicKey(path string) (Unsigner, error) {

	return parsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`))
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return newUnsignerFromKey(rawkey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	return parsePrivateKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`))
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data[]byte, sig []byte) error
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

// Unsign verifies the message using a rsa-sha256 signature
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}








// Implementation of the CommitServer.SubmitRequest() RPC call
func (vs *commitServer) SubmitRequest(ctx context.Context, crequest *mb.ValidationResponse) (*mb.CommitResponse, error) {
	// DO NOT CHANGE THIS PRINTF STATEMENT

	log.Printf("Committed[MSGID:%d, MSG:%s]", crequest.MsgId, crequest.Msg)

	// INSERT CODE HERE

	//loading private key

	// privateKeyFile, err := os.Open("/home/hrishabh/go/src/daad/pkiCommit/private_key.pem")
	// if err != nil {
	//     fmt.Println(err)
	//     os.Exit(1)
	// }


	// pemfileinfo, _ := privateKeyFile.Stat()
	// var size int64 = pemfileinfo.Size()
	// pembytes := make([]byte, size)
	// buffer := bufio.NewReader(privateKeyFile)
	// _, err = buffer.Read(pembytes)
	// data, _ := pem.Decode([]byte(pembytes))
	// privateKeyFile.Close()

	// privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	// if err != nil {
	//     fmt.Println(err)
	//     os.Exit(1)
	// }
	// log.Println("Private Key : ", privateKeyImported)

	//decrypt the message

	// ciphertext := []byte(strconv.Itoa(int(crequest.MsgId)))
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


	// plainText := DecryptWithPrivateKey(ciphertext,privateKeyImported)

	// //compare plaintext with message
	// if string(plainText) != crequest.Msg {

	// log.Println("Not commited")
	// return &mb.CommitResponse{
	// ReturnValue: mb.CommitResponse_FAILURE,
	// }, nil

	// }	


	// toSign := "Sample message"


	parser, perr := loadPublicKey("public.pem")
	if perr != nil {
		// fmt.Errorf("could not sign request: %v", err)
	}
	
	// fmt.Println([]uint8(toSign))

	response := crequest.Msg
	r := strings.Split(response," ")
	signedMsg,toSign := r[0],r[1]

	fmt.Println("$$$$$$")

	fmt.Println(signedMsg)
	fmt.Println(toSign)
	fmt.Println("$$$$$$")

  	signed, err := base64.StdEncoding.DecodeString(signedMsg)
  	toSignDecoded, err := base64.StdEncoding.DecodeString(toSign)

  	log.Println("***********")
	log.Println(signed)

	
	err = parser.Unsign(toSignDecoded,signed)
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)

		fmt.Println("Fail")
			return &mb.CommitResponse{
		ReturnValue: mb.CommitResponse_FAILURE,
	}, nil

	}
	
	fmt.Printf("Unsign error: %v\n", err)

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
