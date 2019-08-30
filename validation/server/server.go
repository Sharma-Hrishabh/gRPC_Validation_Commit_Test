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

	"reflect"

)

// struct to maintain the state
type validationServer struct {
}

// Get a new instance of validationServer
func NewValidationServer() *validationServer {
	return &validationServer{}
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







// Implementation of the ValidationServer.SubmitRequest() RPC call
func (vs *validationServer) SubmitRequest(ctx context.Context, vrequest *mb.ValidationRequest) (*mb.ValidationResponse, error) {
	// DO NOT CHANGE THIS PRINTF STATEMENT
	log.Printf("Validated [MSGID:%d, MSG:%s]", vrequest.MsgId, vrequest.Msg)

	//encrypt the message with public key of Commit Server and make it msg id

	// privateKeyFile, err := os.Open("/home/hrishabh/go/src/daad/pkiValidator/private_key.pem")
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



	// var opts rsa.PSSOptions
	// opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	// PSSmessage := []byte(vrequest.Msg)
	// newhash := crypto.SHA256
	// pssh := newhash.New()
	// pssh.Write(PSSmessage)
	// hashed := pssh.Sum(nil)
	// signature, err := rsa.SignPSS(
	//     rand.Reader, 
	//     privateKeyImported, 
	//     newhash, 
	//     hashed, 
	//     &opts,
	// )
	// if err != nil {
	//     fmt.Println(err)
	//     os.Exit(1)
	// }
	// fmt.Printf("PSS Signature : %x\n", signature)
	// // sig := string([]byte(signature[:]))
	// sig := BytesToString(signature)
	// // sig := string(signature)
	// fmt.Printf("PSS Signature : %s\n", reflect.TypeOf(sig))
	// fmt.Printf("PSS Signature : %s\n", sig)
	// newStr := []uint8(sig)
	// fmt.Println("*********************")
	// fmt.Printf("PSS Signature : %x\n", newStr)




	signer, err := loadPrivateKey("private.pem")
	if err != nil {
		fmt.Errorf("signer is damaged: %v", err)
	}

	toSign := vrequest.Msg

	signed, err := signer.Sign([]byte(toSign))
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(signed)
	fmt.Printf("Signature: %v\n", sig)


	fmt.Println(reflect.TypeOf(signed))
	fmt.Println(signed)

	// parser, perr := loadPublicKey("public.pem")
	// if perr != nil {
	// 	fmt.Errorf("could not sign request: %v", err)
	// }
	
	// err = parser.Unsign([]byte(toSign), signed)
	// if err != nil {
	// 	fmt.Errorf("could not sign request: %v", err)
	// }
	
	// fmt.Printf("Unsign error: %v\n", err)



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
