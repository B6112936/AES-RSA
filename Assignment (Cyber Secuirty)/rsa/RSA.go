package main

import (
	"log"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
)
//////////////////
type Client struct {
	PrivateKey *rsa.PrivateKey
	PublicKeys map[string]*rsa.PublicKey
}

func New(privateKey []byte, publicKeys map[string][]byte) (client *Client, err error) {
	client = &Client{}

	if privateKey != nil {
		validPrivateKey, errPrivate := x509.ParsePKCS1PrivateKey(privateKey)
		if errPrivate != nil {
			err = errPrivate
			log.Println(err)
			return
		}
		client.PrivateKey = validPrivateKey
	}

	if publicKeys != nil {
		validPublicKeysMap := make(map[string]*rsa.PublicKey)
		for k, v := range publicKeys {
			validPublicKey, errPublic := x509.ParsePKIXPublicKey(v)
			if errPublic != nil {
				err = errPublic
				log.Println(err)
				return
			}
			switch validPublicKey := validPublicKey.(type) {
			case *rsa.PublicKey:
				validPublicKeysMap[k] = validPublicKey
			default:
				err = errors.New("Invalid Public Key Type")
				log.Println(err)
				return
			}
		}
		client.PublicKeys = validPublicKeysMap
	}

	return
}
/////////////////////////////
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	pubKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Println(err)
		return
	}
	privKey := &pubKey.PublicKey

	privateKey = x509.MarshalPKCS1PrivateKey(pubKey)
	publicKey, err = x509.MarshalPKIXPublicKey(privKey)
	if err != nil {
		log.Println(err)
	}
	return
}
/////////////////////////////////
func SignDefault(plaintext, privateKey []byte) (signature string, err error) {
	client, err := New(privateKey, nil)
	if err != nil {
		log.Println(err)
		return
	}
	signatureByte, err := client.Sign(plaintext)
	if err != nil {
		log.Println(err)
		return
	}
	signature = base64.StdEncoding.EncodeToString(signatureByte)
	return
}
////////////////////////////////////////
func (c *Client) Sign(plaintext []byte) (signature []byte, err error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(plaintext)
	hashed := pssh.Sum(nil)
	signature, err = rsa.SignPSS(
		rand.Reader,
		c.PrivateKey,
		newhash,
		hashed,
		&opts,
	)
	return
}
////////////////////
func VerifyDefault(plaintext, publicKey []byte, signature string) (err error) {
	publicKeys := make(map[string][]byte)
	publicKeys["default"] = publicKey
	client, err := New(nil, publicKeys)
	if err != nil {
		log.Println(err)
		return
	}

	signatureByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Println(err)
		return
	}

	err = client.Verify(plaintext, signatureByte, "default")
	if err != nil {
		log.Println(err)
		return
	}
	return
}
/////////////////////////////////////
func (c *Client) Verify(plaintext, signature []byte, target string) (err error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(plaintext)
	hashed := pssh.Sum(nil)
	err = rsa.VerifyPSS(
		c.PublicKeys[target],
		newhash,
		hashed,
		signature,
		&opts,
	)
	return
}
/////////////////////////
func ReadFile(filename string) (content []byte) {
	filepath := fmt.Sprintf("%s", filename)
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatal(err.Error())
	}
	return
}
/////////////////
func main() {
	
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		log.Fatalln(err)
	}

	
	plaintext := ReadFile("encrypted-text.txt")
	log.Printf("plaintext : %s\n\n", string(plaintext))

	
	log.Println("creating signature...")
	signature, err := SignDefault(plaintext, privateKey)
	
	if err != nil {
		log.Fatalln(err)
	} else {
		log.Printf("signature : %s\n\n", string(signature))
	}

	
	log.Println("verifying signature and plaintext...")
	errVerify := VerifyDefault(plaintext, publicKey, signature)
	if errVerify != nil {
		log.Fatalln(errVerify)
	} else {
		log.Println("verification success!")
	}

}
