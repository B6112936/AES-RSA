package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	mathRand "math/rand"
	"time"
	
	"fmt"
	"io/ioutil"
	"log"
)
/////////////////////////////////////////////////
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

type Client struct{}

func NewClient() (c *Client) {
	mathRand.Seed(time.Now().UnixNano())
	c = &Client{}
	return
}

func (c *Client) EncryptAES(plainData, secret []byte) (cipherData []byte) {
	block, _ := aes.NewCipher(secret)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())    //////  IV  RANDOM ///////
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}

	cipherData = gcm.Seal(
		nonce,
		nonce,
		plainData,
		nil)

	return
}

func (c *Client) DecryptAES(cipherData, secret []byte) (plainData []byte) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()

	nonce, ciphertext := cipherData[:nonceSize], cipherData[nonceSize:]
	plainData, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}
	return
}

func (c *Client) GenerateRandomString(length int) (result string) {
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[mathRand.Intn(len(letterBytes))]
	}
	result = string(b)
	return
}
///////////////////////////////////////////////////
func ReadFile(filename string) (content []byte) {
	filepath := fmt.Sprintf("%s", filename)
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatal(err.Error())
	}
	return
}

func WriteFile(content []byte, filename string) (err error) {
	filepath := fmt.Sprintf("%s", filename)

	err = ioutil.WriteFile(filepath, content, 0644)
	if err != nil {
		return
	}
	return
}






////////////////////////////////////////////////////////
func ntext()  {
	// encryption start
	// step 1
	text := ReadFile("text.txt")
	// step 2
	encryptionClient := NewClient()
	secret := encryptionClient.GenerateRandomString(32)

	// step 3
	ciphertext := encryptionClient.EncryptAES(text, []byte(secret))

	// step 4
	err := WriteFile(ciphertext, "encrypted-text.txt")
	if err != nil {
		log.Fatalln(err)
	}
	err = WriteFile([]byte(secret), "text-keyT.txt")
	if err != nil {
		log.Fatalln(err)
	}
	// encryption end

	// decryption start
	// 1
	encryptedText := ReadFile("encrypted-text.txt")

	// 2
	key := ReadFile("text-keyT.txt")

	// 3
	plaintext := encryptionClient.DecryptAES(encryptedText, key)
	err = WriteFile(plaintext, "originalText.txt")
	if err != nil {
		log.Fatalln(err)
	}
	// decryption end
}
/////////////////////////////////
func nimg()  {
	// encryption start
	// step 1
	image := ReadFile("NW8.png")
	// step 2
	encryptionClient := NewClient()
	secret := encryptionClient.GenerateRandomString(32)

	// step 3
	cipherImage := encryptionClient.EncryptAES(image, []byte(secret))

	// step 4
	err := WriteFile(cipherImage, "encrypted-img.png")
	if err != nil {
		log.Fatalln(err)
	}
	err = WriteFile([]byte(secret), "image-keyI.txt")
	if err != nil {
		log.Fatalln(err)
	}
	// encryption end

	// decryption start
	// 1
	encryptedImage := ReadFile("encrypted-img.png")

	// 2
	key := ReadFile("image-keyI.txt")

	// 3
	plainImage := encryptionClient.DecryptAES(encryptedImage, key)
	err = WriteFile(plainImage, "originalImg.png")
	if err != nil {
		log.Fatalln(err)
	}
	// decryption end
}
////////////////////////////////////////////

func main() {
	ntext()
	nimg()
}