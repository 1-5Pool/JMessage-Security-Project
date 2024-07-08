package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	//"io/ioutil"
	//"log"
	"gitlab.com/yawning/chacha20.git"
)

// Globals

var (
	serverPort          int
	serverDomain        string
	serverDomainAndPort string
	serverProtocol      string
	noTLS               bool
	strictTLS           bool
	username            string
	password            string
	apiKey              string
	doUserRegister      bool
	headlessMode        bool
	messageIDCounter    int
	attachmentsDir      string
	globalPubKey        PubKeyStruct
	globalPrivKey       PrivKeyStruct
	attack              string
	victim              string
)

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	decrypted string
	url       string
	localPath string
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the POST request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Do a GET request and return the result
func doGetRequest(getURL string) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the GET request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Upload a file to the server
func uploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
		username + "/" + apiKey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func downloadFileFromServer(geturl string, localPath string) error {
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("Bad result code")
	}

	// Create the file
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func serverLogin(username string, password string) (string, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("Bad result code")
	}

	// Parse JSON into an APIKey struct
	var result APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Log in to server
func getPublicKeyFromServer(forUser string) (*PubKeyStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an PubKeyStruct
	var result PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Register username with the server
func registerUserWithServer(username string, password string) error {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := doGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Get messages from the server
func getMessagesFromServer(globalPriv1 PrivKeyStruct) ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption

	decryptMessages(result, globalPriv1)

	return result, nil
}

func getMessagesFromServer1(globalPriv1 PrivKeyStruct, username string) ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption

	decryptMessages(result, globalPriv1)

	return result, nil
}

// Get messages from the server
func getUserListFromServer() ([]UserStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []UserStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

// Post a message to the server
func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	messageIDCounter++
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Post a message to the server copied!
func sendMessageToServer1(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		sender + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	messageIDCounter++
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the serve
func doReadAndSendMessage(recipient string, messageBody string, globalPriv1 PrivKeyStruct) error {

	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading == true {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	encryptedMessage := encryptMessage([]byte(messageBody), username, pubkey, globalPriv1)

	// Check if the "cipher.txt" file exists and delete it
	if _, err := os.Stat("cipher.txt"); err == nil {
		err := os.Remove("cipher.txt")
		if err != nil {
			fmt.Println("Error deleting existing file:", err)
			return err
		}
	}
	// Save the ciphertext to a file named "cipher.txt"
	file, err := os.Create("cipher.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return err
	}
	defer file.Close()

	_, err = file.WriteString(string(encryptedMessage))
	if err != nil {
		fmt.Println("Error writing to file:", err)
	}
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func getKeyFromServer(user_key string) {
	geturl := serverProtocol + "://" + serverDomain + ":" + strconv.Itoa(serverPort) + "/lookupKey?" + user_key

	fmt.Println(geturl)
}

func FixCRC(c2Ciphertext []byte, XoringB []byte) []byte {

	modifiedCiphertext := make([]byte, len(c2Ciphertext))

	copy(modifiedCiphertext, c2Ciphertext)

	//XOR modifiedCiphertext except the last 4 bytes with XOringB

	// XOR modifiedCiphertext except the last 4 bytes with XoringB
	for i := 0; i < len(modifiedCiphertext)-4; i++ {
		modifiedCiphertext[i] ^= XoringB[i]
	}

	// Calculate the CRC32 checksum of the original plaintext CRC(A)
	crc32Original := binary.BigEndian.Uint32(c2Ciphertext[len(c2Ciphertext)-4:])

	// Calculate the CRC32 checksum of the modifiemodifiedc2d ciphertext CRC(B)

	crc32Modified := crc32.ChecksumIEEE(XoringB)

	// CRC(0) checksum

	hex := make([]byte, len(c2Ciphertext)-4)
	for i := range hex {
		hex[i] = 0x00
	}

	checksum_zero := crc32.ChecksumIEEE(hex)

	// XOR the original CRC32 checksum with the modified CRC32 checksum CRC(0) XOR CRC(A) COR CRC(B)
	crc32New := crc32Original ^ crc32Modified ^ checksum_zero

	// Update the last 4 bytes of the modified ciphertext with the new CRC32 checksum
	binary.BigEndian.PutUint32(modifiedCiphertext[len(modifiedCiphertext)-4:], crc32New)

	return modifiedCiphertext
}

func performAttack(ciphertext CiphertextStruct, victimUsername string, username string, privKey PrivKeyStruct) string {
	//Victim2
	SenderUsername := "charlie"
	// Decode the C2 component from base64
	c2Bytes, err := base64.StdEncoding.DecodeString(ciphertext.C2)
	if err != nil {
		fmt.Printf("Failed to decode C2: %v\n", err)
		return ""
	}

	ciphertextLength := len(c2Bytes)

	// Create a slice to store the decrypted plaintext
	plaintext := make([]byte, ciphertextLength-4-len(SenderUsername)-1)

	//Xoring B and initiate to 0
	XoringB := make([]byte, ciphertextLength-4)

	for i := range XoringB {
		XoringB[i] = 0x00
	}

	// maSenderUsernameke delimiter to a
	XoringB[len(SenderUsername)] = 0x5B

	//Index to bruteforce

	// Bruteforce the current character by XORing with 2^7 bits
	modifiedCiphertext := make([]byte, ciphertextLength)
	for i := 0; i < len(plaintext); i++ {
		fmt.Println("Attacking ciphertext......")
		forceI := len(SenderUsername) + 1 + i
		for j := 0; j < 128; j++ {
			fmt.Print(".")
			copy(modifiedCiphertext, c2Bytes)
			XoringB[forceI] = byte(j)

			//Fixcrc
			modifiedCiphertext = FixCRC(modifiedCiphertext, XoringB)

			// Encode the modified ciphertext back to base64
			modifiedC2 := base64.StdEncoding.EncodeToString(modifiedCiphertext)

			// Create a new replay with the modified C2
			replay := ciphertext
			replay.C2 = modifiedC2

			// Sign the modified ciphertext using Mallory's private key
			replay.Sig = signMessage(replay, privKey)

			// Send the modified ciphertext to Alice
			jsonMessage, err := json.Marshal(replay)
			if err != nil {
				fmt.Printf("Failed to marshal modified ciphertext: %v\n", err)
				continue
			}

			err = sendMessageToServer1(username, victimUsername, jsonMessage, 0)
			if err != nil {
				fmt.Printf("Failed to send message to Alice: %v, sending message to this username %s \n", err, username)
				continue
			}

			// Wait for a short duration (e.g., 100ms) to allow Alice to process the message
			time.Sleep(300 * time.Millisecond)

			// Check if a read receipt was received from Alice
			messageList, err := getMessagesFromServer1(privKey, username)
			if err != nil {
				fmt.Printf("Failed to retrieve messages: %v\n", err)
				continue
			}

			readReceiptReceived := false
			for _, message := range messageList {
				if message.ReceiptID != 0 && message.From == victimUsername {
					readReceiptReceived = true
					fmt.Println("Got a Read Reciept for this j value", j)
					break
				}
			}

			if readReceiptReceived {
				// The current character decrypted to 0x3A (':')
				plaintext[i] = byte(j) ^ 0x3A
				fmt.Println("Found PLaintext: ", string(plaintext[i]))
				XoringB[forceI] = plaintext[i] ^ 0x61
				break
			}
		}
		// Increasing the size of the username by an additional character
		username = username + "a"
		fmt.Println("New username", username)
		apiKey := ""
		privKey, apiKey = Reregister(username)
		_ = apiKey
	}

	return string(plaintext)
}

// Upload a new public key to the server
func registerPublicKeyWithServer(username string, pubKeyEncoded PubKeyStruct) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
		username + "/" + apiKey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns the HEX encoded key
// and file hash, or an error.
func encryptAttachment(plaintextFilePath string) (string, string, error) {
	// Read the plaintext file contents
	plaintextData, err := ioutil.ReadFile(plaintextFilePath)
	if err != nil {
		return "", "", err
	}

	// Generate a random 256-bit ChaCha20 key
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		return "", "", err
	}

	// Create a new ChaCha20 cipher with the key and zero nonce
	var nonce [chacha20.NonceSize]byte
	cipher, err := chacha20.New(key, nonce[:])
	if err != nil {
		return "", "", err
	}

	// Encrypt the file contents
	encryptedData := make([]byte, len(plaintextData))
	cipher.XORKeyStream(encryptedData, plaintextData)

	// Calculate the SHA256 hash of the encrypted file
	hash := sha256.Sum256(encryptedData)
	hashStr := hex.EncodeToString(hash[:])

	// Encode the key as base64
	keyStr := base64.StdEncoding.EncodeToString(key)

	// Create a new file with the ".enc" extension to store the encrypted data
	encryptedFilePath := plaintextFilePath + ".enc"
	err = ioutil.WriteFile(encryptedFilePath, encryptedData, 0644)
	if err != nil {
		return "", "", err
	}

	return keyStr, hashStr, nil
}
func decodePrivateSigningKey(privKey PrivKeyStruct) (*ecdsa.PrivateKey, error) {
	sigSKBytes, err := base64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private signing key: %v", err)
	}

	sigSK, err := x509.ParsePKCS8PrivateKey(sigSKBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private signing key: %v", err)
	}

	ecdsaPrivateKey, ok := sigSK.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key format")
	}

	return ecdsaPrivateKey, nil
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	// TODO: IMPLEMENT
	hasher := sha256.New()
	hasher.Write([]byte(message))
	hash := hasher.Sum(nil)

	_ = hash

	// Decode privkey
	signkey := privKey.SigSK
	signkeyBase64, err := base64.StdEncoding.DecodeString(signkey)
	if err != nil {
		log.Fatalf("Failed to decode BASE64: %v", err)
	}
	_ = signkeyBase64
	return nil
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
	var ciphertext CiphertextStruct

	decodedPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("base64 decode error")
		return nil, err
	}
	err = json.Unmarshal(decodedPayload, &ciphertext)
	if err != nil {
		fmt.Println("Unmarshall error")
		return nil, err
	}

	// Verify the signature
	toVerify := ciphertext.C1 + ciphertext.C2
	sigPKBytes, _ := base64.StdEncoding.DecodeString(senderPubKey.SigPK)
	sigPK, err := x509.ParsePKIXPublicKey(sigPKBytes)
	if err != nil {
		fmt.Println("ParsePKIXPublicKey")
		return nil, err
	}
	sigPKECDSA := sigPK.(*ecdsa.PublicKey)
	signature, _ := base64.StdEncoding.DecodeString(ciphertext.Sig)
	hash := sha256.Sum256([]byte(toVerify))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(sigPKECDSA, hash[:], r, s) {
		return nil, errors.New("signature verification failed")
	}

	// Decrypt C1 to obtain the shared secret K
	encSKBytes, _ := base64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	encSK, err := x509.ParsePKCS8PrivateKey(encSKBytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey")
		return nil, err
	}
	encSKECDSA := encSK.(*ecdsa.PrivateKey)
	C1Bytes, _ := base64.StdEncoding.DecodeString(ciphertext.C1)

	pubKeyInterface, err := x509.ParsePKIXPublicKey(C1Bytes)
	if err != nil {
		return nil, errors.New("invalid parsing error")
	}
	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not a ECSSA pubkic key")
	}
	sskX, _ := encSKECDSA.Curve.ScalarMult(pubKey.X, pubKey.Y, encSKECDSA.D.Bytes())
	K := sha256.Sum256(sskX.Bytes())
	// Decrypt C2 using the shared secret K
	C2Bytes, _ := base64.StdEncoding.DecodeString(ciphertext.C2)
	var nonce [chacha20.NonceSize]byte
	cipher, err := chacha20.New(K[:], nonce[:])
	if err != nil {
		return nil, err
	}
	decryptedBytes := make([]byte, len(C2Bytes))
	cipher.XORKeyStream(decryptedBytes, C2Bytes)

	// Verify the integrity of the plaintext message
	delimiterIndex := bytes.IndexByte(decryptedBytes[:len(decryptedBytes)-4], 0x3A)
	if delimiterIndex == -1 {
		return nil, errors.New("invalid plaintext format")
	}
	username := string(decryptedBytes[:delimiterIndex])
	plaintext := decryptedBytes[delimiterIndex+1 : len(decryptedBytes)-4]
	checksum := binary.BigEndian.Uint32(decryptedBytes[len(decryptedBytes)-4:])
	expectedChecksum := crc32.ChecksumIEEE(decryptedBytes[:len(decryptedBytes)-4])
	if checksum != expectedChecksum {
		return nil, errors.New("checksum verification failed")
	}

	// Check if the sender's username matches the expected username
	if username != senderUsername {
		return nil, errors.New("sender username mismatch")
	}

	return plaintext, nil
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct, globalPriv1 PrivKeyStruct) []byte {

	encPK := pubkey.EncPK
	// BASE64 decode the string to get the DER-encoded public key
	derEncodedPubKey, err := base64.StdEncoding.DecodeString(encPK)
	if err != nil {
		log.Fatalf("Failed to decode BASE64: %v", err)
	}
	// Parse the DER-encoded public key
	pubKeyInterface, err := x509.ParsePKIXPublicKey(derEncodedPubKey)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	// Assert the type to *ecdsa.PublicKey to get the public key in usable form
	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Not an ECDSA public key")
	}

	// Check if the curve is P-256

	if pubKey.Curve != elliptic.P256() {
		log.Fatalf("Public key is not on P-256 curve")
	}
	// generater a random scarler c
	c, err := rand.Int(rand.Reader, pubKey.Params().N)
	if err != nil {
		fmt.Println("Error someting!", err)
	}
	//compute epk = cP
	epkX, epkY := pubKey.Curve.ScalarBaseMult(c.Bytes())
	//ssk
	sskX, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, c.Bytes())
	// compute hash of k
	K := sha256.Sum256((sskX.Bytes()))
	//Computing C1 now - not doing parsing here again TODO
	epkPublicKey := &ecdsa.PublicKey{
		Curve: pubKey.Curve,
		X:     epkX,
		Y:     epkY,
	}
	epkBytes, err := x509.MarshalPKIXPublicKey(epkPublicKey)
	if err != nil {
		log.Fatalf("Failed to encode: %v", err)
	}

	// Base64-encode
	C1 := base64.StdEncoding.EncodeToString(epkBytes)

	//Computing C2 now:
	senderBytes := []byte(senderUsername)
	delimiter := []byte{0x3A}
	MPrime := append(senderBytes, delimiter...)
	MPrime = append(MPrime, message...)

	// Compute CHECK
	checksum := crc32.ChecksumIEEE(MPrime)
	checksumBytes := []byte{byte(checksum >> 24), byte(checksum >> 16), byte(checksum >> 8), byte(checksum)}
	MDoublePrime := append(MPrime, checksumBytes...)

	var nonce [chacha20.NonceSize]byte // Zero nonce
	cipher, err := chacha20.New(K[:], nonce[:])
	if err != nil {
		log.Fatalf("Failed to create ChaCha20 cipher: %v", err)
	}

	encryptedMDoublePrime := make([]byte, len(MDoublePrime))
	cipher.XORKeyStream(encryptedMDoublePrime, MDoublePrime)
	// C2 is the BASE64-encoded encrypted M''
	C2 := base64.StdEncoding.EncodeToString(encryptedMDoublePrime)

	// Signature

	toSign := C1 + C2

	// Decode the sender's private signing key
	sigSKBytes, _ := base64.StdEncoding.DecodeString(globalPriv1.SigSK)
	sigSK, err := x509.ParsePKCS8PrivateKey(sigSKBytes)
	if err != nil {
		log.Fatalf("Failed to parse SigSK cipher: %v", err)
	}
	signSk1, ok := sigSK.(*ecdsa.PrivateKey)
	if !ok {
		return nil
	}
	// Sign toSign using ECDSA
	hasher := sha256.New()
	hasher.Write([]byte(toSign))
	hash := hasher.Sum(nil)
	r, s, _ := ecdsa.Sign(rand.Reader, signSk1, hash)
	signature := append(r.Bytes(), s.Bytes()...)

	// Encode signature into Sig
	Sig := base64.StdEncoding.EncodeToString(signature)

	// Construct the final ciphertext payload
	payload := CiphertextStruct{C1, C2, Sig}
	payloadBytes, _ := json.Marshal(payload)

	return payloadBytes
}

// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct, globalPriv1 PrivKeyStruct) {

	for i := range messageArray {
		message := &messageArray[i]
		if message.ReceiptID != 0 {
			// Skip read receipt messages
			continue
		}
		senderPubKey, err := getPublicKeyFromServer(message.From)
		if err != nil {
			fmt.Printf("Failed to retrieve public key for sender %s: %v\n", message.From, err)
			continue
		}
		decryptedMessage, err := decryptMessage(message.Payload, message.From, senderPubKey, &globalPriv1)
		if err != nil {
			fmt.Printf("Failed to decrypt message from %s: %v\n", message.From, err)
			continue
		}
		//Check if the decrypted message contains an attachment
		if strings.HasPrefix(string(decryptedMessage), ">>>MSGURL=") {
			parts := strings.Split(string(decryptedMessage), "?")
			if len(parts) == 3 {
				message.url = parts[0][10:]
				keyPart := parts[1]
				hashPart := parts[2]
				if strings.HasPrefix(keyPart, "KEY=") && strings.HasPrefix(hashPart, "H=") {
					key := keyPart[4:]
					expectedHash := hashPart[2:]

					// Download the attachment file
					localPath := getTempFilePath()
					err := downloadFileFromServer(message.url, localPath)
					if err != nil {
						fmt.Printf("Failed to download attachment from %s: %v\n", message.url, err)
						continue
					}

					// Verify the hash of the downloaded file
					fileHash, err := calculateFileHash(localPath)
					if err != nil {
						fmt.Printf("Failed to calculate hash of the downloaded file: %v\n", err)
						continue
					}
					if fileHash != expectedHash {
						fmt.Printf("Hash verification failed for the downloaded file\n")
						continue
					}

					// Decrypt the attachment file
					decryptedFilePath := getTempFilePath()
					err = decryptAttachmentFile(localPath, decryptedFilePath, key)
					if err != nil {
						fmt.Printf("Failed to decrypt the attachment file: %v\n", err)
						continue
					}

					message.localPath = decryptedFilePath
					err = sendMessageToServer(username, message.From, nil, message.Id)
					if err != nil {
						fmt.Printf("Failed to send read receipt to %s: %v\n", message.From, err)
					}
				}
			}
		} else {
			message.decrypted = string(decryptedMessage)
			//Send a read receipt
			err = sendMessageToServer(username, message.From, nil, message.Id)
			if err != nil {
				fmt.Printf("Failed to send read receipt to %s: %v\n", message.From, err)
			}
		}

	}
}

func calculateFileHash(filePath string) (string, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Create a new SHA256 hash
	hash := sha256.New()

	// Copy the file contents to the hash
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	// Get the hash sum
	hashSum := hash.Sum(nil)

	// Encode the hash sum as a hex string
	hashStr := hex.EncodeToString(hashSum)

	return hashStr, nil
}

func decryptAttachmentFile(encryptedFilePath string, decryptedFilePath string, keyStr string) error {
	// Read the encrypted file contents
	encryptedData, err := ioutil.ReadFile(encryptedFilePath)
	if err != nil {
		return err
	}

	// Decode the key from base64
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return err
	}

	// Create a new ChaCha20 cipher with the key and zero nonce
	var nonce [chacha20.NonceSize]byte
	cipher, err := chacha20.New(key, nonce[:])
	if err != nil {
		return err
	}

	// Decrypt the file contents
	decryptedData := make([]byte, len(encryptedData))
	cipher.XORKeyStream(decryptedData, encryptedData)

	// Write the decrypted data to a new file
	err = ioutil.WriteFile(decryptedFilePath, decryptedData, 0644)
	if err != nil {
		fmt.Println("error in writing the decrypted file")
		return err
	}
	return nil
}
func attackMessenger(ciphertextFilename string, victimUsername string, privKey PrivKeyStruct) {
	// Load the target ciphertext from the file
	ciphertextData, err := ioutil.ReadFile(ciphertextFilename)
	if err != nil {
		fmt.Printf("Failed to load ciphertext file: %v\n", err)
		return
	}
	var rawMessage CiphertextStruct

	err = json.Unmarshal(ciphertextData, &rawMessage)
	if err != nil {
		fmt.Printf("Failed to parse ciphertext JSON: %v\n", err)
		return
	}

	// Decode the C2 component from base64
	c2Bytes, err := base64.StdEncoding.DecodeString(rawMessage.C2)
	if err != nil {
		fmt.Printf("Failed to decode C2: %v\n", err)

	}
	victimUsername2 := "charlie"
	msglen := len(c2Bytes) - 4 - len(victimUsername2) - 2
	_ = msglen
	// Register a new username victimUsername + "a"
	plaintext := performAttack(rawMessage, victimUsername, username, privKey)
	fmt.Println("Attack Successful")
	fmt.Println("The plaintext Message is :", plaintext)
}
func signMessage(message CiphertextStruct, privateKey PrivKeyStruct) string {
	// Concatenate C1 and C2 to form the message to sign
	messageToSign := message.C1 + message.C2

	// Decode Mallory's private signing key
	sigSKBytes, err := base64.StdEncoding.DecodeString(privateKey.SigSK)
	if err != nil {
		fmt.Printf("Failed to decode private signing key: %v\n", err)
		return ""
	}
	// Parse the private key
	sigSK, err := x509.ParsePKCS8PrivateKey(sigSKBytes)
	if err != nil {
		fmt.Printf("Failed to parse private signing key: %v\n", err)
		return ""
	}

	// Convert the private key to ECDSA format
	ecdsaPrivateKey, ok := sigSK.(*ecdsa.PrivateKey)
	if !ok {
		fmt.Printf("Invalid private key format.\n")
		return ""
	}

	// Sign the message using ECDSA
	hasher := sha256.New()
	hasher.Write([]byte(messageToSign))

	hash := hasher.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, hash)
	if err != nil {
		fmt.Printf("Failed to sign message: %v\n", err)
		return ""
	}

	// Encode the signature as a base64 string
	signature := append(r.Bytes(), s.Bytes()...)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return signatureBase64
}

// Print a list of message structs
func printMessageList(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].ReceiptID != 0 {
			fmt.Printf("Read receipt\n")
			continue
		}

		fmt.Printf("From: %s\n\n", messageArray[i].From)

		fmt.Printf(messageArray[i].decrypted)
		if messageArray[i].localPath != "" {
			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].localPath)
		} else if messageArray[i].url != "" {
			fmt.Printf("\n\tAttachment download failed\n")
		}
		fmt.Printf("\n-----------------------------\n\n")
	}
}

// Print a list of user structs
func printUserList(userArray []UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}

func getTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	var pubKey PubKeyStruct
	var privKey PrivKeyStruct

	// TODO: IMPLEMENT
	// Generate ECDH key pair
	encPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pubKey, privKey, nil
	}

	encSKBytes, err := x509.MarshalPKCS8PrivateKey(encPrivateKey)

	if err != nil {
		fmt.Println("Error in marshalling!", err)
		return pubKey, privKey, err
	}
	encPublicKey := encPrivateKey.PublicKey
	encPKBytes, err := x509.MarshalPKIXPublicKey(&encPublicKey)
	if err != nil {
		fmt.Println("Error in marshalling!", err)
		return pubKey, privKey, err
	}

	// Generate ECDSA key pair
	sigPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error in marshalling!", err)
		return pubKey, privKey, nil
	}
	sigSKBytes, err := x509.MarshalPKCS8PrivateKey(sigPrivateKey)
	if err != nil {
		fmt.Println("Error in marshalling!", err)
		return pubKey, privKey, err
	}
	sigPKBytes, err := x509.MarshalPKIXPublicKey(&sigPrivateKey.PublicKey)
	if err != nil {
		fmt.Println("Error in marshalling!", err)
		return pubKey, privKey, err
	}

	// Encode to BASE64
	encPKStr := base64.StdEncoding.EncodeToString(encPKBytes)
	sigPKStr := base64.StdEncoding.EncodeToString(sigPKBytes)
	encSKStr := base64.StdEncoding.EncodeToString(encSKBytes)
	sigSKStr := base64.StdEncoding.EncodeToString(sigSKBytes)
	pubKey.EncPK = encPKStr
	pubKey.SigPK = sigPKStr
	privKey.EncSK = encSKStr
	privKey.SigSK = sigSKStr

	return pubKey, privKey, err
}

func Reregister(username string) (PrivKeyStruct, string) {

	//reregister with new username and default password
	password := "abc"
	err := registerUserWithServer(username, password)
	if err != nil {
		fmt.Println("Unable to register username with server (user may already exist)")
	}

	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Geerate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err := generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}
	return globalPrivKey, apiKey

}

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	flag.IntVar(&serverPort, "port", 8080, "port for the server")
	flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&username, "username", "alice", "login username")
	flag.StringVar(&password, "password", "abc", "login password")
	flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	flag.StringVar(&victim, "victim", "alice", " -victim")
	flag.StringVar(&attack, "attack", "", "file path mention")
	flag.Parse()

	// Set the server protocol to http or https
	if noTLS == false {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if strictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	serverDomainAndPort = serverDomain + ":" + strconv.Itoa(serverPort)

	// If we are registering a new username, let's do that first
	if doUserRegister == true {
		fmt.Println("Registering new user...")
		err := registerUserWithServer(username, password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Geerate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err := generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}

	if attack != "" {
		attackMessenger(attack, victim, globalPrivKey)
	}

	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running == true {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if headlessMode == false {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {

				err = doReadAndSendMessage(strings.TrimSpace(parts[1]), "", globalPrivKey)
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := getMessagesFromServer(globalPrivKey)
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				// downloadAttachments(messageList)
				printMessageList(messageList)
			}
		case "LIST":
			userList, err := getUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				printUserList(userList)
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <recepient> <filename>")
			} else {
				recipient := strings.TrimSpace(parts[1])
				attachmentPath := strings.TrimSpace(parts[2])

				// Check if the attachment file exists
				if _, err := os.Stat(attachmentPath); os.IsNotExist(err) {
					fmt.Printf("Attachment file does not exist: %s\n", attachmentPath)
					break
				}
				// Encrypt the attachment file
				key, hash, err := encryptAttachment(attachmentPath)
				if err != nil {
					fmt.Printf("Failed to encrypt the attachment file: %v\n", err)
					break
				}

				// Upload the encrypted file to the server
				url, err := uploadFileToServer(attachmentPath + ".enc")
				if err != nil {
					fmt.Printf("Failed to upload the attachment file: %v\n", err)
					break
				}

				// Construct the structured plaintext message with the attachment details
				attachmentMessage := fmt.Sprintf(">>>MSGURL=%s?KEY=%s?H=%s", url, key, hash)
				pubkey, err := getPublicKeyFromServer(recipient)
				if err != nil {
					fmt.Printf("Faield to get Pub key of the recipient: %v\n", err)
					break
				}

				// Encrypt the attachment message
				encryptedMessage := encryptMessage([]byte(attachmentMessage), username, pubkey, globalPrivKey)

				// Send the encrypted message to the server
				err = sendMessageToServer(username, recipient, encryptedMessage, 0)
				if err != nil {
					fmt.Printf("Failed to send the attachment message: %v\n", err)
				} else {
					fmt.Println("Attachment message sent successfully!")
				}
			}

		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command\n")
		}
	}
}
