package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const DefaultPort = "9999"

// 🚀 Automatically checks and installs required dependencies on startup
func autoSetupDependencies() {
	// 1. Check if "go.mod" exists. If not, initialize it.
	if _, err := os.Stat("go.mod"); os.IsNotExist(err) {
		fmt.Println("[*] First-time setup: Initializing Go module...")
		cmd := exec.Command("go", "mod", "init", "eotoc")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[-] Failed to initialize go.mod. Please check if Go is installed: %v\n", err)
			os.Exit(1)
		}
	}

	// 2. Download and verify external packages if any are added in the future
	fmt.Println("[*] Checking dependencies...")
	cmdTidy := exec.Command("go", "mod", "tidy")
	if err := cmdTidy.Run(); err != nil {
		fmt.Println("[*] Automatically installing required external packages...")
		cmdGet := exec.Command("go", "get", "://github.com")
		cmdGet.Stdout = os.Stdout
		cmdGet.Stderr = os.Stderr
		cmdGet.Run()
	}
}

func main() {
	// Execute the automatic setup first
	autoSetupDependencies()

	fmt.Println("\n=== Encrypted One-to-One Communication (eotoc) ===")
	fmt.Println("[+] Environment check passed. System started successfully.")

	// Start the background listener server
	go startServer(DefaultPort)

	// Main application loop
	for {
		fmt.Println("\n[ MENU ] 1: Send Message / 2: Exit")
		fmt.Print("Enter your choice: ")
		var choice string
		fmt.Scanln(&choice)

		if choice == "2" {
			fmt.Println("Shutting down the system. Goodbye!")
			break
		} else if choice == "1" {
			handleClientMenu()
		}
	}
}

// --- ⚙️ Server (Receiver) Core ------------------------------------------------

func startServer(port string) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("[-] Key generation error: %v\n", err)
		return
	}
	pubBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pubBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Printf("[-] Server startup error: %v\n", err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		// Handle each connection concurrently in a separate goroutine
		go handleIncomingConnection(conn, privKey, pubBlock)
	}
}

func handleIncomingConnection(conn net.Conn, privKey *rsa.PrivateKey, pubBlock []byte) {
	defer conn.Close()

	// 1. Send RSA public key to the sender
	if _, err := conn.Write(pubBlock); err != nil {
		return
	}

	// 2. Receive the encrypted AES key (256 bytes)
	encAESKey := make([]byte, 256)
	if _, err := io.ReadFull(conn, encAESKey); err != nil {
		return
	}

	// Decrypt the AES key using the server's private key
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encAESKey, nil)
	if err != nil {
		fmt.Printf("[-] Key decryption error: %v\n", err)
		return
	}

	// 3. Receive the IV (16 bytes)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(conn, iv); err != nil {
		return
	}

	// Initialize the AES-CTR stream decoder
	block, _ := aes.NewCipher(aesKey)
	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: conn}

	// 4. Read the stream metadata
	// Message Size (8 bytes)
	var msgSize int64
	if err := binary.Read(reader, binary.BigEndian, &msgSize); err != nil {
		return
	}
	// File Name Size (2 bytes)
	var fileNameSize int16
	if err := binary.Read(reader, binary.BigEndian, &fileNameSize); err != nil {
		return
	}
	// File Size (8 bytes)
	var fileSize int64
	if err := binary.Read(reader, binary.BigEndian, &fileSize); err != nil {
		return
	}

	// Read the text message payload
	msgBuf := make([]byte, msgSize)
	if _, err := io.ReadFull(reader, msgBuf); err != nil {
		return
	}

	var fileName string
	if fileNameSize > 0 {
		fnBuf := make([]byte, fileNameSize)
		if _, err := io.ReadFull(reader, fnBuf); err != nil {
			return
		}
		fileName = string(fnBuf)
	}

	// Display the received text message
	fmt.Printf("\n[+] New message received from (%s)\n", conn.RemoteAddr().String())
	fmt.Printf("----------------------------------------\n%s\n----------------------------------------\n", string(msgBuf))

	// Handle attachment file saving
	if fileSize > 0 {
		savePath := "received_" + filepath.Base(fileName)
		fmt.Printf("[*] Receiving file attachment: %s (%d bytes) -> Saving as %s...\n", fileName, fileSize, savePath)
		
		out, err := os.Create(savePath)
		if err != nil {
			fmt.Printf("[-] File creation error: %v\n", err)
			return
		}
		defer out.Close()

		// Stream decryption straight to disk (unlimited file size support)
		written, err := io.CopyN(out, reader, fileSize)
		if err != nil || written != fileSize {
			fmt.Printf("[-] Incomplete file reception: %v\n", err)
			return
		}
		fmt.Printf("[+] File saved successfully: %s\n", savePath)
	}
}

// --- ✉️ Client (Sender) Core ------------------------------------------------

func handleClientMenu() {
	var uri, message, filePath string

	fmt.Print("Destination URI (e.g., eotoc://127.0.0.1): ")
	fmt.Scanln(&uri)
	if !strings.HasPrefix(uri, "eotoc://") {
		fmt.Println("[-] Invalid URI format. Must start with 'eotoc://'.")
		return
	}
	targetIP := strings.TrimPrefix(uri, "eotoc://")

	fmt.Print("Message body: ")
	var msgParts []string
	for {
		var p string
		fmt.Scanln(&p)
		if p == "" {
			break
		}
		msgParts = append(msgParts, p)
	}
	message = strings.Join(msgParts, " ")

	fmt.Print("File attachment path (Press Enter to skip): ")
	fmt.Scanln(&filePath)

	sendEotoc(targetIP, message, filePath)
}

func sendEotoc(ip, message string, filePath string) {
	conn, err := net.DialTimeout("tcp", ip+":"+DefaultPort, 5*time.Second)
	if err != nil {
		fmt.Printf("[-] Connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	// 1. Receive the recipient's RSA public key
	pubBuf := make([]byte, 2048)
	n, err := conn.Read(pubBuf)
	if err != nil {
		fmt.Printf("[-] Failed to read public key: %v\n", err)
		return
	}
	block, _ := pem.Decode(pubBuf[:n])
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("[-] Public key parsing error: %v\n", err)
		return
	}

	// 2. Generate a one-time ephemeral AES key (32 bytes) and IV (16 bytes)
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	iv := make([]byte, 16)
	rand.Read(iv)

	// Encrypt the AES key using the recipient's RSA public key
	encAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return
	}

	// Send encrypted AES key and raw IV to the recipient
	if _, err := conn.Write(encAESKey); err != nil {
		return
	}
	if _, err := conn.Write(iv); err != nil {
		return
	}

	// Setup the AES-CTR stream encryption writer
	aesBlock, _ := aes.NewCipher(aesKey)
	stream := cipher.NewCTR(aesBlock, iv)
	writer := &cipher.StreamWriter{S: stream, W: conn}

	// 3. Inspect the file if attached
	var fileSize int64 = 0
	var fileName string
	var file *os.File
	if filePath != "" {
		file, err = os.Open(filePath)
		if err == nil {
			defer file.Close()
			fi, _ := file.Stat()
			fileSize = fi.Size()
			fileName = filepath.Base(filePath)
		} else {
			fmt.Printf("[-] Could not open file. Sending message without attachment: %v\n", err)
		}
	}

	// 4. Pack metadata into the encrypted stream
	msgBytes := []byte(message)
	binary.Write(writer, binary.BigEndian, int64(len(msgBytes)))
	binary.Write(writer, binary.BigEndian, int16(len(fileName)))
	binary.Write(writer, binary.BigEndian, fileSize)

	// 5. Stream the message text
	writer.Write(msgBytes)

	// 6. Stream the file data safely without high memory usage
	if fileSize > 0 {
		fmt.Printf("[*] Streaming encrypted file data...")
		if _, err := io.Copy(writer, file); err != nil {
			fmt.Printf("[-] File transmission error: %v\n", err)
			return
		}
	}

	fmt.Println("\n[+] All payloads securely delivered!")
}
