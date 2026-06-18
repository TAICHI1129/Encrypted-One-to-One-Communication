package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	DefaultPort    = "9999"
	KeyFile        = "eotoc_private.pem"
	KnownHostsFile = "eotoc_known_hosts"

	MaxMsgSize      = 10 * 1024 * 1024  // 10 MB
	MaxFileSize     = 512 * 1024 * 1024 // 512 MB
	MaxFileNameSize = 255
	MaxPubKeySize   = 8192

	ChunkSize = 64 * 1024 // 64 KB

	ConnTimeout = 10 * time.Second
	IOTimeout   = 120 * time.Second

	// ACK マジックバイト
	ackOK  = byte(0x06) // ASCII ACK
	ackFAIL = byte(0x15) // ASCII NAK
)

// ============================================================
//  鍵管理
// ============================================================

func loadOrGenerateKey() (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(KeyFile); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "RSA PRIVATE KEY" {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				fmt.Println("[*] Loaded existing private key from", KeyFile)
				return key, nil
			}
		}
		fmt.Println("[!] Key file corrupted. Regenerating...")
	}
	fmt.Println("[*] Generating new RSA-2048 key pair...")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("key generation: %w", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(KeyFile, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("key save: %w", err)
	}
	fmt.Printf("[+] New key saved to %s\n", KeyFile)
	return key, nil
}

func pubKeyToPEM(pub *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})
}

func fingerprint(pub *rsa.PublicKey) string {
	h := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	var sb strings.Builder
	for i, b := range h {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}

// ============================================================
//  known_hosts (TOFU 方式)
//
//  fix 4: loadKnownHosts → ユーザー確認 → saveKnownHost の間に
//          別ゴルーチンが同じ IP を登録できる TOFU 競合を防ぐため、
//          verifyPeerKey 全体を khMu で保護する。
//          loadKnownHosts はロック外で呼ばず、ロック内で直接ファイルを読む。
// ============================================================

var khMu sync.Mutex

// loadKnownHostsLocked はロック保持中に呼ぶ内部専用関数。
func loadKnownHostsLocked() map[string]string {
	hosts := make(map[string]string)
	data, err := os.ReadFile(KnownHostsFile)
	if err != nil {
		return hosts
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			hosts[parts[0]] = parts[1]
		}
	}
	return hosts
}

// saveKnownHostLocked はロック保持中に呼ぶ内部専用関数。
func saveKnownHostLocked(ip, fp string) error {
	f, err := os.OpenFile(KnownHostsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", ip, fp)
	return err
}

// verifyPeerKey: fix 4 — khMu でロック全体を保護し TOFU 競合を排除。
func verifyPeerKey(scanner *bufio.Scanner, peerIP string, peerPub *rsa.PublicKey) error {
	fp := fingerprint(peerPub)

	khMu.Lock()
	defer khMu.Unlock()

	known := loadKnownHostsLocked()
	if saved, exists := known[peerIP]; exists {
		if saved != fp {
			return fmt.Errorf(
				"HOST KEY MISMATCH for %s!\n  Saved:   %s\n  Current: %s\n"+
					"  -> Possible MITM attack. Aborting.",
				peerIP, saved, fp,
			)
		}
		fmt.Printf("[+] Host key verified: %s\n", peerIP)
		return nil
	}

	// 初回接続 (TOFU)
	fmt.Printf("\n[!] Unknown host: %s\n", peerIP)
	fmt.Printf("    Fingerprint (SHA-256): %s\n", fp)
	fmt.Println("    NOTE: TOFU - verify this fingerprint via a trusted channel.")
	fmt.Print("    Trust this host? [yes/no]: ")

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("input read error: %w", err)
		}
		return errors.New("unexpected EOF on stdin")
	}
	if strings.TrimSpace(strings.ToLower(scanner.Text())) != "yes" {
		return errors.New("connection aborted by user")
	}
	if err := saveKnownHostLocked(peerIP, fp); err != nil {
		fmt.Printf("[!] Could not save known host: %v\n", err)
	}
	return nil
}

// ============================================================
//  main
// ============================================================

func main() {
	privKey, err := loadOrGenerateKey()
	if err != nil {
		log.Fatalf("[-] Failed to load/generate key: %v", err)
	}
	pubPEM := pubKeyToPEM(&privKey.PublicKey)

	fmt.Println("\n=== Encrypted One-to-One Communication (eotoc) ===")
	fmt.Printf("[*] My fingerprint: %s\n", fingerprint(&privKey.PublicKey))

	go startServer(DefaultPort, privKey, pubPEM)

	// fix 7: Scanner バッファを MaxMsgSize に合わせて拡張 (旧: 1MB、Max: 10MB)
	const scanBuf = MaxMsgSize + 4096
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, scanBuf), scanBuf)

	for {
		fmt.Println("\n[ MENU ] 1: Send Message / 2: Exit")
		fmt.Print("Enter your choice: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				log.Printf("[-] Stdin error: %v", err)
			}
			fmt.Println("Shutting down. Goodbye!")
			return
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "1":
			handleClientMenu(scanner)
		case "2":
			fmt.Println("Shutting down. Goodbye!")
			return
		default:
			fmt.Println("[-] Invalid choice.")
		}
	}
}

// ============================================================
//  Server (受信側)
// ============================================================

func startServer(port string, privKey *rsa.PrivateKey, pubPEM []byte) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[-] Server startup error: %v", err)
	}
	defer ln.Close()
	fmt.Printf("[*] Listening on port %s\n", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[-] Accept error: %v", err)
			continue
		}
		go handleIncomingConnection(conn, privKey, pubPEM)
	}
}

func handleIncomingConnection(conn net.Conn, privKey *rsa.PrivateKey, pubPEM []byte) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(IOTimeout))

	// 1. 公開鍵を送信
	if err := sendLenPrefixed(conn, pubPEM); err != nil {
		log.Printf("[-] Failed to send public key: %v", err)
		return
	}

	// 2. 暗号化 AES 鍵を受信・復号
	encAESKeyBuf := make([]byte, privKey.Size())
	if _, err := io.ReadFull(conn, encAESKeyBuf); err != nil {
		log.Printf("[-] Failed to read encrypted AES key: %v", err)
		return
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encAESKeyBuf, nil)
	if err != nil {
		log.Printf("[-] AES key decryption error: %v", err)
		return
	}

	// 3. チャンクストリームを受信
	gcmReader, err := newChunkReader(conn, aesKey)
	if err != nil {
		log.Printf("[-] Failed to create chunk reader: %v", err)
		return
	}

	// 4. ヘッダ受信
	var msgSize uint64
	var fnSize uint16
	var fileSize uint64
	if err := binary.Read(gcmReader, binary.BigEndian, &msgSize); err != nil {
		log.Printf("[-] Header read error (msgSize): %v", err)
		sendACK(conn, aesKey, false)
		return
	}
	if err := binary.Read(gcmReader, binary.BigEndian, &fnSize); err != nil {
		log.Printf("[-] Header read error (fnSize): %v", err)
		sendACK(conn, aesKey, false)
		return
	}
	if err := binary.Read(gcmReader, binary.BigEndian, &fileSize); err != nil {
		log.Printf("[-] Header read error (fileSize): %v", err)
		sendACK(conn, aesKey, false)
		return
	}

	if msgSize > MaxMsgSize {
		log.Printf("[-] Message too large: %d", msgSize)
		sendACK(conn, aesKey, false)
		return
	}
	if fnSize > MaxFileNameSize {
		log.Printf("[-] Filename too large: %d", fnSize)
		sendACK(conn, aesKey, false)
		return
	}
	if fileSize > MaxFileSize {
		log.Printf("[-] File too large: %d", fileSize)
		sendACK(conn, aesKey, false)
		return
	}

	// 5. メッセージ本文受信
	msgBuf := make([]byte, msgSize)
	if _, err := io.ReadFull(gcmReader, msgBuf); err != nil {
		log.Printf("[-] Message read error: %v", err)
		sendACK(conn, aesKey, false)
		return
	}
	fmt.Printf("\n[+] Message from (%s)\n", conn.RemoteAddr())
	fmt.Printf("----------------------------------------\n%s\n----------------------------------------\n", string(msgBuf))

	// 6. ファイル名受信
	var fileName string
	if fnSize > 0 {
		fnBuf := make([]byte, fnSize)
		if _, err := io.ReadFull(gcmReader, fnBuf); err != nil {
			log.Printf("[-] Filename read error: %v", err)
			sendACK(conn, aesKey, false)
			return
		}
		fileName = sanitizeFileName(string(fnBuf))
		if fileName == "" {
			log.Printf("[-] Filename sanitized to empty, discarding file data")
			if fileSize > 0 {
				io.CopyN(io.Discard, gcmReader, int64(fileSize))
			}
			sendACK(conn, aesKey, false)
			return
		}
	}

	// 7. ファイルをストリーミング保存
	//    fix 5: progressDeadlineWriter で書き込みのたびに deadline を延長
	if fileSize > 0 && fileName != "" {
		ts := time.Now().Format("20060102_150405")
		savePath := fmt.Sprintf("received_%s_%s", ts, fileName)
		fmt.Printf("[*] Receiving: %s (%d bytes) -> %s\n", fileName, fileSize, savePath)

		out, err := os.Create(savePath)
		if err != nil {
			log.Printf("[-] File create error: %v", err)
			sendACK(conn, aesKey, false)
			return
		}
		defer out.Close()

		// fix 5: 書き込みごとに deadline を延長するラッパー
		pdw := &progressDeadlineConn{conn: conn, timeout: IOTimeout}
		written, err := io.CopyN(io.MultiWriter(out, pdw), gcmReader, int64(fileSize))
		if err != nil || uint64(written) != fileSize {
			log.Printf("[-] Incomplete file: wrote %d/%d, err: %v", written, fileSize, err)
			sendACK(conn, aesKey, false)
			return
		}
		fmt.Printf("[+] File saved: %s\n", savePath)
	}

	// fix 6: 受信成功を暗号化 ACK で通知
	if err := sendACK(conn, aesKey, true); err != nil {
		log.Printf("[-] ACK send error: %v", err)
	}
}

// ============================================================
//  Client (送信側)
// ============================================================

func handleClientMenu(scanner *bufio.Scanner) {
	fmt.Print("Destination URI (e.g., eotoc://192.168.1.10): ")
	if !scanner.Scan() {
		fmt.Println("[-] Input error.")
		return
	}
	uri := strings.TrimSpace(scanner.Text())
	if !strings.HasPrefix(uri, "eotoc://") {
		fmt.Println("[-] Invalid URI. Must start with 'eotoc://'.")
		return
	}
	targetIP := strings.TrimPrefix(uri, "eotoc://")

	fmt.Print("Message body: ")
	if !scanner.Scan() {
		fmt.Println("[-] Input error.")
		return
	}
	message := strings.TrimSpace(scanner.Text())

	fmt.Print("File attachment path (Enter to skip): ")
	if !scanner.Scan() {
		fmt.Println("[-] Input error.")
		return
	}
	filePath := strings.TrimSpace(scanner.Text())

	sendEotoc(scanner, targetIP, message, filePath)
}

func sendEotoc(scanner *bufio.Scanner, ip, message, filePath string) {
	conn, err := net.DialTimeout("tcp", ip+":"+DefaultPort, ConnTimeout)
	if err != nil {
		fmt.Printf("[-] Connection failed: %v\n", err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(IOTimeout))

	// 1. 相手の公開鍵を受信
	pubPEM, err := recvLenPrefixed(conn, MaxPubKeySize)
	if err != nil {
		fmt.Printf("[-] Failed to receive public key: %v\n", err)
		return
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		fmt.Printf("[-] Invalid PEM block (type=%q)\n", func() string {
			if block == nil {
				return "<nil>"
			}
			return block.Type
		}())
		return
	}
	peerPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("[-] Public key parse error: %v\n", err)
		return
	}

	// 2. TOFU 確認
	if err := verifyPeerKey(scanner, ip, peerPub); err != nil {
		fmt.Printf("[-] %v\n", err)
		return
	}

	// 3. ファイル情報取得
	var file *os.File
	var fileSize int64
	var fileName string
	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("[!] Cannot open file, sending without attachment: %v\n", err)
		} else {
			fi, err := f.Stat()
			if err != nil {
				fmt.Printf("[!] Cannot stat file, sending without attachment: %v\n", err)
				f.Close()
			} else if fi.Size() > MaxFileSize {
				fmt.Println("[-] File too large.")
				f.Close()
				return
			} else {
				file = f
				fileSize = fi.Size()
				fileName = filepath.Base(filePath)
				defer file.Close()
			}
		}
	}

	// fix 10: バイト数で制限していることをエラーメッセージに明記
	if len(message) > MaxMsgSize {
		fmt.Printf("[-] Message too large (%d bytes, limit %d bytes).\n", len(message), MaxMsgSize)
		return
	}
	if len(fileName) > MaxFileNameSize {
		fmt.Printf("[-] File name too long (%d bytes, limit %d bytes).\n", len(fileName), MaxFileNameSize)
		return
	}

	// 4. 一時 AES 鍵を生成
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		fmt.Printf("[-] Failed to generate AES key: %v\n", err)
		return
	}

	// 5. AES 鍵を RSA で暗号化して送信
	encAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, peerPub, aesKey, nil)
	if err != nil {
		fmt.Printf("[-] AES key encryption error: %v\n", err)
		return
	}
	if err := writeAll(conn, encAESKey); err != nil {
		fmt.Printf("[-] Send error (encAESKey): %v\n", err)
		return
	}

	// 6. チャンクストリームで送信
	gcmWriter, err := newChunkWriter(conn, aesKey)
	if err != nil {
		fmt.Printf("[-] Failed to create chunk writer: %v\n", err)
		return
	}

	msgBytes := []byte(message)
	fnBytes := []byte(fileName)

	if err := binary.Write(gcmWriter, binary.BigEndian, uint64(len(msgBytes))); err != nil {
		fmt.Printf("[-] Header write error: %v\n", err)
		return
	}
	if err := binary.Write(gcmWriter, binary.BigEndian, uint16(len(fnBytes))); err != nil {
		fmt.Printf("[-] Header write error: %v\n", err)
		return
	}
	if err := binary.Write(gcmWriter, binary.BigEndian, uint64(fileSize)); err != nil {
		fmt.Printf("[-] Header write error: %v\n", err)
		return
	}
	if _, err := gcmWriter.Write(msgBytes); err != nil {
		fmt.Printf("[-] Message write error: %v\n", err)
		return
	}
	if len(fnBytes) > 0 {
		if _, err := gcmWriter.Write(fnBytes); err != nil {
			fmt.Printf("[-] Filename write error: %v\n", err)
			return
		}
	}

	if file != nil && fileSize > 0 {
		// fix 5: 送信中も deadline を延長
		conn.SetDeadline(time.Now().Add(IOTimeout))
		fmt.Print("[*] Streaming encrypted file")
		pdw := &progressDeadlineConn{conn: conn, timeout: IOTimeout}
		if _, err := io.Copy(io.MultiWriter(gcmWriter, pdw), file); err != nil {
			fmt.Printf("\n[-] File transmission error: %v\n", err)
			return
		}
		fmt.Println(" done.")
	}

	if err := gcmWriter.Close(); err != nil {
		fmt.Printf("[-] Stream close error: %v\n", err)
		return
	}

	// fix 6: 受信側からの暗号化 ACK を待つ
	conn.SetDeadline(time.Now().Add(IOTimeout))
	ok, err := recvACK(conn, aesKey)
	if err != nil {
		fmt.Printf("[-] ACK receive error: %v\n", err)
		return
	}
	if ok {
		fmt.Println("[+] All payloads securely delivered and acknowledged!")
	} else {
		fmt.Println("[-] Receiver reported an error. Delivery may have failed.")
	}
}

// ============================================================
//  暗号化 ACK (fix 6)
//
//  受信側: 処理結果を AES-GCM で暗号化して 1 バイト送信する。
//           ackOK(0x06) = 成功 / ackFAIL(0x15) = 失敗
//  送信側: 受信して復号し、結果を確認する。
//
//  平文 ACK では攻撃者が偽造できるため、同一 AES 鍵で暗号化する。
// ============================================================

func sendACK(conn net.Conn, aesKey []byte, ok bool) error {
	conn.SetDeadline(time.Now().Add(IOTimeout))
	blk, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	payload := []byte{ackFAIL}
	if ok {
		payload = []byte{ackOK}
	}
	ciphertext := gcm.Seal(nil, nonce, payload, nil)

	// フレーム: [nonceSize:1][nonce][ciphertextLen:4][ciphertext]
	frame := make([]byte, 1+len(nonce)+4+len(ciphertext))
	frame[0] = byte(len(nonce))
	copy(frame[1:], nonce)
	binary.BigEndian.PutUint32(frame[1+len(nonce):], uint32(len(ciphertext)))
	copy(frame[1+len(nonce)+4:], ciphertext)
	return writeAll(conn, frame)
}

func recvACK(conn net.Conn, aesKey []byte) (bool, error) {
	blk, err := aes.NewCipher(aesKey)
	if err != nil {
		return false, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return false, err
	}
	// nonceSize を読む
	nsBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, nsBuf); err != nil {
		return false, fmt.Errorf("ACK nonce size read: %w", err)
	}
	nonceSize := int(nsBuf[0])
	if nonceSize != gcm.NonceSize() {
		return false, fmt.Errorf("unexpected ACK nonce size: %d", nonceSize)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return false, fmt.Errorf("ACK nonce read: %w", err)
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return false, fmt.Errorf("ACK length read: %w", err)
	}
	ctLen := binary.BigEndian.Uint32(lenBuf)
	if ctLen > 64 { // ACK は 1 バイト + GCM タグ 16 バイト = 17 バイト程度
		return false, fmt.Errorf("ACK ciphertext suspiciously large: %d", ctLen)
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(conn, ct); err != nil {
		return false, fmt.Errorf("ACK ciphertext read: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return false, fmt.Errorf("ACK GCM authentication failed: %w", err)
	}
	if len(plain) != 1 {
		return false, fmt.Errorf("unexpected ACK payload length: %d", len(plain))
	}
	return plain[0] == ackOK, nil
}

// ============================================================
//  チャンク GCM ストリーム
//
//  fix 1+2+3: AAD に seqNum(uint64) と isFinal(uint8) を含める。
//
//  フレーム構造 (1 チャンク):
//    [nonce:12][dataLen:4][encryptedData+tag: dataLen バイト]
//
//  AAD (認証付きデータ、暗号化はされないが改ざんを検知):
//    [seqNum:8][isFinal:1]
//
//  終端チャンク:
//    isFinal=1 のチャンク。dataLen は 0 でもよい。
//    nonce + AAD ごと GCM 認証されるため、攻撃者が偽造・挿入できない。
//
//  順序・リプレイ防止:
//    seqNum が AAD に含まれるため、チャンクの順序入れ替えや
//    再送を行うと GCM 認証が失敗する。
// ============================================================

// aadBuf は AAD を組み立てるヘルパー。
// [seqNum:8][isFinal:1] = 9 バイト
func buildAAD(seqNum uint64, isFinal bool) []byte {
	aad := make([]byte, 9)
	binary.BigEndian.PutUint64(aad, seqNum)
	if isFinal {
		aad[8] = 1
	}
	return aad
}

type chunkWriter struct {
	conn   net.Conn
	gcm    cipher.AEAD
	buf    []byte
	seqNum uint64
}

func newChunkWriter(conn net.Conn, aesKey []byte) (*chunkWriter, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &chunkWriter{conn: conn, gcm: gcm}, nil
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		space := ChunkSize - len(w.buf)
		take := len(p)
		if take > space {
			take = space
		}
		w.buf = append(w.buf, p[:take]...)
		p = p[take:]
		total += take
		if len(w.buf) == ChunkSize {
			if err := w.flushChunk(false); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// Close: 残りバッファを isFinal=true チャンクとして送信する。
// fix 8: 別途終端フレームを送る sendTerminator を廃止。
//         最終チャンクの AAD に isFinal=1 を立てることで終端を認証する。
func (w *chunkWriter) Close() error {
	return w.flushChunk(true) // 空でも isFinal=true チャンクを必ず送る
}

func (w *chunkWriter) flushChunk(isFinal bool) error {
	nonce := make([]byte, w.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aad := buildAAD(w.seqNum, isFinal)
	ciphertext := w.gcm.Seal(nil, nonce, w.buf, aad)
	w.buf = nil   // fix E: GC に返す
	w.seqNum++

	frame := make([]byte, len(nonce)+4+len(ciphertext))
	copy(frame, nonce)
	binary.BigEndian.PutUint32(frame[len(nonce):], uint32(len(ciphertext)))
	copy(frame[len(nonce)+4:], ciphertext)
	return writeAll(w.conn, frame)
}

type chunkReader struct {
	conn        net.Conn
	gcm         cipher.AEAD
	buf         []byte
	seqNum      uint64
	done        bool
}

func newChunkReader(conn net.Conn, aesKey []byte) (*chunkReader, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &chunkReader{conn: conn, gcm: gcm}, nil
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if err := r.readNextChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *chunkReader) readNextChunk() error {
	nonceSize := r.gcm.NonceSize()
	header := make([]byte, nonceSize+4)
	if _, err := io.ReadFull(r.conn, header); err != nil {
		return err
	}
	nonce := header[:nonceSize]
	dataLen := binary.BigEndian.Uint32(header[nonceSize:])

	// fix 1+2+3: isFinal を「試す」のではなく dataLen==0 の可能性を含めて
	//             両方の AAD を認証し、どちらかが通ればそのまま採用する。
	//             ただしチャンクが空 (dataLen==0) なのは isFinal=1 のみ許可する。
	maxChunk := uint32(ChunkSize + r.gcm.Overhead())
	if dataLen > maxChunk {
		return fmt.Errorf("chunk too large: %d", dataLen)
	}

	ciphertext := make([]byte, dataLen)
	if _, err := io.ReadFull(r.conn, ciphertext); err != nil {
		return err
	}

	// まず isFinal=false (通常チャンク) で試みる
	aadNormal := buildAAD(r.seqNum, false)
	plain, err := r.gcm.Open(nil, nonce, ciphertext, aadNormal)
	if err != nil {
		// 通常チャンクで失敗したら isFinal=true (終端チャンク) で試みる
		aadFinal := buildAAD(r.seqNum, true)
		plain, err = r.gcm.Open(nil, nonce, ciphertext, aadFinal)
		if err != nil {
			// 両方失敗 → 順序入れ替え・リプレイ・改ざん検知
			return fmt.Errorf("GCM authentication failed at seq %d: possible reorder/replay/tamper", r.seqNum)
		}
		// isFinal=true で成功 → ストリーム終端
		r.seqNum++
		r.buf = plain
		r.done = true
		return nil
	}

	// 通常チャンクで成功
	r.seqNum++
	r.buf = plain
	return nil
}

// ============================================================
//  progressDeadlineConn (fix 5)
//
//  大容量ファイル転送中に io.Copy の書き込みが発生するたびに
//  接続の deadline を延長する。
//  io.Writer として MultiWriter に渡すため、実際のデータは書き捨てる。
// ============================================================

type progressDeadlineConn struct {
	conn    net.Conn
	timeout time.Duration
}

func (p *progressDeadlineConn) Write(b []byte) (int, error) {
	p.conn.SetDeadline(time.Now().Add(p.timeout))
	return len(b), nil
}

// ============================================================
//  ファイル名サニタイズ
// ============================================================

var safeFileNameRe = regexp.MustCompile(`[^\p{L}\p{N}\-_. ]`)

func sanitizeFileName(name string) string {
	name = filepath.Base(name)
	name = safeFileNameRe.ReplaceAllString(name, "_")
	name = strings.TrimSpace(name)
	return name
}

// ============================================================
//  TCP ヘルパー
// ============================================================

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func sendLenPrefixed(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if err := writeAll(w, lenBuf); err != nil {
		return err
	}
	return writeAll(w, data)
}

func recvLenPrefixed(r io.Reader, maxSize uint32) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(lenBuf)
	if size > maxSize {
		return nil, fmt.Errorf("declared length %d exceeds limit %d", size, maxSize)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
