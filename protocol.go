package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	protocolMagic   uint32 = 0x454F5443 // "EOTC"
	protocolVersion byte   = 1

	packetMessage       byte = 1
	packetMessageFile   byte = 2

	maxMessageSize uint32 = 1 << 20        // 1 MiB
	maxFileNameSize uint32 = 255
	maxFileSize int64 = 1 << 30             // 1 GiB

	connectTimeout = 5 * time.Second
	idleTimeout    = 60 * time.Second
)

type Packet struct {
	Type     byte
	Message  string
	FileName string
	FileSize int64
}

func dialEOTOC(
	address string,
	trustedFingerprint string,
) (*tls.Conn, error) {
	dialer := &net.Dialer{
		Timeout: connectTimeout,
	}

	config := clientTLSConfig(
		address,
		trustedFingerprint,
	)

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		address,
		config,
	)
	if err != nil {
		return nil, err
	}

	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func startEOTOCServer(
	port string,
	onPacket func(net.Addr, Packet, io.Reader) error,
) error {
	cert, err := generateServerCertificate()
	if err != nil {
		return err
	}

	config := serverTLSConfig(cert)

	listener, err := tls.Listen(
		"tcp",
		":"+port,
		config,
	)
	if err != nil {
		return fmt.Errorf(
			"listen on port %s: %w",
			port,
			err,
		)
	}

	fmt.Printf(
		"[+] EOTOC server listening on %s\n",
		port,
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleServerConnection(
			conn,
			onPacket,
		)
	}
}

func handleServerConnection(
	raw net.Conn,
	onPacket func(net.Addr, Packet, io.Reader) error,
) {
	defer raw.Close()

	conn, ok := raw.(*tls.Conn)
	if !ok {
		return
	}

	if err := conn.Handshake(); err != nil {
		return
	}

	remote := conn.RemoteAddr()

	_ = conn.SetDeadline(
		time.Now().Add(idleTimeout),
	)

	packet, reader, err := readPacket(conn)
	if err != nil {
		return
	}

	if err := onPacket(
		remote,
		packet,
		reader,
	); err != nil {
		fmt.Printf(
			"[-] Packet error from %s: %v\n",
			remote.String(),
			err,
		)
	}
}

func writePacket(
	w io.Writer,
	packet Packet,
	file *os.File,
) error {
	message := []byte(packet.Message)
	fileName := []byte(packet.FileName)

	if uint32(len(message)) > maxMessageSize {
		return errors.New("message too large")
	}

	if uint32(len(fileName)) > maxFileNameSize {
		return errors.New("filename too long")
	}

	if packet.FileSize < 0 ||
		packet.FileSize > maxFileSize {
		return errors.New("invalid file size")
	}

	header := make([]byte, 20)

	binary.BigEndian.PutUint32(
		header[0:4],
		protocolMagic,
	)

	header[4] = protocolVersion
	header[5] = packet.Type

	// Reserved flags.
	binary.BigEndian.PutUint16(
		header[6:8],
		0,
	)

	binary.BigEndian.PutUint32(
		header[8:12],
		uint32(len(message)),
	)

	binary.BigEndian.PutUint32(
		header[12:16],
		uint32(len(fileName)),
	)

	binary.BigEndian.PutUint32(
		header[16:20],
		uint32(packet.FileSize),
	)

	if packet.FileSize > 0 {
		if file == nil {
			return errors.New("file handle missing")
		}
	}

	if _, err := w.Write(header); err != nil {
		return err
	}

	if _, err := w.Write(message); err != nil {
		return err
	}

	if _, err := w.Write(fileName); err != nil {
		return err
	}

	if packet.FileSize > 0 {
		written, err := io.CopyN(
			w,
			file,
			packet.FileSize,
		)

		if err != nil {
			return fmt.Errorf(
				"file transfer: %w",
				err,
			)
		}

		if written != packet.FileSize {
			return errors.New(
				"file size mismatch",
			)
		}
	}

	return nil
}

func readPacket(
	r io.Reader,
) (Packet, io.Reader, error) {
	header := make([]byte, 20)

	if _, err := io.ReadFull(r, header); err != nil {
		return Packet{}, nil, err
	}

	magic := binary.BigEndian.Uint32(
		header[0:4],
	)

	if magic != protocolMagic {
		return Packet{}, nil, errors.New(
			"invalid EOTOC packet",
		)
	}

	version := header[4]

	if version != protocolVersion {
		return Packet{}, nil, fmt.Errorf(
			"unsupported protocol version: %d",
			version,
		)
	}

	packetType := header[5]

	messageSize := binary.BigEndian.Uint32(
		header[8:12],
	)

	fileNameSize := binary.BigEndian.Uint32(
		header[12:16],
	)

	fileSize := int64(
		binary.BigEndian.Uint32(
			header[16:20],
		),
	)

	if messageSize > maxMessageSize {
		return Packet{}, nil, errors.New(
			"message too large",
		)
	}

	if fileNameSize > maxFileNameSize {
		return Packet{}, nil, errors.New(
			"filename too long",
		)
	}

	if fileSize < 0 ||
		fileSize > maxFileSize {
		return Packet{}, nil, errors.New(
			"file too large",
		)
	}

	message := make([]byte, messageSize)

	if _, err := io.ReadFull(
		r,
		message,
	); err != nil {
		return Packet{}, nil, err
	}

	fileName := make([]byte, fileNameSize)

	if _, err := io.ReadFull(
		r,
		fileName,
	); err != nil {
		return Packet{}, nil, err
	}

	packet := Packet{
		Type:     packetType,
		Message:  string(message),
		FileName: string(fileName),
		FileSize: fileSize,
	}

	return packet, r, nil
}

func sendMessage(
	address string,
	trustedFingerprint string,
	message string,
	filePath string,
) error {
	conn, err := dialEOTOC(
		address,
		trustedFingerprint,
	)
	if err != nil {
		return err
	}

	defer conn.Close()

	_ = conn.SetDeadline(
		time.Now().Add(idleTimeout),
	)

	if len(message) > int(maxMessageSize) {
		return errors.New("message is too large")
	}

	var file *os.File
	var fileSize int64
	var fileName string
	var packetType byte = packetMessage

	if filePath != "" {
		file, err = os.Open(filePath)
		if err != nil {
			return fmt.Errorf(
				"open attachment: %w",
				err,
			)
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return errors.New(
				"attachment is not a regular file",
			)
		}

		fileSize = info.Size()

		if fileSize > maxFileSize {
			return errors.New(
				"attachment is too large",
			)
		}

		fileName = filepath.Base(
			info.Name(),
		)

		if fileName == "." ||
			fileName == string(filepath.Separator) ||
			fileName == "" {
			return errors.New(
				"invalid filename",
			)
		}

		if len([]byte(fileName)) >
			int(maxFileNameSize) {
			return errors.New(
				"filename is too long",
			)
		}

		packetType = packetMessageFile
	}

	return writePacket(
		conn,
		Packet{
			Type:     packetType,
			Message:  message,
			FileName: fileName,
			FileSize: fileSize,
		},
		file,
	)
}

func saveReceivedFile(
	reader io.Reader,
	fileName string,
	fileSize int64,
) (string, error) {
	if fileSize <= 0 {
		return "", nil
	}

	fileName = filepath.Base(fileName)

	if fileName == "." ||
		fileName == ".." ||
		fileName == "" {
		return "", errors.New(
			"invalid filename",
		)
	}

	if strings.ContainsRune(
		fileName,
		'\x00',
	) {
		return "", errors.New(
			"filename contains NUL",
		)
	}

	safeName := "received_" + fileName

	output, err := os.CreateTemp(
		".",
		".eotoc-*",
	)
	if err != nil {
		return "", err
	}

	tempPath := output.Name()

	cleanup := func() {
		output.Close()
		os.Remove(tempPath)
	}

	written, err := io.CopyN(
		output,
		bufio.NewReader(reader),
		fileSize,
	)
	if err != nil {
		cleanup()
		return "", err
	}

	if written != fileSize {
		cleanup()
		return "", errors.New(
			"incomplete file",
		)
	}

	if err := output.Sync(); err != nil {
		cleanup()
		return "", err
	}

	if err := output.Close(); err != nil {
		os.Remove(tempPath)
		return "", err
	}

	if err := os.Chmod(
		tempPath,
		0600,
	); err != nil {
		os.Remove(tempPath)
		return "", err
	}

	if err := os.Rename(
		tempPath,
		safeName,
	); err != nil {
		os.Remove(tempPath)
		return "", err
	}

	return safeName, nil
}