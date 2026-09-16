package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const defaultPort = "9999"

type EOTOCApp struct {
	app       fyne.App
	window    fyne.Window
	trust     *TrustStore

	destination *widget.Entry
	message     *widget.Entry
	fileLabel   *widget.Label
	status      *widget.Label
	identity    *widget.Label
	messages    *widget.List

	selectedFile string

	receivedMu sync.Mutex
	received   []string
}

func main() {
	eotoc := app.NewWithID(
		"com.eotoc.app",
	)

	trust, err := NewTrustStore()
	if err != nil {
		fmt.Printf(
			"[-] Trust store error: %v\n",
			err,
		)
		return
	}

	ui := &EOTOCApp{
		app:      eotoc,
		trust:    trust,
		received: make([]string, 0),
	}

	ui.window = eotoc.NewWindow(
		"EOTOC",
	)

	ui.buildUI()

	go ui.startServer()

	ui.window.Resize(
		fyne.NewSize(760, 650),
	)

	ui.window.ShowAndRun()
}

func (e *EOTOCApp) buildUI() {
	e.destination = widget.NewEntry()
	e.destination.SetPlaceHolder(
		"eotoc://192.168.1.20:9999",
	)

	e.message = widget.NewMultiLineEntry()
	e.message.SetPlaceHolder(
		"Enter your message...",
	)

	e.fileLabel = widget.NewLabel(
		"No attachment selected",
	)

	e.status = widget.NewLabel(
		"● Server starting...",
	)

	e.identity = widget.NewLabel(
		"Server identity: loading...",
	)

	selectFile := widget.NewButton(
		"Select File",
		func() {
			e.selectFile()
		},
	)

	clearFile := widget.NewButton(
		"Clear",
		func() {
			e.selectedFile = ""
			e.fileLabel.SetText(
				"No attachment selected",
			)
		},
	)

	sendButton := widget.NewButton(
		"SEND",
		func() {
			e.send()
		},
	)

	refreshIdentity := widget.NewButton(
		"Show Identity",
		func() {
			e.showLocalIdentity()
		},
	)

	e.messages = widget.NewList(
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			e.receivedMu.Lock()
			defer e.receivedMu.Unlock()

			if id < len(e.received) {
				label.SetText(
					e.received[id],
				)
			}
		},
		func() int {
			e.receivedMu.Lock()
			defer e.receivedMu.Unlock()

			return len(e.received)
		},
	)

	identityBox := container.NewVBox(
		e.status,
		e.identity,
		refreshIdentity,
	)

	fileBox := container.NewBorder(
		nil,
		nil,
		selectFile,
		clearFile,
		e.fileLabel,
	)

	sendBox := container.NewVBox(
		widget.NewLabel("Destination"),
		e.destination,
		widget.NewLabel("Message"),
		e.message,
		widget.NewLabel("Attachment"),
		fileBox,
		sendButton,
	)

	receivedBox := container.NewBorder(
		widget.NewLabel("Received Messages"),
		nil,
		nil,
		nil,
		e.messages,
	)

	content := container.NewBorder(
		identityBox,
		nil,
		nil,
		nil,
		container.NewVSplit(
			sendBox,
			receivedBox,
		),
	)

	e.window.SetContent(content)
}

func (e *EOTOCApp) selectFile() {
	dialog.NewFileOpen(
		func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(
					err,
					e.window,
				)
				return
			}

			if reader == nil {
				return
			}

			uri := reader.URI()
			reader.Close()

			path := uri.Path()

			if path == "" {
				dialog.ShowInformation(
					"EOTOC",
					"Could not determine the file path.",
					e.window,
				)
				return
			}

			e.selectedFile = filepath.Clean(path)

			e.fileLabel.SetText(
				filepath.Base(e.selectedFile),
			)
		},
		e.window,
	).Show()
}

func (e *EOTOCApp) send() {
	raw := strings.TrimSpace(
		e.destination.Text,
	)

	if raw == "" {
		dialog.ShowInformation(
			"EOTOC",
			"Enter a destination.",
			e.window,
		)
		return
	}

	address, err := parseEOTOCAddress(raw)
	if err != nil {
		dialog.ShowError(
			err,
			e.window,
		)
		return
	}

	message := e.message.Text

	if strings.TrimSpace(message) == "" &&
		e.selectedFile == "" {
		dialog.ShowInformation(
			"EOTOC",
			"Enter a message or select a file.",
			e.window,
		)
		return
	}

	e.status.SetText(
		"● Connecting...",
	)

	go func() {
		e.sendToAddress(
			address,
			message,
			e.selectedFile,
		)
	}()
}

func (e *EOTOCApp) sendToAddress(
	address string,
	message string,
	filePath string,
) {
	expected, trusted := e.trust.Get(address)

	conn, err := dialEOTOC(
		address,
		expected,
	)

	if err != nil {
		e.status.SetText(
			"● Connection rejected",
		)

		dialog.ShowError(
			fmt.Errorf(
				"connection failed:\n%w",
				err,
			),
			e.window,
		)

		return
	}

	state := conn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		conn.Close()

		dialog.ShowError(
			fmt.Errorf(
				"server did not provide a certificate",
			),
			e.window,
		)

		return
	}

	actualFingerprint :=
		fingerprintCertificate(
			state.PeerCertificates[0],
		)

	if !trusted {
		conn.Close()

		accepted := make(chan bool, 1)

		messageText := fmt.Sprintf(
			"This server is not trusted yet.\n\n"+
				"Address:\n%s\n\n"+
				"SHA-256 fingerprint:\n%s\n\n"+
				"Only trust this server if you have "+
				"verified this fingerprint through a "+
				"trusted channel.",
			address,
			actualFingerprint,
		)

		dialog.ShowConfirm(
			"New Server Identity",
			messageText,
			func(ok bool) {
				accepted <- ok
			},
			e.window,
		)

		if !<-accepted {
			e.status.SetText(
				"● Server not trusted",
			)
			return
		}

		if err := e.trust.Trust(
			address,
			actualFingerprint,
		); err != nil {
			dialog.ShowError(
				err,
				e.window,
			)
			return
		}

		// Reconnect after the user has explicitly trusted
		// the identity. No application payload was sent
		// before this point.
		conn, err = dialEOTOC(
			address,
			actualFingerprint,
		)
		if err != nil {
			dialog.ShowError(
				fmt.Errorf(
					"trusted reconnect failed:\n%w",
					err,
				),
				e.window,
			)
			return
		}
	}

	defer conn.Close()

	if err := writePacket(
		conn,
		Packet{
			Type: func() byte {
				if filePath != "" {
					return packetMessageFile
				}
				return packetMessage
			}(),
			Message: message,
			FileName: func() string {
				if filePath == "" {
					return ""
				}
				return filepath.Base(filePath)
			}(),
			FileSize: func() int64 {
				if filePath == "" {
					return 0
				}

				info, err := os.Stat(filePath)
				if err != nil {
					return 0
				}

				return info.Size()
			}(),
		},
		func() *os.File {
			if filePath == "" {
				return nil
			}

			file, err := os.Open(filePath)
			if err != nil {
				return nil
			}

			return file
		}(),
	); err != nil {
		e.status.SetText(
			"● Send failed",
		)

		dialog.ShowError(
			err,
			e.window,
		)
		return
	}

	e.status.SetText(
		"● Secure connection established",
	)

	dialog.ShowInformation(
		"Sent",
		"Message delivered successfully.",
		e.window,
	)
}

func (e *EOTOCApp) startServer() {
	e.status.SetText(
		"● Starting secure server...",
	)

	err := startEOTOCServer(
		defaultPort,
		e.handleIncoming,
	)

	if err != nil {
		e.status.SetText(
			"● Server error",
		)

		fmt.Printf(
			"[-] Server error: %v\n",
			err,
		)
		return
	}
}

func (e *EOTOCApp) handleIncoming(
	remote net.Addr,
	packet Packet,
	reader io.Reader,
) error {
	text := fmt.Sprintf(
		"From: %s\n%s",
		remote.String(),
		packet.Message,
	)

	if packet.FileSize > 0 {
		name, err := saveReceivedFile(
			reader,
			packet.FileName,
			packet.FileSize,
		)
		if err != nil {
			return err
		}

		text += fmt.Sprintf(
			"\n\nFile received: %s\nSize: %d bytes",
			name,
			packet.FileSize,
		)
	}

	e.receivedMu.Lock()

	e.received = append(
		e.received,
		text,
	)

	e.receivedMu.Unlock()

	e.messages.Refresh()

	e.status.SetText(
		"● Secure server / message received",
	)

	return nil
}

func (e *EOTOCApp) showLocalIdentity() {
	cert, err := generateServerCertificate()
	if err != nil {
		dialog.ShowError(
			err,
			e.window,
		)
		return
	}

	if len(cert.Certificate) == 0 {
		return
	}

	x509Cert, err := tls.X509KeyPair(
		cert.Certificate[0],
		cert.PrivateKey,
	)
	_ = x509Cert

	if err != nil {
		return
	}

	parsed, err := parseCertificate(
		cert.Certificate[0],
	)
	if err != nil {
		dialog.ShowError(
			err,
			e.window,
		)
		return
	}

	fingerprint := fingerprintCertificate(
		parsed,
	)

	dialog.ShowInformation(
		"EOTOC Server Identity",
		"SHA-256 fingerprint:\n\n"+fingerprint+
			"\n\nThis fingerprint identifies this "+
			"EOTOC installation.",
		e.window,
	)
}

func parseCertificate(
	der []byte,
) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func parseEOTOCAddress(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if parsed.Scheme != "eotoc" {
		return "", fmt.Errorf(
			"URI must use eotoc://",
		)
	}

	if parsed.Host == "" {
		return "", fmt.Errorf(
			"destination host is empty",
		)
	}

	host := parsed.Host

	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(
			host,
			defaultPort,
		)
	}

	return host, nil
}