# EOTOC — Encrypted One-to-One Communication System

A 1-on-1 encrypted peer-to-peer communication tool written in Go.

## Features

- Fyne GUI
- TLS 1.3
- Persistent server identity
- SHA-256 certificate fingerprint
- Trust On First Use (TOFU)
- Server identity change detection
- Text messages
- File attachments
- Streaming file transfer
- File size limits
- Safe received filenames
- Atomic received-file creation

## Requirements

- Go 1.24 or newer
- A desktop environment supported by Fyne

## Build

Run:

go mod tidy

Then:

go build .

## Run

Run the generated executable.

On Linux/macOS:

./eotoc

On Windows:

eotoc.exe

## Server Identity

EOTOC creates a persistent server identity in:

~/.eotoc/

The identity consists of:

server.crt
server.key

The server certificate fingerprint is calculated using SHA-256.

## Trust Model

The first time a client connects to a server, EOTOC displays the server's SHA-256 fingerprint.

The user should verify the fingerprint through a trusted communication channel before selecting Trust.

After trust is established, the fingerprint is stored in:

~/.eotoc/trusted_peers.json

Future connections must present the same fingerprint.

If the server certificate changes, the connection is rejected.

## Security Model

EOTOC uses TLS 1.3 for transport encryption and integrity protection.

EOTOC does not implement its own AES/RSA transport encryption protocol.

The application protocol operates above TLS.

## Default Port

9999

Example:

eotoc://192.168.1.20:9999

If no port is specified:

eotoc://192.168.1.20

defaults to port 9999.

## Limits

Maximum message size:

1 MiB

Maximum file size:

1 GiB

Maximum filename size:

255 bytes

## Important

TOFU protects against unexpected identity changes after the first trust decision.

The first fingerprint must still be verified through a trusted channel.

For high-security deployments, a dedicated PKI or another independently authenticated identity system should be used.