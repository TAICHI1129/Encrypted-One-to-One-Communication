# EOTOC — Encrypted One-to-One Communication

A 1-on-1 encrypted peer-to-peer communication tool written in Go.
It combines RSA-based hybrid key exchange, chunked AES-256-GCM stream
encryption, and TOFU-style host key verification to securely send
messages and files.

## Features

- **Hybrid encryption**: a one-time AES-256 key is exchanged via
  RSA-OAEP (SHA-256), while the actual payload is encrypted with a
  chunked AES-256-GCM stream
- **Authenticated chunk sequencing**: each chunk's AAD includes an
  8-byte `seqNum` and a 1-byte `isFinal` flag, detecting reordering,
  replay, tampering, and truncation
- **TOFU host key verification**: on first connection, the peer's
  public key fingerprint is shown for the user to confirm; afterward
  it's checked against the value stored in `eotoc_known_hosts`
  (protected by a `sync.Mutex` to prevent TOFU race conditions)
- **Encrypted ACK/NAK**: delivery results are signaled via AES-GCM
  encrypted acknowledgements instead of plaintext, preventing forged
  ACKs
- **Progress-aware deadline extension**: during large file transfers,
  the connection deadline is extended on every write
- **Filename sanitization**: `filepath.Base` is applied and
  disallowed characters are replaced to prevent path traversal

## Requirements

- Go 1.21 or later recommended (uses only the standard library, no
  external dependencies)

## Build & Run

```bash
go build -o eotoc main.go
./eotoc
```

Or run directly:

```bash
go run main.go
```

On startup, a private key (`eotoc_private.pem`) is generated
automatically if one doesn't already exist, and the tool starts
listening on port `9999`.

## Usage

```
[ MENU ] 1: Send Message / 2: Exit
Enter your choice: 1
Destination URI (e.g., eotoc://192.168.1.10): eotoc://192.168.1.10
Message body: Hello
File attachment path (Enter to skip): /path/to/file.txt
```

- The destination URI uses the format `eotoc://<IP address>` (the
  port is fixed at `9999`)
- A file attachment is optional (leave blank to skip)
- On first connection, the host key fingerprint is displayed —
  verify it through a trusted out-of-band channel (in person, phone,
  etc.) before answering `yes`

## Communication Flow

1. The server sends its public key (PEM, RSA-2048) length-prefixed
2. The client receives the public key and verifies it via TOFU
3. The client generates a one-time AES-256 key, encrypts it with
   RSA-OAEP, and sends it
4. The client streams a header (message length, filename length,
   file size), the message body, the filename, and the file contents
   over an AES-GCM chunked stream
5. The server receives and decrypts the stream, validates size
   limits, and saves the file
6. The server returns an encrypted ACK/NAK, and the client checks the
   result

## Limits

| Item | Limit |
|---|---|
| Message size | 10 MB |
| File size | 512 MB |
| Filename length | 255 bytes |
| Public key size | 8192 bytes |
| Chunk size | 64 KB |

## Generated Files

- `eotoc_private.pem` — RSA private key (permissions 0600)
- `eotoc_known_hosts` — list of trusted hosts' IPs and fingerprints
  (TOFU)
- `received_<timestamp>_<filename>` — destination for received files

## Security Notes

  production use
- Because this uses TOFU, always verify the fingerprint shown on
  first connection through a separate trusted channel
- Be mindful of file permissions on the directory where the key file
  and known_hosts file are stored