# SocksOverRDP Node Server

Node.js port of `SocksOverRDP-Server.exe`.

This script runs inside the remote RDP session, opens the same Dynamic Virtual
Channel used by the existing client plugin, and relays SOCKS traffic without
building the original C++ server EXE.

## What It Implements

- Dynamic Virtual Channel open/query/duplicate through Win32 FFI.
- Overlapped `ReadFile` and `WriteFile` so TCP socket relay can stay async.
- Existing channel name: `SocksChannel`.
- Existing application frame format:
  - `uint32 connection_id`
  - `uint32 payload_length`
  - `uint8 close_flag`
  - `payload`
- SOCKS4 and SOCKS4a CONNECT.
- SOCKS5 no-auth CONNECT.
- Per-connection relay between client-side SOCKS streams and outbound TCP sockets.

Like the original server, BIND and UDP ASSOCIATE are not implemented.

## Setup

Node cannot call the Windows Terminal Services API by itself, so this port uses
FFI packages:

```powershell
cd .\SocksOverRDP-Server-Node
npm install
```

## Usage

Run this from inside the remote RDP session after the client-side plugin has
loaded:

```powershell
node .\server.js -v
```

Useful options:

```powershell
node .\server.js -v -d
node .\server.js --connect-timeout 5
```

## Checks

```powershell
npm run check
npm run test:helpers
```

The protocol helpers are testable without FFI installed. Opening the RDP
channel requires `npm install` and an active RDP session with the plugin loaded.
