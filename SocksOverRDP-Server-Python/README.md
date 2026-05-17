# SocksOverRDP Python Server

Python port of `SocksOverRDP-Server.exe`.

This script runs inside the remote RDP session, opens the same Dynamic Virtual
Channel used by the existing client plugin, and relays SOCKS traffic without a
compiled server EXE.

## What It Implements

- Dynamic Virtual Channel open/query/duplicate via `ctypes`.
- Existing channel name: `SocksChannel`.
- Existing application frame format:
  - `uint32 connection_id`
  - `uint32 payload_length`
  - `uint8 close_flag`
  - `payload`
- SOCKS4 and SOCKS4a CONNECT.
- SOCKS5 no-auth CONNECT.
- Per-connection worker threads and outbound TCP relay.
- Close propagation from target sockets back to the client plugin.

Like the original server, BIND and UDP ASSOCIATE are not implemented.

## Usage

Run this from inside the remote RDP session after the client-side plugin has
loaded:

```powershell
python .\server.py -v
```

Useful options:

```powershell
python .\server.py -v -d
python .\server.py --connect-timeout 5
```
