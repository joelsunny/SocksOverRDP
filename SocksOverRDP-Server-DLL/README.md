# SocksOverRDP DLL Server

Native DLL port of `SocksOverRDP-Server.exe`.

This folder is intentionally separate from the original C++ EXE project, like
the Python and Node server ports. It opens the same RDP Dynamic Virtual Channel
(`SocksChannel`) and speaks the same application frame format:

- `uint32 connection_id`
- `uint32 payload_length`
- `uint8 close_flag`
- `payload`

## What It Implements

- Dynamic Virtual Channel open/query/duplicate through `wtsapi32`.
- Overlapped channel reads and writes.
- `ERROR_MORE_DATA` handling for Dynamic Virtual Channel reads, carried over
  from the Python/Node port fix.
- Frame-leftover buffering when a SocksOverRDP frame spans multiple channel
  reads.
- Correct outbound channel fragmentation with payload offsets, so multi-chunk
  target responses are not resent from the beginning of the buffer.
- SOCKS4, SOCKS4a, and SOCKS5 no-auth CONNECT.
- Per-connection worker threads and target socket relay.

Like the original server, BIND and UDP ASSOCIATE are not implemented.

## Build

Open or build the standalone project:

```powershell
msbuild .\SocksOverRDP-Server-DLL.vcxproj /p:Configuration=Release /p:Platform=x64
```

The output goes under:

```text
bin\<Configuration>\<Platform>\SocksOverRDP-Server-DLL.dll
```

## Exports

```cpp
INT WINAPI SocksOverRDPServerRun(INT argc, WCHAR **argv);
INT WINAPI SocksOverRDPServerRunWithOptions(
    BOOL verbose,
    BOOL debug,
    DWORD priority,
    DWORD connectTimeoutMs);
VOID WINAPI SocksOverRDPServerStop(VOID);
VOID CALLBACK Rundll32Start(HWND hwnd, HINSTANCE hinst, LPSTR cmdLine, INT nCmdShow);
```

`SocksOverRDPServerRun` accepts:

```text
-v, --verbose
-d, --debug
--priority N
--connect-timeout SECONDS
--log PATH
```

## Usage

Run it inside the remote RDP session after the client-side plugin has loaded.
The DLL is blocking: the host process stays alive while the tunnel is active,
until the RDP channel closes, the host process exits, or
`SocksOverRDPServerStop` is called.

For quick manual testing with the x64 build:

```powershell
C:\Windows\System32\rundll32.exe .\SocksOverRDP-Server-DLL.dll,Rundll32Start -v
```

For a 32-bit DLL build, use `C:\Windows\SysWOW64\rundll32.exe` instead.

The DLL writes a diagnostic log to the DLL folder by default:

```text
.\SocksOverRDP-Server-DLL.log
```

To choose the path when using `rundll32`, pass `--log`:

```powershell
C:\Windows\System32\rundll32.exe .\SocksOverRDP-Server-DLL.dll,Rundll32Start -v -d --log=C:\Temp\SocksOverRDP-Server-DLL.log
```

When the channel opens successfully, the SOCKS listener is created by the
client-side plugin, normally on `127.0.0.1:1080`, just like the original server
EXE. If `rundll32.exe` exits immediately, check that the RDP session is active
and that the client-side plugin loaded.

For an embedding host, call `SocksOverRDPServerRunWithOptions` on a worker
thread and call `SocksOverRDPServerStop` when the host wants it to exit.
