#!/usr/bin/env python3
"""Python server-side implementation for SocksOverRDP.

This replaces the original remote-side C++ EXE with a Python process that:

* opens the same RDP Dynamic Virtual Channel (`SocksChannel`),
* decodes the existing SocksOverRDP frame format,
* handles SOCKS4, SOCKS4a, and SOCKS5 CONNECT requests, and
* relays bytes between the RDP client plugin and outbound TCP sockets.
"""

from __future__ import annotations

import argparse
import ctypes
import queue
import socket
import struct
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass


CHANNEL_NAME = b"SocksChannel"
CHANNEL_PDU_HEADER_SIZE = 8
CHANNEL_PDU_LENGTH = 1600
BUF_SIZE = 4096

FRAME_HEADER = struct.Struct("<IIB")

WTS_CURRENT_SESSION = 0xFFFFFFFF
WTS_CHANNEL_OPTION_DYNAMIC = 0x00000001
WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH = 0x00000004
WTS_VIRTUAL_FILE_HANDLE = 1
DUPLICATE_SAME_ACCESS = 0x00000002

ERROR_IO_PENDING = 997
ERROR_MORE_DATA = 234
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_FAILED = 0xFFFFFFFF


class WinApiError(OSError):
    """Raised when a Windows API call fails."""

    @classmethod
    def last(cls, operation: str) -> "WinApiError":
        code = ctypes.get_last_error()
        return cls(code, f"{operation} failed with Win32 error {code}")


class ProtocolError(Exception):
    """Raised when a SOCKS request or SocksOverRDP frame is malformed."""


class RemoteStreamClosed(EOFError):
    """Raised when the client-side SOCKS stream closes during parsing."""


ULONG_PTR = ctypes.c_size_t


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


@dataclass(frozen=True)
class Frame:
    connection_id: int
    payload: bytes
    close: bool = False


def iter_frames(buffer: bytes) -> tuple[list[Frame], bytes]:
    """Decode complete SocksOverRDP frames, returning frames and leftovers."""

    frames: list[Frame] = []
    offset = 0
    while len(buffer) - offset >= FRAME_HEADER.size:
        connection_id, payload_length, close_flag = FRAME_HEADER.unpack_from(buffer, offset)
        frame_end = offset + FRAME_HEADER.size + payload_length
        if frame_end > len(buffer):
            break

        payload_start = offset + FRAME_HEADER.size
        frames.append(
            Frame(
                connection_id=connection_id,
                payload=buffer[payload_start:frame_end],
                close=close_flag == 1,
            )
        )
        offset = frame_end

    return frames, buffer[offset:]


def encode_frame(frame: Frame) -> bytes:
    close_flag = 1 if frame.close else 0
    return FRAME_HEADER.pack(frame.connection_id, len(frame.payload), close_flag) + frame.payload


def port_to_bytes(port: int) -> bytes:
    return struct.pack(">H", port)


def bytes_to_port(raw: bytes) -> int:
    return struct.unpack(">H", raw)[0]


class RdpVirtualChannel:
    """Thin ctypes wrapper around a Windows RDP Dynamic Virtual Channel."""

    def __init__(self, channel_name: bytes = CHANNEL_NAME, priority: int = WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH):
        self._wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._channel_name = channel_name
        self._priority = priority
        self._wts_handle: int | None = None
        self._file_handle: int | None = None
        self._configure_api()

    def _configure_api(self) -> None:
        self._wtsapi32.WTSVirtualChannelOpenEx.argtypes = [wintypes.DWORD, wintypes.LPSTR, wintypes.DWORD]
        self._wtsapi32.WTSVirtualChannelOpenEx.restype = wintypes.HANDLE

        self._wtsapi32.WTSVirtualChannelQuery.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._wtsapi32.WTSVirtualChannelQuery.restype = wintypes.BOOL

        self._wtsapi32.WTSVirtualChannelClose.argtypes = [wintypes.HANDLE]
        self._wtsapi32.WTSVirtualChannelClose.restype = wintypes.BOOL

        self._wtsapi32.WTSFreeMemory.argtypes = [wintypes.LPVOID]
        self._wtsapi32.WTSFreeMemory.restype = None

        self._kernel32.GetCurrentProcess.argtypes = []
        self._kernel32.GetCurrentProcess.restype = wintypes.HANDLE

        self._kernel32.DuplicateHandle.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        self._kernel32.DuplicateHandle.restype = wintypes.BOOL

        self._kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        self._kernel32.CreateEventW.restype = wintypes.HANDLE

        self._kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD

        self._kernel32.GetOverlappedResult.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(OVERLAPPED),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
        ]
        self._kernel32.GetOverlappedResult.restype = wintypes.BOOL

        self._kernel32.ReadFile.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(OVERLAPPED),
        ]
        self._kernel32.ReadFile.restype = wintypes.BOOL

        self._kernel32.WriteFile.argtypes = [
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(OVERLAPPED),
        ]
        self._kernel32.WriteFile.restype = wintypes.BOOL

        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL

    @staticmethod
    def _handle_value(handle) -> int | None:
        if handle is None:
            return None
        return handle.value if hasattr(handle, "value") else int(handle)

    @staticmethod
    def _valid_handle(handle: int | None) -> bool:
        return handle not in (None, 0, -1)

    def open(self) -> None:
        flags = WTS_CHANNEL_OPTION_DYNAMIC | self._priority
        self._wts_handle = self._handle_value(
            self._wtsapi32.WTSVirtualChannelOpenEx(
                WTS_CURRENT_SESSION,
                ctypes.c_char_p(self._channel_name),
                flags,
            )
        )
        if not self._valid_handle(self._wts_handle):
            raise WinApiError.last("WTSVirtualChannelOpenEx")

        handle_ptr = wintypes.LPVOID()
        length = wintypes.DWORD()
        ok = self._wtsapi32.WTSVirtualChannelQuery(
            self._wts_handle,
            WTS_VIRTUAL_FILE_HANDLE,
            ctypes.byref(handle_ptr),
            ctypes.byref(length),
        )
        if not ok:
            raise WinApiError.last("WTSVirtualChannelQuery")

        try:
            if length.value != ctypes.sizeof(wintypes.HANDLE):
                raise WinApiError(87, f"unexpected virtual file handle size {length.value}")

            source_handle = ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents
            current_process = self._kernel32.GetCurrentProcess()
            duplicated = wintypes.HANDLE()
            ok = self._kernel32.DuplicateHandle(
                current_process,
                source_handle,
                current_process,
                ctypes.byref(duplicated),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            )
            if not ok:
                raise WinApiError.last("DuplicateHandle")
            self._file_handle = self._handle_value(duplicated)
        finally:
            if handle_ptr:
                self._wtsapi32.WTSFreeMemory(handle_ptr)

    def _new_event(self, operation: str) -> int:
        event = self._handle_value(self._kernel32.CreateEventW(None, True, False, None))
        if not self._valid_handle(event):
            raise WinApiError.last(f"CreateEventW({operation})")
        return event

    def _finish_overlapped(
        self,
        operation: str,
        ok: bool,
        handle: int,
        overlapped: OVERLAPPED,
        transferred: wintypes.DWORD,
        *,
        allow_more_data: bool = False,
    ) -> tuple[int, bool]:
        if ok:
            return transferred.value, False

        err = ctypes.get_last_error()
        if err == ERROR_MORE_DATA and allow_more_data:
            count = transferred.value or int(overlapped.InternalHigh or 0)
            return count, True
        if err != ERROR_IO_PENDING:
            raise WinApiError(err, f"{operation} failed with Win32 error {err}")

        wait_rc = self._kernel32.WaitForSingleObject(overlapped.hEvent, INFINITE)
        if wait_rc != WAIT_OBJECT_0:
            if wait_rc == WAIT_FAILED:
                raise WinApiError.last(f"WaitForSingleObject({operation})")
            raise WinApiError(wait_rc, f"WaitForSingleObject({operation}) returned {wait_rc}")

        ok = self._kernel32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(transferred), False)
        if not ok:
            err = ctypes.get_last_error()
            if err == ERROR_MORE_DATA and allow_more_data:
                count = transferred.value or int(overlapped.InternalHigh or 0)
                return count, True
            raise WinApiError.last(f"GetOverlappedResult({operation})")
        return transferred.value, False

    def _read_file_once(self, size: int) -> tuple[bytes, bool]:
        if not self._valid_handle(self._file_handle):
            raise WinApiError(6, "channel file handle is not open")

        buffer = ctypes.create_string_buffer(size)
        transferred = wintypes.DWORD()
        overlapped = OVERLAPPED()
        event = self._new_event("ReadFile")
        overlapped.hEvent = event
        try:
            ok = self._kernel32.ReadFile(
                self._file_handle,
                buffer,
                size,
                ctypes.byref(transferred),
                ctypes.byref(overlapped),
            )
            count, more_data = self._finish_overlapped(
                "ReadFile",
                bool(ok),
                self._file_handle,
                overlapped,
                transferred,
                allow_more_data=True,
            )
            return buffer.raw[:count], more_data
        finally:
            self._kernel32.CloseHandle(event)

    def _read_file(self, size: int) -> bytes:
        chunks = []
        while True:
            chunk, more_data = self._read_file_once(size)
            chunks.append(chunk)
            if not more_data:
                return b"".join(chunks)

    def _write_file(self, data: bytes) -> int:
        if not self._valid_handle(self._file_handle):
            raise WinApiError(6, "channel file handle is not open")

        buffer = ctypes.create_string_buffer(data)
        transferred = wintypes.DWORD()
        overlapped = OVERLAPPED()
        event = self._new_event("WriteFile")
        overlapped.hEvent = event
        try:
            ok = self._kernel32.WriteFile(
                self._file_handle,
                buffer,
                len(data),
                ctypes.byref(transferred),
                ctypes.byref(overlapped),
            )
            count, _more_data = self._finish_overlapped("WriteFile", bool(ok), self._file_handle, overlapped, transferred)
            if count != len(data):
                raise WinApiError(0, f"WriteFile wrote {count} of {len(data)} bytes")
            return count
        finally:
            self._kernel32.CloseHandle(event)

    def read_pdu_payload(self) -> bytes:
        data = self._read_file(CHANNEL_PDU_LENGTH)
        if len(data) < CHANNEL_PDU_HEADER_SIZE:
            return b""
        return data[CHANNEL_PDU_HEADER_SIZE:]

    def write_frame(self, frame: Frame) -> int:
        return self._write_file(encode_frame(frame))

    def close(self) -> None:
        if self._valid_handle(self._file_handle):
            self._kernel32.CloseHandle(self._file_handle)
            self._file_handle = None
        if self._valid_handle(self._wts_handle):
            self._wtsapi32.WTSVirtualChannelClose(self._wts_handle)
            self._wts_handle = None

    def __enter__(self) -> "RdpVirtualChannel":
        self.open()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


class RemoteInput:
    """Stream facade over the plugin's per-connection channel frames."""

    def __init__(self) -> None:
        self._queue: queue.Queue[tuple[bytes, bool] | None] = queue.Queue()
        self._buffer = bytearray()
        self._eof = False

    def feed(self, payload: bytes, close: bool) -> None:
        self._queue.put((payload, close))

    def close(self) -> None:
        self._queue.put(None)

    def _pull(self) -> None:
        item = self._queue.get()
        if item is None:
            self._eof = True
            return

        payload, close = item
        if payload:
            self._buffer.extend(payload)
        if close:
            self._eof = True

    def read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size and not self._eof:
            self._pull()

        if len(self._buffer) < size:
            raise RemoteStreamClosed("client stream closed")

        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read_until_null(self, max_bytes: int = BUF_SIZE) -> bytes:
        while True:
            nul_at = self._buffer.find(0)
            if nul_at >= 0:
                data = bytes(self._buffer[:nul_at])
                del self._buffer[: nul_at + 1]
                return data
            if len(self._buffer) > max_bytes:
                raise ProtocolError("unterminated field is too long")
            if self._eof:
                raise RemoteStreamClosed("client stream closed")
            self._pull()

    def read_some(self, max_bytes: int = BUF_SIZE) -> tuple[bytes, bool]:
        while not self._buffer and not self._eof:
            self._pull()

        if not self._buffer:
            return b"", True

        data = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return data, self._eof and not self._buffer


class SocksOverRdpServer:
    def __init__(self, channel: RdpVirtualChannel, *, verbose: bool, debug: bool, connect_timeout: float):
        self.channel = channel
        self.verbose = verbose
        self.debug = debug
        self.connect_timeout = connect_timeout
        self._connections: dict[int, ProxyConnection] = {}
        self._connections_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._shutdown = threading.Event()

    def log(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)

    def debug_log(self, message: str) -> None:
        if self.debug:
            print(message, flush=True)

    def serve_forever(self) -> int:
        leftovers = b""
        while not self._shutdown.is_set():
            payload = self.channel.read_pdu_payload()
            if not payload:
                continue

            frames, leftovers = iter_frames(leftovers + payload)
            for frame in frames:
                self._dispatch_frame(frame)

        return 0

    def _dispatch_frame(self, frame: Frame) -> None:
        with self._connections_lock:
            connection = self._connections.get(frame.connection_id)
            if connection is None:
                connection = ProxyConnection(self, frame.connection_id)
                self._connections[frame.connection_id] = connection
                connection.start()
                self.debug_log(f"[*] {frame.connection_id:08x}: connection worker started")

        connection.feed(frame)

    def send_to_client(self, connection_id: int, payload: bytes, *, close: bool = False) -> None:
        if not payload and not close:
            return

        with self._write_lock:
            if payload:
                offset = 0
                while offset < len(payload):
                    chunk = payload[offset : offset + BUF_SIZE]
                    offset += len(chunk)
                    self.channel.write_frame(Frame(connection_id, chunk, close=close and offset >= len(payload)))
            elif close:
                self.channel.write_frame(Frame(connection_id, b"", close=True))

    def remove_connection(self, connection_id: int, connection: "ProxyConnection") -> None:
        with self._connections_lock:
            if self._connections.get(connection_id) is connection:
                del self._connections[connection_id]
                self.debug_log(f"[*] {connection_id:08x}: connection worker removed")

    def shutdown(self) -> None:
        self._shutdown.set()
        with self._connections_lock:
            connections = list(self._connections.values())
        for connection in connections:
            connection.stop()


class ProxyConnection:
    def __init__(self, server: SocksOverRdpServer, connection_id: int):
        self.server = server
        self.connection_id = connection_id
        self.input = RemoteInput()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name=f"socks-{connection_id:08x}", daemon=True)
        self._socket: socket.socket | None = None

    def start(self) -> None:
        self.thread.start()

    def feed(self, frame: Frame) -> None:
        if not self.stop_event.is_set():
            self.input.feed(frame.payload, frame.close)

    def stop(self) -> None:
        self.stop_event.set()
        self.input.close()
        if self._socket is not None:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._socket.close()
            except OSError:
                pass

    def send(self, payload: bytes, *, close: bool = False) -> None:
        self.server.send_to_client(self.connection_id, payload, close=close)

    def run(self) -> None:
        try:
            version = self.input.read_exact(1)[0]
            if version == 4:
                relay_socket = self._handle_socks4()
            elif version == 5:
                relay_socket = self._handle_socks5()
            else:
                self.server.debug_log(f"[-] {self.connection_id:08x}: unknown SOCKS version {version}")
                self.send(b"", close=True)
                return

            if relay_socket is None:
                return

            self._socket = relay_socket
            self._relay(relay_socket)
        except RemoteStreamClosed:
            self.server.debug_log(f"[-] {self.connection_id:08x}: client stream closed during negotiation")
        except ProtocolError as exc:
            self.server.debug_log(f"[-] {self.connection_id:08x}: protocol error: {exc}")
            try:
                self.send(b"", close=True)
            except OSError:
                pass
        except OSError as exc:
            self.server.debug_log(f"[-] {self.connection_id:08x}: socket/channel error: {exc}")
        finally:
            self.stop()
            self.server.remove_connection(self.connection_id, self)

    def _handle_socks4(self) -> socket.socket | None:
        command = self.input.read_exact(1)[0]
        port = bytes_to_port(self.input.read_exact(2))
        ip_bytes = self.input.read_exact(4)
        _user_id = self.input.read_until_null()

        if ip_bytes[:3] == b"\x00\x00\x00" and ip_bytes[3] != 0:
            host = self.input.read_until_null().decode("idna")
            self.server.log(f"[+] {self.connection_id:08x}: SOCKS4a CONNECT {host}:{port}")
        else:
            host = socket.inet_ntop(socket.AF_INET, ip_bytes)
            self.server.log(f"[+] {self.connection_id:08x}: SOCKS4 CONNECT {host}:{port}")

        if command != 1:
            self.server.debug_log(f"[-] {self.connection_id:08x}: SOCKS4 command {command} is unsupported")
            self.send(self._socks4_reply(0x5B), close=True)
            return None

        relay_socket = self._connect(host, port)
        if relay_socket is None:
            self.send(self._socks4_reply(0x5B), close=True)
            return None

        self.send(self._socks4_reply(0x5A))
        return relay_socket

    def _handle_socks5(self) -> socket.socket | None:
        method_count = self.input.read_exact(1)[0]
        methods = self.input.read_exact(method_count)
        if 0x00 not in methods:
            self.server.debug_log(f"[-] {self.connection_id:08x}: SOCKS5 no-auth method not offered")
            self.send(b"\x05\xff", close=True)
            return None

        self.send(b"\x05\x00")

        version, command, reserved, address_type = self.input.read_exact(4)
        if version != 5 or reserved != 0:
            raise ProtocolError("invalid SOCKS5 request header")

        try:
            host, port = self._read_socks5_address(address_type)
        except ProtocolError as exc:
            self.server.debug_log(f"[-] {self.connection_id:08x}: {exc}")
            self.send(self._socks5_reply(0x08), close=True)
            return None

        self.server.log(f"[+] {self.connection_id:08x}: SOCKS5 CONNECT {host}:{port}")

        if command != 1:
            self.server.debug_log(f"[-] {self.connection_id:08x}: SOCKS5 command {command} is unsupported")
            self.send(self._socks5_reply(0x07), close=True)
            return None

        relay_socket = self._connect(host, port)
        if relay_socket is None:
            self.send(self._socks5_reply(0x05), close=True)
            return None

        self.send(self._socks5_reply(0x00))
        return relay_socket

    def _read_socks5_address(self, address_type: int) -> tuple[str, int]:
        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, self.input.read_exact(4))
        elif address_type == 3:
            length = self.input.read_exact(1)[0]
            if length == 0:
                raise ProtocolError("empty SOCKS5 domain name")
            host = self.input.read_exact(length).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, self.input.read_exact(16))
        else:
            raise ProtocolError(f"unsupported SOCKS5 address type {address_type}")

        return host, bytes_to_port(self.input.read_exact(2))

    def _connect(self, host: str, port: int) -> socket.socket | None:
        try:
            relay_socket = socket.create_connection((host, port), timeout=self.server.connect_timeout)
            relay_socket.settimeout(0.5)
            return relay_socket
        except OSError as exc:
            self.server.debug_log(f"[-] {self.connection_id:08x}: connect({host}:{port}) failed: {exc}")
            return None

    @staticmethod
    def _socks4_reply(status: int) -> bytes:
        return bytes([0x00, status]) + b"\x00" * 6

    @staticmethod
    def _socks5_reply(status: int) -> bytes:
        return bytes([0x05, status, 0x00, 0x01]) + b"\x00" * 6

    def _relay(self, relay_socket: socket.socket) -> None:
        socket_reader = threading.Thread(
            target=self._relay_socket_to_client,
            args=(relay_socket,),
            name=f"target-{self.connection_id:08x}",
            daemon=True,
        )
        socket_reader.start()

        try:
            while not self.stop_event.is_set():
                payload, closed = self.input.read_some()
                if payload:
                    relay_socket.sendall(payload)
                if closed:
                    self.server.debug_log(f"[*] {self.connection_id:08x}: client side closed")
                    break
        finally:
            self.stop_event.set()
            try:
                relay_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                relay_socket.close()
            except OSError:
                pass
            socket_reader.join(timeout=1.0)

    def _relay_socket_to_client(self, relay_socket: socket.socket) -> None:
        sent_close = False
        try:
            while not self.stop_event.is_set():
                try:
                    payload = relay_socket.recv(BUF_SIZE)
                except socket.timeout:
                    continue

                if payload:
                    self.server.send_to_client(self.connection_id, payload)
                    continue

                if not self.stop_event.is_set():
                    self.server.debug_log(f"[*] {self.connection_id:08x}: target side closed")
                    self.server.send_to_client(self.connection_id, b"", close=True)
                    sent_close = True
                break
        except OSError as exc:
            if not self.stop_event.is_set():
                self.server.debug_log(f"[-] {self.connection_id:08x}: recv target failed: {exc}")
                try:
                    self.server.send_to_client(self.connection_id, b"", close=True)
                    sent_close = True
                except OSError:
                    pass
        finally:
            if sent_close:
                self.input.close()
            self.stop_event.set()


def run(args: argparse.Namespace) -> int:
    print("Socks Over RDP Python server")
    with RdpVirtualChannel(priority=args.priority) as channel:
        print("[*] Channel opened over RDP")
        server = SocksOverRdpServer(
            channel,
            verbose=args.verbose,
            debug=args.debug,
            connect_timeout=args.connect_timeout,
        )
        try:
            return server.serve_forever()
        except KeyboardInterrupt:
            print("[*] CTRL+C pressed. Closing down.")
            server.shutdown()
            return 130


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SocksOverRDP Python server")
    parser.add_argument("-v", "--verbose", action="store_true", help="log connection targets")
    parser.add_argument("-d", "--debug", action="store_true", help="log detailed relay events")
    parser.add_argument(
        "--priority",
        type=int,
        default=WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH,
        help="dynamic virtual channel priority flag, default: 4",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=10.0,
        help="outbound TCP connect timeout in seconds, default: 10",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run(args)
    except OSError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
