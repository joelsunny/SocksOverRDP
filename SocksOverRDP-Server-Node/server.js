"use strict";

const net = require("node:net");

const CHANNEL_NAME = "SocksChannel";
const CHANNEL_PDU_HEADER_SIZE = 8;
const CHANNEL_PDU_LENGTH = 1600;
const BUF_SIZE = 4096;
const FRAME_HEADER_SIZE = 9;

const WTS_CURRENT_SESSION = 0xffffffff;
const WTS_CHANNEL_OPTION_DYNAMIC = 0x00000001;
const WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH = 0x00000004;
const WTS_VIRTUAL_FILE_HANDLE = 1;
const DUPLICATE_SAME_ACCESS = 0x00000002;

const ERROR_IO_PENDING = 997;
const ERROR_MORE_DATA = 234;
const WAIT_OBJECT_0 = 0;
const WAIT_FAILED = 0xffffffff;
const INFINITE = 0xffffffff;

class ProtocolError extends Error {}
class RemoteStreamClosed extends Error {}

function encodeFrame({ connectionId, payload = Buffer.alloc(0), close = false }) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const frame = Buffer.alloc(FRAME_HEADER_SIZE + body.length);
  frame.writeUInt32LE(connectionId >>> 0, 0);
  frame.writeUInt32LE(body.length, 4);
  frame.writeUInt8(close ? 1 : 0, 8);
  body.copy(frame, FRAME_HEADER_SIZE);
  return frame;
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;

  while (buffer.length - offset >= FRAME_HEADER_SIZE) {
    const connectionId = buffer.readUInt32LE(offset);
    const payloadLength = buffer.readUInt32LE(offset + 4);
    const close = buffer.readUInt8(offset + 8) === 1;
    const frameEnd = offset + FRAME_HEADER_SIZE + payloadLength;

    if (frameEnd > buffer.length) {
      break;
    }

    frames.push({
      connectionId,
      close,
      payload: buffer.subarray(offset + FRAME_HEADER_SIZE, frameEnd)
    });
    offset = frameEnd;
  }

  return {
    frames,
    leftover: buffer.subarray(offset)
  };
}

function portToBuffer(port) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(port);
  return buffer;
}

function bufferToPort(buffer, offset = 0) {
  return buffer.readUInt16BE(offset);
}

function ipv4FromBuffer(buffer) {
  return Array.from(buffer.subarray(0, 4)).join(".");
}

function loadWin32Ffi() {
  let koffi;

  try {
    koffi = require("koffi");
  } catch (error) {
    if (error.code === "MODULE_NOT_FOUND") {
      throw new Error(
        "The Node server requires koffi. " +
          "Run `npm install` in SocksOverRDP-Server-Node before starting the server."
      );
    }
    throw error;
  }

  const HANDLE = koffi.pointer("HANDLE", koffi.opaque());
  const DWORD = koffi.alias("DWORD", "uint32_t");
  const OVERLAPPED = koffi.struct("OVERLAPPED", {
    Internal: "uintptr_t",
    InternalHigh: "uintptr_t",
    Offset: DWORD,
    OffsetHigh: DWORD,
    hEvent: HANDLE
  });

  const kernel32 = koffi.load("kernel32.dll");
  const wtsapi32 = koffi.load("wtsapi32.dll");

  return {
    koffi,
    HANDLE,
    DWORD,
    OVERLAPPED,
    kernel32: {
      GetLastError: kernel32.func("DWORD __stdcall GetLastError(void)"),
      GetCurrentProcess: kernel32.func("HANDLE __stdcall GetCurrentProcess(void)"),
      DuplicateHandle: kernel32.func(
        "int __stdcall DuplicateHandle(HANDLE, HANDLE, HANDLE, _Out_ HANDLE *, DWORD, int, DWORD)"
      ),
      CreateEventW: kernel32.func("HANDLE __stdcall CreateEventW(void *, int, int, void *)"),
      WaitForSingleObject: kernel32.func("DWORD __stdcall WaitForSingleObject(HANDLE, DWORD)"),
      GetOverlappedResult: kernel32.func(
        "int __stdcall GetOverlappedResult(HANDLE, _Inout_ OVERLAPPED *, _Out_ DWORD *, int)"
      ),
      ReadFile: kernel32.func("int __stdcall ReadFile(HANDLE, _Out_ void *, DWORD, _Out_ DWORD *, _Inout_ OVERLAPPED *)"),
      WriteFile: kernel32.func(
        "int __stdcall WriteFile(HANDLE, const void *, DWORD, _Out_ DWORD *, _Inout_ OVERLAPPED *)"
      ),
      CloseHandle: kernel32.func("int __stdcall CloseHandle(HANDLE)")
    },
    wtsapi32: {
      WTSVirtualChannelOpenEx: wtsapi32.func("HANDLE __stdcall WTSVirtualChannelOpenEx(DWORD, const char *, DWORD)"),
      WTSVirtualChannelQuery: wtsapi32.func(
        "int __stdcall WTSVirtualChannelQuery(HANDLE, int, _Out_ void **, _Out_ DWORD *)"
      ),
      WTSVirtualChannelClose: wtsapi32.func("int __stdcall WTSVirtualChannelClose(HANDLE)"),
      WTSFreeMemory: wtsapi32.func("void __stdcall WTSFreeMemory(void *)")
    }
  };
}

class RdpVirtualChannel {
  constructor({ channelName = CHANNEL_NAME, priority = WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH } = {}) {
    this.channelName = channelName;
    this.priority = priority;
    this.win32 = null;
    this.wtsHandle = null;
    this.fileHandle = null;
  }

  _load() {
    if (!this.win32) {
      this.win32 = loadWin32Ffi();
    }
    return this.win32;
  }

  _isNullPointer(pointer) {
    const { koffi } = this._load();
    return pointer == null || koffi.address(pointer) === 0n;
  }

  _lastError(operation) {
    const { kernel32 } = this._load();
    const code = kernel32.GetLastError();
    return new Error(`${operation} failed with Win32 error ${code}`);
  }

  async open() {
    const { koffi, HANDLE, kernel32, wtsapi32 } = this._load();
    const flags = WTS_CHANNEL_OPTION_DYNAMIC | this.priority;
    const wtsHandle = wtsapi32.WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, this.channelName, flags);

    if (this._isNullPointer(wtsHandle)) {
      throw this._lastError("WTSVirtualChannelOpenEx");
    }
    this.wtsHandle = wtsHandle;

    const fileHandleMemoryPtr = [null];
    const lengthPtr = [0];
    const ok = wtsapi32.WTSVirtualChannelQuery(
      this.wtsHandle,
      WTS_VIRTUAL_FILE_HANDLE,
      fileHandleMemoryPtr,
      lengthPtr
    );
    if (!ok) {
      throw this._lastError("WTSVirtualChannelQuery");
    }

    const fileHandleMemory = fileHandleMemoryPtr[0];
    try {
      if (lengthPtr[0] !== koffi.sizeof(HANDLE)) {
        throw new Error(`unexpected virtual file handle size ${lengthPtr[0]}`);
      }

      const sourceHandle = koffi.decode(fileHandleMemory, HANDLE);
      const duplicatedPtr = [null];
      const currentProcess = kernel32.GetCurrentProcess();
      const duplicated = kernel32.DuplicateHandle(
        currentProcess,
        sourceHandle,
        currentProcess,
        duplicatedPtr,
        0,
        0,
        DUPLICATE_SAME_ACCESS
      );
      if (!duplicated) {
        throw this._lastError("DuplicateHandle");
      }
      this.fileHandle = duplicatedPtr[0];
    } finally {
      if (!this._isNullPointer(fileHandleMemory)) {
        wtsapi32.WTSFreeMemory(fileHandleMemory);
      }
    }
  }

  async readPduPayload() {
    const data = await this._readFile(CHANNEL_PDU_LENGTH);
    if (data.length < CHANNEL_PDU_HEADER_SIZE) {
      return Buffer.alloc(0);
    }
    return data.subarray(CHANNEL_PDU_HEADER_SIZE);
  }

  async writeFrame(frame) {
    return this._writeFile(encodeFrame(frame));
  }

  async _readFile(size) {
    const chunks = [];
    for (;;) {
      const { data, moreData } = await this._readFileOnce(size);
      chunks.push(data);
      if (!moreData) {
        return Buffer.concat(chunks);
      }
    }
  }

  async _readFileOnce(size) {
    const { koffi, DWORD, kernel32, OVERLAPPED } = this._load();
    const buffer = koffi.alloc("uint8_t", size);
    const transferredPtr = this._allocStable(DWORD, 0);
    const overlapped = this._allocOverlapped();
    const event = this._createEvent("ReadFile");
    this._writeOverlapped(overlapped, event);

    try {
      const ok = kernel32.ReadFile(this.fileHandle, buffer, size, transferredPtr, overlapped);
      const { count, moreData } = await this._finishOverlapped("ReadFile", ok, overlapped, transferredPtr, {
        allowMoreData: true
      });
      return { data: Buffer.from(koffi.view(buffer, count)), moreData };
    } finally {
      kernel32.CloseHandle(event);
    }
  }

  async _writeFile(data) {
    const { DWORD, kernel32 } = this._load();
    const buffer = Buffer.from(data);
    const transferredPtr = this._allocStable(DWORD, 0);
    const overlapped = this._allocOverlapped();
    const event = this._createEvent("WriteFile");
    this._writeOverlapped(overlapped, event);

    try {
      const ok = kernel32.WriteFile(this.fileHandle, buffer, buffer.length, transferredPtr, overlapped);
      const { count } = await this._finishOverlapped("WriteFile", ok, overlapped, transferredPtr);
      if (count !== buffer.length) {
        throw new Error(`WriteFile wrote ${count} of ${buffer.length} bytes`);
      }
      return count;
    } finally {
      kernel32.CloseHandle(event);
    }
  }

  _createEvent(operation) {
    const { kernel32 } = this._load();
    const event = kernel32.CreateEventW(null, 1, 0, null);
    if (this._isNullPointer(event)) {
      throw this._lastError(`CreateEventW(${operation})`);
    }
    return event;
  }

  _allocStable(type, value) {
    const { koffi } = this._load();
    const pointer = koffi.alloc(type, 1);
    koffi.encode(pointer, type, value);
    return pointer;
  }

  _allocOverlapped() {
    const { koffi, OVERLAPPED } = this._load();
    return koffi.alloc(OVERLAPPED, 1);
  }

  _readStable(pointer, type) {
    const { koffi } = this._load();
    return koffi.decode(pointer, type);
  }

  _writeOverlapped(pointer, event) {
    const { koffi, OVERLAPPED } = this._load();
    koffi.encode(pointer, OVERLAPPED, {
      Internal: 0,
      InternalHigh: 0,
      Offset: 0,
      OffsetHigh: 0,
      hEvent: event
    });
  }

  async _finishOverlapped(operation, ok, overlapped, transferredPtr, { allowMoreData = false } = {}) {
    const { DWORD, kernel32, OVERLAPPED } = this._load();

    if (ok) {
      return { count: this._readStable(transferredPtr, DWORD), moreData: false };
    }

    const errorCode = kernel32.GetLastError();
    if (errorCode === ERROR_MORE_DATA && allowMoreData) {
      const overlappedData = this._readStable(overlapped, OVERLAPPED);
      return {
        count: this._readStable(transferredPtr, DWORD) || Number(overlappedData.InternalHigh || 0),
        moreData: true
      };
    }
    if (errorCode !== ERROR_IO_PENDING) {
      throw new Error(`${operation} failed with Win32 error ${errorCode}`);
    }

    const waitResult = await new Promise((resolve, reject) => {
      const overlappedData = this._readStable(overlapped, OVERLAPPED);
      kernel32.WaitForSingleObject.async(overlappedData.hEvent, INFINITE, (error, result) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(result);
      });
    });

    if (waitResult !== WAIT_OBJECT_0) {
      if (waitResult === WAIT_FAILED) {
        throw this._lastError(`WaitForSingleObject(${operation})`);
      }
      throw new Error(`WaitForSingleObject(${operation}) returned ${waitResult}`);
    }

    const completed = kernel32.GetOverlappedResult(this.fileHandle, overlapped, transferredPtr, 0);
    if (!completed) {
      const completedError = kernel32.GetLastError();
      if (completedError === ERROR_MORE_DATA && allowMoreData) {
        const overlappedData = this._readStable(overlapped, OVERLAPPED);
        return {
          count: this._readStable(transferredPtr, DWORD) || Number(overlappedData.InternalHigh || 0),
          moreData: true
        };
      }
      throw this._lastError(`GetOverlappedResult(${operation})`);
    }
    return { count: this._readStable(transferredPtr, DWORD), moreData: false };
  }

  close() {
    const { kernel32, wtsapi32 } = this._load();
    if (this.fileHandle && !this._isNullPointer(this.fileHandle)) {
      kernel32.CloseHandle(this.fileHandle);
      this.fileHandle = null;
    }
    if (this.wtsHandle && !this._isNullPointer(this.wtsHandle)) {
      wtsapi32.WTSVirtualChannelClose(this.wtsHandle);
      this.wtsHandle = null;
    }
  }
}

class RemoteInput {
  constructor() {
    this.queue = [];
    this.waiters = [];
    this.buffer = Buffer.alloc(0);
    this.ended = false;
  }

  feed(payload, close = false) {
    if (this.ended) {
      return;
    }
    this._push({ payload: Buffer.from(payload), close });
  }

  close() {
    this._push(null);
  }

  _push(item) {
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter(item);
      return;
    }
    this.queue.push(item);
  }

  async _pull() {
    if (this.queue.length > 0) {
      return this.queue.shift();
    }
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  async _fill(size) {
    while (this.buffer.length < size && !this.ended) {
      const item = await this._pull();
      if (item === null) {
        this.ended = true;
        break;
      }
      if (item.payload.length > 0) {
        this.buffer = Buffer.concat([this.buffer, item.payload]);
      }
      if (item.close) {
        this.ended = true;
      }
    }
  }

  async readExact(size) {
    await this._fill(size);
    if (this.buffer.length < size) {
      throw new RemoteStreamClosed("client stream closed");
    }
    const data = this.buffer.subarray(0, size);
    this.buffer = this.buffer.subarray(size);
    return data;
  }

  async readUntilNull(maxBytes = BUF_SIZE) {
    for (;;) {
      const index = this.buffer.indexOf(0);
      if (index >= 0) {
        const data = this.buffer.subarray(0, index);
        this.buffer = this.buffer.subarray(index + 1);
        return data;
      }
      if (this.buffer.length > maxBytes) {
        throw new ProtocolError("unterminated field is too long");
      }
      if (this.ended) {
        throw new RemoteStreamClosed("client stream closed");
      }
      await this._fill(this.buffer.length + 1);
    }
  }

  async readSome(maxBytes = BUF_SIZE) {
    await this._fill(1);
    if (this.buffer.length === 0) {
      return { payload: Buffer.alloc(0), closed: true };
    }
    const payload = this.buffer.subarray(0, maxBytes);
    this.buffer = this.buffer.subarray(maxBytes);
    return { payload, closed: this.ended && this.buffer.length === 0 };
  }
}

class SocksOverRdpServer {
  constructor(channel, { verbose = false, debug = false, connectTimeout = 10000 } = {}) {
    this.channel = channel;
    this.verbose = verbose;
    this.debug = debug;
    this.connectTimeout = connectTimeout;
    this.connections = new Map();
    this.writeChain = Promise.resolve();
    this.stopped = false;
  }

  log(message) {
    if (this.verbose) {
      console.log(message);
    }
  }

  debugLog(message) {
    if (this.debug) {
      console.log(message);
    }
  }

  async serveForever() {
    let leftover = Buffer.alloc(0);
    while (!this.stopped) {
      const payload = await this.channel.readPduPayload();
      if (payload.length === 0) {
        continue;
      }

      const decoded = decodeFrames(Buffer.concat([leftover, payload]));
      leftover = decoded.leftover;
      for (const frame of decoded.frames) {
        this.dispatchFrame(frame);
      }
    }
  }

  dispatchFrame(frame) {
    let connection = this.connections.get(frame.connectionId);
    if (!connection) {
      connection = new ProxyConnection(this, frame.connectionId);
      this.connections.set(frame.connectionId, connection);
      connection.start();
      this.debugLog(`[*] ${frame.connectionId.toString(16).padStart(8, "0")}: connection worker started`);
    }
    connection.feed(frame);
  }

  async sendToClient(connectionId, payload = Buffer.alloc(0), { close = false } = {}) {
    const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    if (body.length === 0 && !close) {
      return;
    }

    const operation = async () => {
      if (body.length === 0) {
        await this.channel.writeFrame({ connectionId, payload: Buffer.alloc(0), close: true });
        return;
      }

      let offset = 0;
      while (offset < body.length) {
        const chunk = body.subarray(offset, offset + BUF_SIZE);
        offset += chunk.length;
        await this.channel.writeFrame({
          connectionId,
          payload: chunk,
          close: close && offset >= body.length
        });
      }
    };

    const next = this.writeChain.then(operation, operation);
    this.writeChain = next.catch(() => {});
    return next;
  }

  removeConnection(connectionId, connection) {
    if (this.connections.get(connectionId) === connection) {
      this.connections.delete(connectionId);
      this.debugLog(`[*] ${connectionId.toString(16).padStart(8, "0")}: connection worker removed`);
    }
  }

  shutdown() {
    this.stopped = true;
    for (const connection of this.connections.values()) {
      connection.stop();
    }
  }
}

class ProxyConnection {
  constructor(server, connectionId) {
    this.server = server;
    this.connectionId = connectionId;
    this.input = new RemoteInput();
    this.socket = null;
    this.stopped = false;
  }

  start() {
    this.run().catch((error) => {
      this.server.debugLog(`[-] ${this.hexId()}: worker failed: ${error.message}`);
    });
  }

  feed(frame) {
    if (!this.stopped) {
      this.input.feed(frame.payload, frame.close);
    }
  }

  stop() {
    this.stopped = true;
    this.input.close();
    if (this.socket) {
      this.socket.destroy();
    }
  }

  hexId() {
    return this.connectionId.toString(16).padStart(8, "0");
  }

  async send(payload, { close = false } = {}) {
    await this.server.sendToClient(this.connectionId, payload, { close });
  }

  async run() {
    try {
      const version = (await this.input.readExact(1))[0];
      let relaySocket = null;
      if (version === 4) {
        relaySocket = await this.handleSocks4();
      } else if (version === 5) {
        relaySocket = await this.handleSocks5();
      } else {
        this.server.debugLog(`[-] ${this.hexId()}: unknown SOCKS version ${version}`);
        await this.send(Buffer.alloc(0), { close: true });
        return;
      }

      if (!relaySocket) {
        return;
      }

      this.socket = relaySocket;
      await this.relay(relaySocket);
    } catch (error) {
      if (error instanceof RemoteStreamClosed) {
        this.server.debugLog(`[-] ${this.hexId()}: client stream closed during negotiation`);
      } else if (error instanceof ProtocolError) {
        this.server.debugLog(`[-] ${this.hexId()}: protocol error: ${error.message}`);
        await this.send(Buffer.alloc(0), { close: true }).catch(() => {});
      } else {
        this.server.debugLog(`[-] ${this.hexId()}: socket/channel error: ${error.message}`);
      }
    } finally {
      this.stop();
      this.server.removeConnection(this.connectionId, this);
    }
  }

  async handleSocks4() {
    const command = (await this.input.readExact(1))[0];
    const port = bufferToPort(await this.input.readExact(2));
    const ip = await this.input.readExact(4);
    await this.input.readUntilNull();

    let host;
    let family = 4;
    if (ip[0] === 0 && ip[1] === 0 && ip[2] === 0 && ip[3] !== 0) {
      host = (await this.input.readUntilNull()).toString("utf8");
      this.server.log(`[+] ${this.hexId()}: SOCKS4a CONNECT ${host}:${port}`);
    } else {
      host = ipv4FromBuffer(ip);
      this.server.log(`[+] ${this.hexId()}: SOCKS4 CONNECT ${host}:${port}`);
    }

    if (command !== 1) {
      this.server.debugLog(`[-] ${this.hexId()}: SOCKS4 command ${command} is unsupported`);
      await this.send(socks4Reply(0x5b), { close: true });
      return null;
    }

    const relaySocket = await this.connectTarget(host, port, family);
    if (!relaySocket) {
      await this.send(socks4Reply(0x5b), { close: true });
      return null;
    }

    await this.send(socks4Reply(0x5a));
    return relaySocket;
  }

  async handleSocks5() {
    const methodCount = (await this.input.readExact(1))[0];
    const methods = await this.input.readExact(methodCount);
    if (!methods.includes(0x00)) {
      this.server.debugLog(`[-] ${this.hexId()}: SOCKS5 no-auth method not offered`);
      await this.send(Buffer.from([0x05, 0xff]), { close: true });
      return null;
    }

    await this.send(Buffer.from([0x05, 0x00]));

    const requestHeader = await this.input.readExact(4);
    const version = requestHeader[0];
    const command = requestHeader[1];
    const reserved = requestHeader[2];
    const addressType = requestHeader[3];

    if (version !== 5 || reserved !== 0) {
      throw new ProtocolError("invalid SOCKS5 request header");
    }

    let target;
    try {
      target = await this.readSocks5Address(addressType);
    } catch (error) {
      if (error instanceof ProtocolError) {
        this.server.debugLog(`[-] ${this.hexId()}: ${error.message}`);
        await this.send(socks5Reply(0x08), { close: true });
        return null;
      }
      throw error;
    }

    this.server.log(`[+] ${this.hexId()}: SOCKS5 CONNECT ${target.host}:${target.port}`);

    if (command !== 1) {
      this.server.debugLog(`[-] ${this.hexId()}: SOCKS5 command ${command} is unsupported`);
      await this.send(socks5Reply(0x07), { close: true });
      return null;
    }

    const relaySocket = await this.connectTarget(target.host, target.port, target.family);
    if (!relaySocket) {
      await this.send(socks5Reply(0x05), { close: true });
      return null;
    }

    await this.send(socks5Reply(0x00));
    return relaySocket;
  }

  async readSocks5Address(addressType) {
    if (addressType === 1) {
      const raw = await this.input.readExact(4);
      return { host: ipv4FromBuffer(raw), port: bufferToPort(await this.input.readExact(2)), family: 4 };
    }

    if (addressType === 3) {
      const length = (await this.input.readExact(1))[0];
      if (length === 0) {
        throw new ProtocolError("empty SOCKS5 domain name");
      }
      const host = (await this.input.readExact(length)).toString("utf8");
      return { host, port: bufferToPort(await this.input.readExact(2)), family: 4 };
    }

    if (addressType === 4) {
      const raw = await this.input.readExact(16);
      const host = raw.toString("hex").match(/.{1,4}/g).join(":");
      return { host, port: bufferToPort(await this.input.readExact(2)), family: 6 };
    }

    throw new ProtocolError(`unsupported SOCKS5 address type ${addressType}`);
  }

  async connectTarget(host, port, family) {
    return new Promise((resolve) => {
      const socket = net.createConnection({ host, port, family });
      let settled = false;
      const timeout = setTimeout(() => {
        finish(null, new Error("connect timeout"));
      }, this.server.connectTimeout);

      const finish = (result, error = null) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        socket.removeAllListeners("connect");
        socket.removeAllListeners("error");
        if (error) {
          this.server.debugLog(`[-] ${this.hexId()}: connect(${host}:${port}) failed: ${error.message}`);
          socket.destroy();
        }
        resolve(result);
      };

      socket.once("connect", () => {
        socket.setNoDelay(true);
        finish(socket);
      });
      socket.once("error", (error) => finish(null, error));
    });
  }

  async relay(socket) {
    let clientClosed = false;
    let closeSent = false;

    const sendCloseToClient = async () => {
      if (!clientClosed && !closeSent) {
        closeSent = true;
        await this.server.sendToClient(this.connectionId, Buffer.alloc(0), { close: true }).catch(() => {});
      }
    };

    const targetClosed = new Promise((resolve) => {
      socket.on("data", (chunk) => {
        socket.pause();
        this.server
          .sendToClient(this.connectionId, chunk)
          .catch((error) => {
            this.server.debugLog(`[-] ${this.hexId()}: channel write failed: ${error.message}`);
            this.stopped = true;
          })
          .finally(() => {
            if (!this.stopped && !socket.destroyed) {
              socket.resume();
            }
          });
      });

      const closeTarget = async () => {
        await sendCloseToClient();
        this.input.close();
        resolve();
      };

      socket.once("end", closeTarget);
      socket.once("close", closeTarget);
      socket.once("error", async (error) => {
        if (!this.stopped) {
          this.server.debugLog(`[-] ${this.hexId()}: target socket error: ${error.message}`);
        }
        await closeTarget();
      });
    });

    const clientClosedPromise = (async () => {
      while (!this.stopped) {
        const { payload, closed } = await this.input.readSome();
        if (payload.length > 0) {
          await writeSocket(socket, payload);
        }
        if (closed) {
          clientClosed = true;
          break;
        }
      }
      socket.end();
    })();

    await Promise.race([targetClosed, clientClosedPromise]);
    this.stopped = true;
    socket.destroy();
    await Promise.allSettled([targetClosed, clientClosedPromise]);
  }
}

function socks4Reply(status) {
  return Buffer.from([0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

function socks5Reply(status) {
  return Buffer.from([0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

function writeSocket(socket, data) {
  return new Promise((resolve, reject) => {
    socket.write(data, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function parseArgs(argv) {
  const args = {
    verbose: false,
    debug: false,
    priority: WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH,
    connectTimeout: 10000,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help" || arg === "/?") {
      args.help = true;
    } else if (arg === "-v" || arg === "--verbose") {
      args.verbose = true;
    } else if (arg === "-d" || arg === "--debug") {
      args.debug = true;
    } else if (arg === "--priority") {
      i += 1;
      args.priority = Number.parseInt(argv[i], 10);
    } else if (arg === "--connect-timeout") {
      i += 1;
      args.connectTimeout = Number.parseFloat(argv[i]) * 1000;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!Number.isFinite(args.priority)) {
    throw new Error("--priority requires an integer value");
  }
  if (!Number.isFinite(args.connectTimeout) || args.connectTimeout <= 0) {
    throw new Error("--connect-timeout requires a positive number of seconds");
  }

  return args;
}

function printUsage() {
  console.log(`Usage: node server.js [-v] [-d] [--priority 4] [--connect-timeout 10]

SocksOverRDP Node server

Options:
  -h, --help                 Show this help
  -v, --verbose              Log connection targets
  -d, --debug                Log detailed relay events
  --priority N               Dynamic virtual channel priority flag, default: 4
  --connect-timeout SECONDS  Outbound TCP connect timeout, default: 10`);
}

async function run(args) {
  console.log("Socks Over RDP Node server");
  const channel = new RdpVirtualChannel({ priority: args.priority });
  await channel.open();
  console.log("[*] Channel opened over RDP");

  const server = new SocksOverRdpServer(channel, {
    verbose: args.verbose,
    debug: args.debug,
    connectTimeout: args.connectTimeout
  });

  process.once("SIGINT", () => {
    console.log("[*] CTRL+C pressed. Closing down.");
    server.shutdown();
    channel.close();
  });

  try {
    await server.serveForever();
  } finally {
    server.shutdown();
    channel.close();
  }
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    printUsage();
    return 0;
  }
  await run(args);
  return 0;
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[-] ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {
  BUF_SIZE,
  FRAME_HEADER_SIZE,
  RemoteInput,
  ProxyConnection,
  RdpVirtualChannel,
  SocksOverRdpServer,
  bufferToPort,
  decodeFrames,
  encodeFrame,
  parseArgs,
  portToBuffer,
  socks4Reply,
  socks5Reply
};
