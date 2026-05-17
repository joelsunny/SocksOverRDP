#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "SocksOverRDP-Server-DLL.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:SocksOverRDPServerRun=_SocksOverRDPServerRun@8")
#pragma comment(linker, "/EXPORT:SocksOverRDPServerRunWithOptions=_SocksOverRDPServerRunWithOptions@16")
#pragma comment(linker, "/EXPORT:SocksOverRDPServerStop=_SocksOverRDPServerStop@0")
#pragma comment(linker, "/EXPORT:Rundll32Start=_Rundll32Start@16")
#endif

namespace
{
constexpr char kChannelName[] = "SocksChannel";
constexpr DWORD kChannelPduHeaderSize = 8;
constexpr DWORD kChannelPduLength = 1600;
constexpr DWORD kFrameHeaderSize = sizeof(DWORD) + sizeof(DWORD) + sizeof(BYTE);
constexpr DWORD kBufferSize = 4096;
constexpr DWORD kDefaultPriority = 4;
constexpr DWORD kDefaultConnectTimeoutMs = 10000;

struct Options
{
	bool verbose = false;
	bool debug = false;
	DWORD priority = kDefaultPriority;
	DWORD connectTimeoutMs = kDefaultConnectTimeoutMs;
};

struct Frame
{
	DWORD connectionId = 0;
	std::vector<char> payload;
	bool close = false;
};

class SocksOverRdpServer;

std::mutex g_serverMutex;
SocksOverRdpServer *g_server = nullptr;

void DebugLine(const wchar_t *prefix, const std::wstring &message)
{
	std::wstring line = prefix;
	line += message;
	line += L"\n";
	OutputDebugStringW(line.c_str());
	fwprintf(stderr, L"%ls", line.c_str());
}

void LogLine(bool enabled, const wchar_t *prefix, const std::wstring &message)
{
	if (enabled)
	{
		DebugLine(prefix, message);
	}
}

std::wstring HexId(DWORD value)
{
	wchar_t buffer[16] = {};
	swprintf_s(buffer, L"%08x", value);
	return buffer;
}

DWORD ReadUInt32Le(const char *data)
{
	DWORD value = 0;
	memcpy(&value, data, sizeof(value));
	return value;
}

WORD ReadUInt16Be(const std::vector<char> &data, size_t offset)
{
	return static_cast<WORD>(
		(static_cast<unsigned char>(data[offset]) << 8) |
		static_cast<unsigned char>(data[offset + 1]));
}

void AppendUInt32Le(std::vector<char> &out, DWORD value)
{
	const char *bytes = reinterpret_cast<const char *>(&value);
	out.insert(out.end(), bytes, bytes + sizeof(value));
}

void AppendBytes(std::vector<char> &out, const void *data, size_t size)
{
	const char *bytes = static_cast<const char *>(data);
	out.insert(out.end(), bytes, bytes + size);
}

std::vector<char> MakeFrameBuffer(const Frame &frame)
{
	std::vector<char> out;
	out.reserve(kFrameHeaderSize + frame.payload.size());
	AppendUInt32Le(out, frame.connectionId);
	AppendUInt32Le(out, static_cast<DWORD>(frame.payload.size()));
	out.push_back(frame.close ? 1 : 0);
	out.insert(out.end(), frame.payload.begin(), frame.payload.end());
	return out;
}

std::vector<char> Socks4Reply(BYTE status)
{
	return { 0x00, static_cast<char>(status), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
}

std::vector<char> Socks5Reply(BYTE status)
{
	return {
		0x05, static_cast<char>(status), 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
}

bool ContainsNoAuthMethod(const std::vector<char> &methods)
{
	return std::find(methods.begin(), methods.end(), '\0') != methods.end();
}

std::string BytesToString(const std::vector<char> &bytes)
{
	return std::string(bytes.begin(), bytes.end());
}

std::wstring ToWide(const std::string &value)
{
	if (value.empty())
	{
		return L"";
	}

	int len = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
	if (len <= 0)
	{
		len = MultiByteToWideChar(CP_ACP, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
		if (len <= 0)
		{
			return L"<invalid>";
		}
		std::wstring out(len, L'\0');
		MultiByteToWideChar(CP_ACP, 0, value.c_str(), static_cast<int>(value.size()), out.data(), len);
		return out;
	}

	std::wstring out(len, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), len);
	return out;
}

class RdpVirtualChannel
{
public:
	explicit RdpVirtualChannel(DWORD priority) : priority_(priority)
	{
	}

	~RdpVirtualChannel()
	{
		Close();
	}

	DWORD Open()
	{
		std::lock_guard<std::mutex> lock(closeMutex_);
		DWORD flags = WTS_CHANNEL_OPTION_DYNAMIC | priority_;
		wtsHandle_ = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, const_cast<LPSTR>(kChannelName), flags);
		if (!IsValidHandle(wtsHandle_))
		{
			return GetLastError();
		}

		PVOID fileHandleMemory = nullptr;
		DWORD length = 0;
		if (!WTSVirtualChannelQuery(wtsHandle_, WTSVirtualFileHandle, &fileHandleMemory, &length))
		{
			DWORD err = GetLastError();
			CloseLocked();
			return err;
		}

		DWORD err = ERROR_SUCCESS;
		if (length != sizeof(HANDLE))
		{
			err = ERROR_INVALID_PARAMETER;
		}
		else
		{
			HANDLE sourceHandle = *static_cast<HANDLE *>(fileHandleMemory);
			HANDLE currentProcess = GetCurrentProcess();
			if (!DuplicateHandle(
				currentProcess,
				sourceHandle,
				currentProcess,
				&fileHandle_,
				0,
				FALSE,
				DUPLICATE_SAME_ACCESS))
			{
				err = GetLastError();
			}
		}

		if (fileHandleMemory)
		{
			WTSFreeMemory(fileHandleMemory);
		}

		if (err != ERROR_SUCCESS)
		{
			CloseLocked();
		}
		return err;
	}

	bool ReadPduPayload(std::vector<char> &payload, DWORD &error)
	{
		std::vector<char> data;
		if (!ReadFileAll(kChannelPduLength, data, error))
		{
			return false;
		}

		if (data.size() <= kChannelPduHeaderSize)
		{
			payload.clear();
			return true;
		}

		payload.assign(data.begin() + kChannelPduHeaderSize, data.end());
		return true;
	}

	bool WriteFrame(const Frame &frame, DWORD &error)
	{
		std::vector<char> data = MakeFrameBuffer(frame);
		return WriteFileAll(data, error);
	}

	void Close()
	{
		std::lock_guard<std::mutex> lock(closeMutex_);
		CloseLocked();
	}

private:
	static bool IsValidHandle(HANDLE handle)
	{
		return handle != nullptr && handle != INVALID_HANDLE_VALUE;
	}

	HANDLE FileHandleSnapshot()
	{
		std::lock_guard<std::mutex> lock(closeMutex_);
		return fileHandle_;
	}

	bool ReadFileAll(DWORD chunkSize, std::vector<char> &out, DWORD &error)
	{
		out.clear();
		for (;;)
		{
			std::vector<char> chunk;
			bool moreData = false;
			if (!ReadFileOnce(chunkSize, chunk, moreData, error))
			{
				return false;
			}

			out.insert(out.end(), chunk.begin(), chunk.end());
			if (!moreData)
			{
				error = ERROR_SUCCESS;
				return true;
			}
		}
	}

	bool ReadFileOnce(DWORD size, std::vector<char> &out, bool &moreData, DWORD &error)
	{
		HANDLE fileHandle = FileHandleSnapshot();
		if (!IsValidHandle(fileHandle))
		{
			error = ERROR_OPERATION_ABORTED;
			return false;
		}

		out.assign(size, 0);
		OVERLAPPED overlapped = {};
		overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!overlapped.hEvent)
		{
			error = GetLastError();
			return false;
		}

		DWORD transferred = 0;
		BOOL ok = ReadFile(fileHandle, out.data(), size, &transferred, &overlapped);
		bool success = FinishOverlappedRead(fileHandle, ok, overlapped, transferred, moreData, error);
		CloseHandle(overlapped.hEvent);

		if (!success)
		{
			out.clear();
			return false;
		}

		out.resize(transferred);
		return true;
	}

	bool WriteFileAll(const std::vector<char> &data, DWORD &error)
	{
		HANDLE fileHandle = FileHandleSnapshot();
		if (!IsValidHandle(fileHandle))
		{
			error = ERROR_OPERATION_ABORTED;
			return false;
		}

		OVERLAPPED overlapped = {};
		overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!overlapped.hEvent)
		{
			error = GetLastError();
			return false;
		}

		DWORD transferred = 0;
		BOOL ok = WriteFile(
			fileHandle,
			data.empty() ? nullptr : data.data(),
			static_cast<DWORD>(data.size()),
			&transferred,
			&overlapped);

		bool success = FinishOverlappedWrite(fileHandle, ok, overlapped, transferred, static_cast<DWORD>(data.size()), error);
		CloseHandle(overlapped.hEvent);
		return success;
	}

	bool FinishOverlappedRead(
		HANDLE fileHandle,
		BOOL ok,
		OVERLAPPED &overlapped,
		DWORD &transferred,
		bool &moreData,
		DWORD &error)
	{
		moreData = false;
		if (ok)
		{
			error = ERROR_SUCCESS;
			return true;
		}

		DWORD err = GetLastError();
		if (err == ERROR_MORE_DATA)
		{
			if (transferred == 0 && overlapped.InternalHigh != 0)
			{
				transferred = static_cast<DWORD>(overlapped.InternalHigh);
			}
			moreData = true;
			error = ERROR_SUCCESS;
			return true;
		}

		if (err != ERROR_IO_PENDING)
		{
			error = err;
			return false;
		}

		DWORD waitResult = WaitForSingleObject(overlapped.hEvent, INFINITE);
		if (waitResult != WAIT_OBJECT_0)
		{
			error = waitResult == WAIT_FAILED ? GetLastError() : waitResult;
			return false;
		}

		if (GetOverlappedResult(fileHandle, &overlapped, &transferred, FALSE))
		{
			error = ERROR_SUCCESS;
			return true;
		}

		err = GetLastError();
		if (err == ERROR_MORE_DATA)
		{
			if (transferred == 0 && overlapped.InternalHigh != 0)
			{
				transferred = static_cast<DWORD>(overlapped.InternalHigh);
			}
			moreData = true;
			error = ERROR_SUCCESS;
			return true;
		}

		error = err;
		return false;
	}

	bool FinishOverlappedWrite(
		HANDLE fileHandle,
		BOOL ok,
		OVERLAPPED &overlapped,
		DWORD &transferred,
		DWORD expected,
		DWORD &error)
	{
		if (!ok)
		{
			DWORD err = GetLastError();
			if (err != ERROR_IO_PENDING)
			{
				error = err;
				return false;
			}

			DWORD waitResult = WaitForSingleObject(overlapped.hEvent, INFINITE);
			if (waitResult != WAIT_OBJECT_0)
			{
				error = waitResult == WAIT_FAILED ? GetLastError() : waitResult;
				return false;
			}

			if (!GetOverlappedResult(fileHandle, &overlapped, &transferred, FALSE))
			{
				error = GetLastError();
				return false;
			}
		}

		if (transferred != expected)
		{
			error = ERROR_WRITE_FAULT;
			return false;
		}

		error = ERROR_SUCCESS;
		return true;
	}

	void CloseLocked()
	{
		if (IsValidHandle(fileHandle_))
		{
			CancelIoEx(fileHandle_, nullptr);
			CloseHandle(fileHandle_);
			fileHandle_ = nullptr;
		}
		if (IsValidHandle(wtsHandle_))
		{
			WTSVirtualChannelClose(wtsHandle_);
			wtsHandle_ = nullptr;
		}
	}

	DWORD priority_ = kDefaultPriority;
	HANDLE wtsHandle_ = nullptr;
	HANDLE fileHandle_ = nullptr;
	std::mutex closeMutex_;
};

struct InputChunk
{
	std::vector<char> payload;
	bool close = false;
};

class RemoteInput
{
public:
	void Feed(const std::vector<char> &payload, bool close)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (stopped_)
		{
			return;
		}
		queue_.push_back({ payload, close });
		condition_.notify_one();
	}

	void Close()
	{
		std::lock_guard<std::mutex> lock(mutex_);
		stopped_ = true;
		eof_ = true;
		condition_.notify_all();
	}

	bool ReadExact(size_t size, std::vector<char> &out)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		while (buffer_.size() < size && !eof_)
		{
			if (!PullLocked(lock))
			{
				break;
			}
		}

		if (buffer_.size() < size)
		{
			return false;
		}

		out.assign(buffer_.begin(), buffer_.begin() + size);
		buffer_.erase(buffer_.begin(), buffer_.begin() + size);
		return true;
	}

	bool ReadUntilNull(size_t maxBytes, std::vector<char> &out)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		for (;;)
		{
			auto found = std::find(buffer_.begin(), buffer_.end(), '\0');
			if (found != buffer_.end())
			{
				out.assign(buffer_.begin(), found);
				buffer_.erase(buffer_.begin(), found + 1);
				return true;
			}

			if (buffer_.size() > maxBytes || eof_)
			{
				return false;
			}

			if (!PullLocked(lock))
			{
				return false;
			}
		}
	}

	bool ReadSome(size_t maxBytes, std::vector<char> &out, bool &closed)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		while (buffer_.empty() && !eof_)
		{
			if (!PullLocked(lock))
			{
				break;
			}
		}

		if (buffer_.empty())
		{
			closed = eof_;
			out.clear();
			return true;
		}

		size_t count = std::min(maxBytes, buffer_.size());
		out.assign(buffer_.begin(), buffer_.begin() + count);
		buffer_.erase(buffer_.begin(), buffer_.begin() + count);
		closed = eof_ && buffer_.empty();
		return true;
	}

private:
	bool PullLocked(std::unique_lock<std::mutex> &lock)
	{
		condition_.wait(lock, [&]() { return stopped_ || !queue_.empty(); });
		if (queue_.empty())
		{
			return false;
		}

		InputChunk chunk = std::move(queue_.front());
		queue_.pop_front();
		buffer_.insert(buffer_.end(), chunk.payload.begin(), chunk.payload.end());
		if (chunk.close)
		{
			eof_ = true;
		}
		return true;
	}

	std::mutex mutex_;
	std::condition_variable condition_;
	std::deque<InputChunk> queue_;
	std::vector<char> buffer_;
	bool eof_ = false;
	bool stopped_ = false;
};

class ProxyConnection : public std::enable_shared_from_this<ProxyConnection>
{
public:
	ProxyConnection(SocksOverRdpServer &server, DWORD connectionId);
	~ProxyConnection();

	void Start();
	void Feed(const Frame &frame);
	void Stop();
	void Join();

	DWORD Id() const { return connectionId_; }

private:
	void Run();
	SOCKET HandleSocks4();
	SOCKET HandleSocks5();
	bool ReadSocks5Address(BYTE addressType, std::string &host, WORD &port);
	SOCKET ConnectTarget(const std::string &host, WORD port);
	bool SendAll(SOCKET socketHandle, const std::vector<char> &payload);
	void Relay(SOCKET socketHandle);
	void RelayTargetToClient(SOCKET socketHandle);
	void Send(const std::vector<char> &payload, bool close = false);
	void SetSocket(SOCKET socketHandle);
	void CloseSocket();
	void LogTarget(const wchar_t *protocol, const std::string &host, WORD port);

	SocksOverRdpServer &server_;
	DWORD connectionId_ = 0;
	RemoteInput input_;
	std::thread worker_;
	std::atomic<bool> stopping_{ false };
	std::mutex socketMutex_;
	SOCKET socket_ = INVALID_SOCKET;
};

class SocksOverRdpServer
{
public:
	explicit SocksOverRdpServer(const Options &options) :
		options_(options),
		channel_(options.priority)
	{
	}

	INT Serve()
	{
		DWORD err = channel_.Open();
		if (err != ERROR_SUCCESS)
		{
			LogLine(true, L"[-] ", L"WTSVirtualChannelOpenEx failed: " + std::to_wstring(err));
			return static_cast<INT>(err);
		}

		LogLine(true, L"[*] ", L"Channel opened over RDP");

		std::vector<char> pending;
		while (!stopping_)
		{
			std::vector<char> payload;
			if (!channel_.ReadPduPayload(payload, err))
			{
				if (!stopping_)
				{
					LogLine(true, L"[-] ", L"ReadFile failed: " + std::to_wstring(err));
				}
				break;
			}

			if (payload.empty())
			{
				continue;
			}

			pending.insert(pending.end(), payload.begin(), payload.end());
			DispatchCompleteFrames(pending);
		}

		Shutdown();
		return 0;
	}

	void Shutdown()
	{
		if (stopping_.exchange(true))
		{
			return;
		}

		channel_.Close();

		std::vector<std::shared_ptr<ProxyConnection>> connections;
		{
			std::lock_guard<std::mutex> lock(connectionsMutex_);
			for (const auto &entry : connections_)
			{
				connections.push_back(entry.second);
			}
		}

		for (auto &connection : connections)
		{
			connection->Stop();
		}
		for (auto &connection : connections)
		{
			connection->Join();
		}

		std::lock_guard<std::mutex> lock(connectionsMutex_);
		connections_.clear();
	}

	void SendToClient(DWORD connectionId, const std::vector<char> &payload, bool close)
	{
		if (payload.empty() && !close)
		{
			return;
		}

		{
			bool requestShutdown = false;
			{
				std::lock_guard<std::mutex> lock(writeMutex_);
				DWORD err = ERROR_SUCCESS;

				if (payload.empty())
				{
					if (!channel_.WriteFrame(Frame{ connectionId, {}, true }, err))
					{
						Debug(L"channel close-frame write failed: " + std::to_wstring(err));
						requestShutdown = true;
					}
				}
				else
				{
					size_t offset = 0;
					while (offset < payload.size())
					{
						size_t count = std::min<size_t>(kBufferSize, payload.size() - offset);
						std::vector<char> chunk(payload.begin() + offset, payload.begin() + offset + count);
						offset += count;
						bool closeThisFrame = close && offset >= payload.size();
						if (!channel_.WriteFrame(Frame{ connectionId, std::move(chunk), closeThisFrame }, err))
						{
							Debug(L"channel write failed: " + std::to_wstring(err));
							requestShutdown = true;
							break;
						}
					}
				}
			}

			if (requestShutdown)
			{
				Shutdown();
			}
		}
	}

	void RemoveConnection(DWORD connectionId, ProxyConnection *connection)
	{
		std::lock_guard<std::mutex> lock(connectionsMutex_);
		auto found = connections_.find(connectionId);
		if (found != connections_.end() && found->second.get() == connection)
		{
			connections_.erase(found);
			Debug(HexId(connectionId) + L": connection worker removed");
		}
	}

	bool IsStopping() const
	{
		return stopping_;
	}

	DWORD ConnectTimeoutMs() const
	{
		return options_.connectTimeoutMs;
	}

	void Verbose(const std::wstring &message)
	{
		LogLine(options_.verbose, L"[+] ", message);
	}

	void Debug(const std::wstring &message)
	{
		LogLine(options_.debug, L"[*] ", message);
	}

private:
	void DispatchCompleteFrames(std::vector<char> &pending)
	{
		size_t offset = 0;
		while (pending.size() - offset >= kFrameHeaderSize)
		{
			DWORD connectionId = ReadUInt32Le(pending.data() + offset);
			DWORD payloadLength = ReadUInt32Le(pending.data() + offset + sizeof(DWORD));
			BYTE closeFlag = static_cast<BYTE>(pending[offset + sizeof(DWORD) + sizeof(DWORD)]);
			size_t frameEnd = offset + kFrameHeaderSize + payloadLength;

			if (frameEnd > pending.size())
			{
				break;
			}

			Frame frame;
			frame.connectionId = connectionId;
			frame.close = closeFlag == 1;
			frame.payload.assign(
				pending.begin() + offset + kFrameHeaderSize,
				pending.begin() + frameEnd);

			DispatchFrame(frame);
			offset = frameEnd;
		}

		if (offset > 0)
		{
			pending.erase(pending.begin(), pending.begin() + offset);
		}
	}

	void DispatchFrame(const Frame &frame)
	{
		std::shared_ptr<ProxyConnection> connection;
		{
			std::lock_guard<std::mutex> lock(connectionsMutex_);
			auto found = connections_.find(frame.connectionId);
			if (found == connections_.end())
			{
				connection = std::make_shared<ProxyConnection>(*this, frame.connectionId);
				connections_[frame.connectionId] = connection;
				connection->Start();
				Debug(HexId(frame.connectionId) + L": connection worker started");
			}
			else
			{
				connection = found->second;
			}
		}

		connection->Feed(frame);
	}

	Options options_;
	RdpVirtualChannel channel_;
	std::atomic<bool> stopping_{ false };
	std::mutex writeMutex_;
	std::mutex connectionsMutex_;
	std::unordered_map<DWORD, std::shared_ptr<ProxyConnection>> connections_;
};

ProxyConnection::ProxyConnection(SocksOverRdpServer &server, DWORD connectionId) :
	server_(server),
	connectionId_(connectionId)
{
}

ProxyConnection::~ProxyConnection()
{
	Stop();
	Join();
}

void ProxyConnection::Start()
{
	std::shared_ptr<ProxyConnection> self = shared_from_this();
	worker_ = std::thread([self]() { self->Run(); });
}

void ProxyConnection::Feed(const Frame &frame)
{
	if (!stopping_)
	{
		input_.Feed(frame.payload, frame.close);
	}
}

void ProxyConnection::Stop()
{
	stopping_.exchange(true);
	input_.Close();
	CloseSocket();
}

void ProxyConnection::Join()
{
	if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id())
	{
		worker_.join();
	}
}

void ProxyConnection::Run()
{
	SOCKET relaySocket = INVALID_SOCKET;
	std::vector<char> version;
	if (!input_.ReadExact(1, version))
	{
		server_.Debug(HexId(connectionId_) + L": client stream closed before SOCKS version");
		server_.RemoveConnection(connectionId_, this);
		return;
	}

	if (static_cast<unsigned char>(version[0]) == 4)
	{
		relaySocket = HandleSocks4();
	}
	else if (static_cast<unsigned char>(version[0]) == 5)
	{
		relaySocket = HandleSocks5();
	}
	else
	{
		server_.Debug(HexId(connectionId_) + L": unknown SOCKS version");
		Send({}, true);
	}

	if (relaySocket != INVALID_SOCKET)
	{
		SetSocket(relaySocket);
		Relay(relaySocket);
	}

	Stop();
	server_.RemoveConnection(connectionId_, this);
}

SOCKET ProxyConnection::HandleSocks4()
{
	std::vector<char> command;
	std::vector<char> rawPort;
	std::vector<char> rawIp;
	std::vector<char> ignoredUserId;
	if (!input_.ReadExact(1, command) ||
		!input_.ReadExact(2, rawPort) ||
		!input_.ReadExact(4, rawIp) ||
		!input_.ReadUntilNull(kBufferSize, ignoredUserId))
	{
		server_.Debug(HexId(connectionId_) + L": malformed SOCKS4 request");
		Send(Socks4Reply(0x5B), true);
		return INVALID_SOCKET;
	}

	WORD port = ReadUInt16Be(rawPort, 0);
	std::string host;
	if (rawIp[0] == 0 && rawIp[1] == 0 && rawIp[2] == 0 && rawIp[3] != 0)
	{
		std::vector<char> domain;
		if (!input_.ReadUntilNull(kBufferSize, domain))
		{
			server_.Debug(HexId(connectionId_) + L": malformed SOCKS4a domain");
			Send(Socks4Reply(0x5B), true);
			return INVALID_SOCKET;
		}
		host = BytesToString(domain);
		LogTarget(L"SOCKS4a", host, port);
	}
	else
	{
		char text[INET_ADDRSTRLEN] = {};
		inet_ntop(AF_INET, rawIp.data(), text, sizeof(text));
		host = text;
		LogTarget(L"SOCKS4", host, port);
	}

	if (static_cast<unsigned char>(command[0]) != 1)
	{
		server_.Debug(HexId(connectionId_) + L": unsupported SOCKS4 command");
		Send(Socks4Reply(0x5B), true);
		return INVALID_SOCKET;
	}

	SOCKET relaySocket = ConnectTarget(host, port);
	if (relaySocket == INVALID_SOCKET)
	{
		Send(Socks4Reply(0x5B), true);
		return INVALID_SOCKET;
	}

	Send(Socks4Reply(0x5A));
	return relaySocket;
}

SOCKET ProxyConnection::HandleSocks5()
{
	std::vector<char> methodCount;
	if (!input_.ReadExact(1, methodCount))
	{
		server_.Debug(HexId(connectionId_) + L": malformed SOCKS5 method request");
		return INVALID_SOCKET;
	}

	std::vector<char> methods;
	if (!input_.ReadExact(static_cast<unsigned char>(methodCount[0]), methods))
	{
		server_.Debug(HexId(connectionId_) + L": incomplete SOCKS5 methods");
		return INVALID_SOCKET;
	}

	if (!ContainsNoAuthMethod(methods))
	{
		Send({ 0x05, static_cast<char>(0xFF) }, true);
		return INVALID_SOCKET;
	}

	Send({ 0x05, 0x00 });

	std::vector<char> header;
	if (!input_.ReadExact(4, header))
	{
		server_.Debug(HexId(connectionId_) + L": incomplete SOCKS5 request header");
		Send(Socks5Reply(0x01), true);
		return INVALID_SOCKET;
	}

	BYTE version = static_cast<BYTE>(header[0]);
	BYTE command = static_cast<BYTE>(header[1]);
	BYTE reserved = static_cast<BYTE>(header[2]);
	BYTE addressType = static_cast<BYTE>(header[3]);
	if (version != 5 || reserved != 0)
	{
		server_.Debug(HexId(connectionId_) + L": invalid SOCKS5 request header");
		Send(Socks5Reply(0x01), true);
		return INVALID_SOCKET;
	}

	std::string host;
	WORD port = 0;
	if (!ReadSocks5Address(addressType, host, port))
	{
		Send(Socks5Reply(0x08), true);
		return INVALID_SOCKET;
	}

	LogTarget(L"SOCKS5", host, port);

	if (command != 1)
	{
		server_.Debug(HexId(connectionId_) + L": unsupported SOCKS5 command");
		Send(Socks5Reply(0x07), true);
		return INVALID_SOCKET;
	}

	SOCKET relaySocket = ConnectTarget(host, port);
	if (relaySocket == INVALID_SOCKET)
	{
		Send(Socks5Reply(0x05), true);
		return INVALID_SOCKET;
	}

	Send(Socks5Reply(0x00));
	return relaySocket;
}

bool ProxyConnection::ReadSocks5Address(BYTE addressType, std::string &host, WORD &port)
{
	std::vector<char> rawAddress;
	std::vector<char> rawPort;
	char text[INET6_ADDRSTRLEN] = {};

	if (addressType == 1)
	{
		if (!input_.ReadExact(4, rawAddress) || !input_.ReadExact(2, rawPort))
		{
			return false;
		}
		inet_ntop(AF_INET, rawAddress.data(), text, sizeof(text));
		host = text;
	}
	else if (addressType == 3)
	{
		std::vector<char> lengthBytes;
		if (!input_.ReadExact(1, lengthBytes))
		{
			return false;
		}

		BYTE length = static_cast<BYTE>(lengthBytes[0]);
		if (length == 0 || !input_.ReadExact(length, rawAddress) || !input_.ReadExact(2, rawPort))
		{
			return false;
		}
		host = BytesToString(rawAddress);
	}
	else if (addressType == 4)
	{
		if (!input_.ReadExact(16, rawAddress) || !input_.ReadExact(2, rawPort))
		{
			return false;
		}
		inet_ntop(AF_INET6, rawAddress.data(), text, sizeof(text));
		host = text;
	}
	else
	{
		server_.Debug(HexId(connectionId_) + L": unsupported SOCKS5 address type");
		return false;
	}

	port = ReadUInt16Be(rawPort, 0);
	return true;
}

SOCKET ProxyConnection::ConnectTarget(const std::string &host, WORD port)
{
	addrinfo hints = {};
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	std::string portText = std::to_string(port);
	addrinfo *result = nullptr;
	int rc = getaddrinfo(host.c_str(), portText.c_str(), &hints, &result);
	if (rc != 0)
	{
		server_.Debug(HexId(connectionId_) + L": getaddrinfo failed: " + std::to_wstring(rc));
		return INVALID_SOCKET;
	}

	SOCKET connected = INVALID_SOCKET;
	for (addrinfo *item = result; item != nullptr && connected == INVALID_SOCKET; item = item->ai_next)
	{
		SOCKET candidate = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
		if (candidate == INVALID_SOCKET)
		{
			continue;
		}

		u_long nonBlocking = 1;
		ioctlsocket(candidate, FIONBIO, &nonBlocking);

		rc = connect(candidate, item->ai_addr, static_cast<int>(item->ai_addrlen));
		if (rc == SOCKET_ERROR)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINVAL)
			{
				fd_set writeSet;
				fd_set exceptSet;
				FD_ZERO(&writeSet);
				FD_ZERO(&exceptSet);
				FD_SET(candidate, &writeSet);
				FD_SET(candidate, &exceptSet);

				timeval timeout = {};
				timeout.tv_sec = static_cast<long>(server_.ConnectTimeoutMs() / 1000);
				timeout.tv_usec = static_cast<long>((server_.ConnectTimeoutMs() % 1000) * 1000);
				rc = select(0, nullptr, &writeSet, &exceptSet, &timeout);
				if (rc > 0 && FD_ISSET(candidate, &writeSet))
				{
					int socketError = 0;
					int socketErrorLen = sizeof(socketError);
					if (getsockopt(candidate, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&socketError), &socketErrorLen) == 0 &&
						socketError == 0)
					{
						connected = candidate;
					}
				}
			}
		}
		else
		{
			connected = candidate;
		}

		if (connected == INVALID_SOCKET)
		{
			closesocket(candidate);
		}
	}

	freeaddrinfo(result);

	if (connected != INVALID_SOCKET)
	{
		u_long blocking = 0;
		ioctlsocket(connected, FIONBIO, &blocking);
		BOOL noDelay = TRUE;
		setsockopt(connected, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&noDelay), sizeof(noDelay));
	}
	else
	{
		server_.Debug(HexId(connectionId_) + L": connect failed");
	}

	return connected;
}

bool ProxyConnection::SendAll(SOCKET socketHandle, const std::vector<char> &payload)
{
	size_t sent = 0;
	while (sent < payload.size() && !stopping_)
	{
		int rc = send(
			socketHandle,
			payload.data() + sent,
			static_cast<int>(payload.size() - sent),
			0);
		if (rc == SOCKET_ERROR || rc == 0)
		{
			server_.Debug(HexId(connectionId_) + L": send target failed");
			return false;
		}
		sent += static_cast<size_t>(rc);
	}
	return true;
}

void ProxyConnection::Relay(SOCKET socketHandle)
{
	std::shared_ptr<ProxyConnection> self = shared_from_this();
	std::thread targetReader([self, socketHandle]() { self->RelayTargetToClient(socketHandle); });

	std::vector<char> payload;
	bool closed = false;
	while (!stopping_)
	{
		if (!input_.ReadSome(kBufferSize, payload, closed))
		{
			break;
		}

		if (!payload.empty() && !SendAll(socketHandle, payload))
		{
			break;
		}

		if (closed)
		{
			server_.Debug(HexId(connectionId_) + L": client side closed");
			break;
		}
	}

	Stop();
	if (targetReader.joinable())
	{
		targetReader.join();
	}
}

void ProxyConnection::RelayTargetToClient(SOCKET socketHandle)
{
	std::vector<char> buffer(kBufferSize);
	bool sentClose = false;

	while (!stopping_)
	{
		int rc = recv(socketHandle, buffer.data(), static_cast<int>(buffer.size()), 0);
		if (rc > 0)
		{
			Send(std::vector<char>(buffer.begin(), buffer.begin() + rc));
			continue;
		}

		if (!stopping_.exchange(true))
		{
			server_.Debug(HexId(connectionId_) + L": target side closed");
			Send({}, true);
			sentClose = true;
		}
		break;
	}

	if (sentClose)
	{
		input_.Close();
	}
}

void ProxyConnection::Send(const std::vector<char> &payload, bool close)
{
	server_.SendToClient(connectionId_, payload, close);
}

void ProxyConnection::SetSocket(SOCKET socketHandle)
{
	std::lock_guard<std::mutex> lock(socketMutex_);
	socket_ = socketHandle;
}

void ProxyConnection::CloseSocket()
{
	std::lock_guard<std::mutex> lock(socketMutex_);
	if (socket_ != INVALID_SOCKET)
	{
		shutdown(socket_, SD_BOTH);
		closesocket(socket_);
		socket_ = INVALID_SOCKET;
	}
}

void ProxyConnection::LogTarget(const wchar_t *protocol, const std::string &host, WORD port)
{
	server_.Verbose(
		HexId(connectionId_) + L": " + protocol + L" CONNECT " + ToWide(host) + L":" + std::to_wstring(port));
}

Options ParseOptions(INT argc, WCHAR **argv)
{
	Options options;
	for (INT i = 1; i < argc; ++i)
	{
		if (_wcsicmp(argv[i], L"-v") == 0 || _wcsicmp(argv[i], L"--verbose") == 0)
		{
			options.verbose = true;
		}
		else if (_wcsicmp(argv[i], L"-d") == 0 || _wcsicmp(argv[i], L"--debug") == 0)
		{
			options.debug = true;
		}
		else if (_wcsicmp(argv[i], L"--priority") == 0 && i + 1 < argc)
		{
			options.priority = wcstoul(argv[++i], nullptr, 10);
		}
		else if (_wcsicmp(argv[i], L"--connect-timeout") == 0 && i + 1 < argc)
		{
			double seconds = wcstod(argv[++i], nullptr);
			if (seconds > 0)
			{
				options.connectTimeoutMs = static_cast<DWORD>(seconds * 1000.0);
			}
		}
	}
	return options;
}

Options ParseRundllOptions(LPSTR cmdLine)
{
	Options options;
	if (!cmdLine)
	{
		return options;
	}

	std::string args = cmdLine;
	if (args.find("-v") != std::string::npos || args.find("--verbose") != std::string::npos)
	{
		options.verbose = true;
	}
	if (args.find("-d") != std::string::npos || args.find("--debug") != std::string::npos)
	{
		options.debug = true;
	}
	return options;
}

INT RunWithOptions(const Options &options)
{
	WSADATA wsaData = {};
	int wsa = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsa != 0)
	{
		return wsa;
	}

	SocksOverRdpServer server(options);
	{
		std::lock_guard<std::mutex> lock(g_serverMutex);
		if (g_server != nullptr)
		{
			WSACleanup();
			return ERROR_BUSY;
		}
		g_server = &server;
	}

	INT result = server.Serve();

	{
		std::lock_guard<std::mutex> lock(g_serverMutex);
		if (g_server == &server)
		{
			g_server = nullptr;
		}
	}

	WSACleanup();
	return result;
}
}

SOCKSOVERRDP_API INT WINAPI SocksOverRDPServerRun(INT argc, WCHAR **argv)
{
	Options options = ParseOptions(argc, argv);
	return RunWithOptions(options);
}

SOCKSOVERRDP_API INT WINAPI SocksOverRDPServerRunWithOptions(
	BOOL verbose,
	BOOL debug,
	DWORD priority,
	DWORD connectTimeoutMs)
{
	Options options;
	options.verbose = verbose ? true : false;
	options.debug = debug ? true : false;
	options.priority = priority ? priority : kDefaultPriority;
	options.connectTimeoutMs = connectTimeoutMs ? connectTimeoutMs : kDefaultConnectTimeoutMs;
	return RunWithOptions(options);
}

SOCKSOVERRDP_API VOID WINAPI SocksOverRDPServerStop(VOID)
{
	SocksOverRdpServer *server = nullptr;
	{
		std::lock_guard<std::mutex> lock(g_serverMutex);
		server = g_server;
	}

	if (server)
	{
		server->Shutdown();
	}
}

SOCKSOVERRDP_API VOID CALLBACK Rundll32Start(HWND, HINSTANCE, LPSTR cmdLine, INT)
{
	Options options = ParseRundllOptions(cmdLine);
	RunWithOptions(options);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(module);
	}
	return TRUE;
}
