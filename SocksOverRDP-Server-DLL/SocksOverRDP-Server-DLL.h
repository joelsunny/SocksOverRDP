#pragma once

#include <windows.h>

#ifdef SOCKSOVERRDP_SERVER_DLL_EXPORTS
#define SOCKSOVERRDP_API extern "C" __declspec(dllexport)
#else
#define SOCKSOVERRDP_API extern "C" __declspec(dllimport)
#endif

// Blocking server entry point. Pass argv-style options such as -v, -d,
// --priority N, and --connect-timeout SECONDS.
SOCKSOVERRDP_API INT WINAPI SocksOverRDPServerRun(INT argc, WCHAR **argv);

// Blocking server entry point for hosts that prefer a fixed ABI over argv.
SOCKSOVERRDP_API INT WINAPI SocksOverRDPServerRunWithOptions(
	BOOL verbose,
	BOOL debug,
	DWORD priority,
	DWORD connectTimeoutMs);

// Requests the currently running server instance to stop.
SOCKSOVERRDP_API VOID WINAPI SocksOverRDPServerStop(VOID);

// Convenience export for rundll32.exe. The command line accepts -v and -d.
SOCKSOVERRDP_API VOID CALLBACK Rundll32Start(HWND hwnd, HINSTANCE hinst, LPSTR cmdLine, INT nCmdShow);
