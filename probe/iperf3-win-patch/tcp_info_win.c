/*
 * Windows-native TCP_INFO collection for Cygwin builds, via
 * WSAIoctl(SIO_TCP_INFO) -- Linknesis-local patch, not part of upstream
 * iperf3. See tcp_info_win.h for why this lives in its own translation
 * unit, isolated from every POSIX socket header the rest of the codebase
 * includes.
 *
 * iperf3 upstream has never implemented Windows TCP_INFO collection (its
 * own tcp_info.c says "I think MS Windows does support TCP_INFO, but
 * iperf3 does not currently support Windows"), even though Windows has had
 * a native equivalent since Windows 10 version 1703 (Creators Update /
 * RS2): SIO_TCP_INFO, a per-socket WSAIoctl requiring no elevated
 * privileges, documented at
 * https://learn.microsoft.com/windows/win32/winsock/sio-tcp-info
 *
 * The Cygwin fd returned by socket() is a Cygwin fd-table index, NOT
 * numerically equal to the underlying Win32 SOCKET handle (casting the fd
 * directly makes WSAIoctl fail with WSAENOTSOCK/10038). The real handle is retrieved via Cygwin's own _get_osfhandle(fd)
 * (documented by Cygwin as "return a Win32 HANDLE from a fd", and it works
 * for socket fds too, not just file fds).
 *
 * WSAIoctl is resolved at runtime via GetProcAddress against ws2_32.dll
 * (already loaded into every Cygwin process, since Cygwin's own socket
 * layer sits on top of it) rather than linked at build time with
 * -lws2_32. Linking -lws2_32 directly into iperf3.exe was tried first and
 * measurably broke the binary: -lws2_32 pulls in Winsock's own
 * socket/connect/send/recv/select symbols, which shadow Cygwin's POSIX
 * implementations of those same names, and the resulting iperf3.exe could
 * no longer connect to any TCP server at all (reproduced against a known-
 * good server/port that the unpatched, unlinked build connected to
 * successfully moments earlier). Resolving just the one function pointer
 * we need at runtime avoids touching the rest of the binary's socket
 * symbol table.
 */
#if defined(__CYGWIN__)

#include <string.h>
#include <stdint.h>

#define _WIN32_WINNT 0x0A00 /* -> NTDDI_VERSION >= NTDDI_WIN10_RS2, required for TCP_INFO_v0 */
#include <winsock2.h>
#include <windows.h>
#include <mstcpip.h>
#include <io.h> /* _get_osfhandle() */

#include "tcp_info_win.h"

typedef int (WSAAPI *WSAIoctlFn)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD,
				  LPDWORD, LPWSAOVERLAPPED,
				  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSAGetLastErrorFn)(void);

static WSAIoctlFn g_wsaIoctl = NULL;
static WSAGetLastErrorFn g_wsaGetLastError = NULL;
static int g_resolved = 0;

static void
resolveWinsockFns(void)
{
    HMODULE h;

    if (g_resolved)
	return;
    g_resolved = 1;

    /* GetModuleHandle, not LoadLibrary: ws2_32.dll is already mapped into
     * every Cygwin process, so this never triggers a fresh DLL load. Both
     * pointers are resolved here (rather than linked at build time with
     * -lws2_32) for the same reason -- see the file header comment. */
    h = GetModuleHandleA("ws2_32.dll");
    if (h == NULL)
	return;
    g_wsaIoctl = (WSAIoctlFn)GetProcAddress(h, "WSAIoctl");
    g_wsaGetLastError = (WSAGetLastErrorFn)GetProcAddress(h, "WSAGetLastError");
}

static int g_last_wsa_error = 0;
static SOCKET g_last_socket_value = 0;

int
win_tcpinfo_last_error(void)
{
    return g_last_wsa_error;
}

long
win_tcpinfo_last_socket_value(void)
{
    return (long)g_last_socket_value;
}

int
win_tcpinfo_get(int fd, struct win_tcpinfo *out)
{
    TCP_INFO_v0 info;
    DWORD version_in = 0; /* 0 selects TCP_INFO_v0 */
    DWORD bytes_returned = 0;
    SOCKET s;

    memset(out, 0, sizeof(*out));
    memset(&info, 0, sizeof(info));
    g_last_wsa_error = 0;

    resolveWinsockFns();
    if (g_wsaIoctl == NULL) {
	g_last_wsa_error = -1; /* could not resolve WSAIoctl at all */
	return -1;
    }

    s = (SOCKET)(UINT_PTR)(intptr_t)_get_osfhandle(fd);
    g_last_socket_value = s;

    if (g_wsaIoctl(s, SIO_TCP_INFO, &version_in, sizeof(version_in),
		 &info, sizeof(info), &bytes_returned, NULL, NULL) != 0) {
	g_last_wsa_error = g_wsaGetLastError ? g_wsaGetLastError() : -2;
	return -1;
    }

    out->cwnd = (unsigned long)info.Cwnd;
    out->bytes_retrans = (unsigned long)info.BytesRetrans;
    out->fast_retrans = (unsigned long)info.FastRetrans;
    out->timeout_episodes = (unsigned long)info.TimeoutEpisodes;
    out->syn_retrans = (unsigned char)info.SynRetrans;
    return 0;
}

#endif /* __CYGWIN__ */
