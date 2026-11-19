/*
 * Windows-native TCP_INFO collection for Cygwin builds -- Linknesis-local
 * patch, not part of upstream iperf3 (which has never implemented Windows
 * TCP_INFO collection at all; see the comment at the top of tcp_info.c).
 *
 * struct win_tcpinfo is a flat, plain-C mirror of the fields we need from
 * Windows' TCP_INFO_v0 (see <mstcpip.h>), deliberately free of any Windows
 * header types so it can be included from iperf.h and tcp_info.c without
 * pulling in <winsock2.h> there. Cygwin's POSIX <sys/socket.h> (already
 * included by iperf.h/tcp_info.c) and native <winsock2.h> both define
 * struct timeval/fd_set/etc. under the same names with independent,
 * conflicting definitions -- mixing them in one translation unit is a
 * classic Cygwin header conflict. The actual WSAIoctl(SIO_TCP_INFO) call
 * lives in tcp_info_win.c, which includes ONLY Windows headers and is
 * reached from the rest of the codebase through this plain-C boundary.
 */
#ifndef IPERF_TCP_INFO_WIN_H
#define IPERF_TCP_INFO_WIN_H

struct win_tcpinfo {
    unsigned long cwnd;             /* TCP_INFO_v0.Cwnd, bytes */
    unsigned long bytes_retrans;    /* TCP_INFO_v0.BytesRetrans, bytes (not a segment count) */
    unsigned long fast_retrans;     /* TCP_INFO_v0.FastRetrans, algorithm invocations */
    unsigned long timeout_episodes; /* TCP_INFO_v0.TimeoutEpisodes, RTO episodes (each may cover >1 segment) */
    unsigned char syn_retrans;      /* TCP_INFO_v0.SynRetrans */
};

#if defined(__CYGWIN__)
/* Returns 0 and fills *out on success, -1 on failure (out is zeroed either way). */
int win_tcpinfo_get(int fd, struct win_tcpinfo *out);
/* Diagnostics for the most recent win_tcpinfo_get() failure (temporary,
 * used while bringing this patch up -- see tcp_info.c's save_tcpinfo()). */
int win_tcpinfo_last_error(void);
long win_tcpinfo_last_socket_value(void);
#endif

#endif /* IPERF_TCP_INFO_WIN_H */
