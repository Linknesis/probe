# Windows iperf3 TCP statistics patch

Upstream iperf3 does not collect TCP statistics on Windows, so a stock
Windows build reports no congestion window or retransmits for TCP tests.
Windows has provided them since Windows 10 1703 through
`WSAIoctl(SIO_TCP_INFO)`, without elevated privileges. This patch adds a
Windows (Cygwin) branch to iperf3's TCP_INFO layer that uses it.

The files in this directory are derived from iperf3 and remain under
iperf3's BSD 3-Clause license (see `probe/iperf3_license.txt`).

## What is patched

Starting from upstream iperf3 **3.21** (`https://github.com/esnet/iperf`,
tag `3.21`):

- `src/tcp_info.c`: replaced with the copy here. Adds a
  `#elif defined(__CYGWIN__)` branch to `has_tcpinfo()`,
  `has_tcpinfo_retransmits()`, `save_tcpinfo()`, `get_total_retransmits()`
  and `get_snd_cwnd()`.
- `src/iperf.h`: replaced with the copy here. Adds
  `#include "tcp_info_win.h"` and a `struct win_tcpinfo tcpInfoWin` member
  to `struct iperf_interval_results` for Cygwin.
- `src/tcp_info_win.c` and `src/tcp_info_win.h`: new files. They contain
  the `WSAIoctl(SIO_TCP_INFO)` call, in their own translation unit that
  includes only Windows headers (Cygwin's POSIX socket headers and
  `<winsock2.h>` conflict).

Only the congestion window and retransmits are implemented. Windows has no
direct equivalent of Linux's retransmitted-segment count, so retransmits are
approximated as `FastRetrans + TimeoutEpisodes + SynRetrans` (retransmission
events). This can under-count compared with Linux.

Two implementation details:

- `ws2_32` is not linked directly, because its socket functions would
  replace Cygwin's. `WSAIoctl` and `WSAGetLastError` are resolved at run
  time with `GetProcAddress` (`ws2_32.dll` is already loaded in every Cygwin
  process).
- A Cygwin file descriptor is not a Win32 `SOCKET`. The handle is obtained
  with Cygwin's `_get_osfhandle(fd)`.

## Building

On Windows 10 or later, install Cygwin with the packages `gcc-core`,
`gcc-g++`, `make`, `autoconf`, `automake`, `libtool` and `git`. Then, from a
Cygwin shell:

```bash
curl -fsSL -o iperf-3.21.tar.gz https://downloads.es.net/pub/iperf/iperf-3.21.tar.gz
echo "656e4405ebd620121de7ceca3eaf43a88f79ea1b857d041a6a0b1314801acdd8  iperf-3.21.tar.gz" | sha256sum -c -
tar xzf iperf-3.21.tar.gz
cd iperf-3.21

# Apply the patch
cp /path/to/this/directory/{tcp_info.c,iperf.h,tcp_info_win.c,tcp_info_win.h} src/

# Add the new files to src/Makefile.am's libiperf_la_SOURCES, right after
# the "tcp_info.c \" line:
#     tcp_info_win.c \
#     tcp_info_win.h \

automake --add-missing --force-missing
./configure
make -j4
```

Use `src/.libs/iperf3.exe`, not `src/iperf3.exe`: the latter is a small
libtool wrapper that only works from inside the build tree. `file
src/.libs/iperf3.exe` should report 19 sections (the wrapper has 10).
Copy it to `probe/iperf3-win-patch/iperf3.exe` before building the Probe.

The binary needs `cygwin1.dll` (LGPL v3) at run time. The Windows installer
places it next to `iperf3.exe`; it is not embedded in the Probe. A Cygwin
build is not byte-for-byte reproducible, so your `iperf3.exe` will differ
from the official one even when built from the same source.
