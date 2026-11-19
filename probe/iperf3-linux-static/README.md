# Static Linux iperf3

The Linux Probe embeds a statically linked build of upstream iperf3 **3.21**
(unmodified), so it works the same on every distribution regardless of the
iperf3 version in its package repositories, or whether iperf3 is packaged
at all. Some distributions ship old versions (RHEL 9 and its derivatives
ship 3.9), which lack the `--json-stream` and `--idle-timeout` options the
Probe relies on.

## Building

From this directory, with Docker:

```bash
docker run --rm -v "$(pwd)":/build alpine:3.20 sh /build/build.sh
```

`build.sh` downloads `iperf-3.21.tar.gz` from
`https://downloads.es.net/pub/iperf/`, checks its SHA-256 against the
upstream checksum, builds it statically against musl, strips it and writes
`iperf3-linux-x86_64` in this directory.

The build is reproducible: the resulting file should have the SHA-256
listed for `iperf3-linux-x86_64` in `IPERF3-SHA256.txt` at the repository
root.

## Static linking note

`-all-static` is a libtool flag, not a compiler flag, so it is passed only
to the final `make` and not to `./configure` (where it breaks the compiler
check). A plain `-static` at configure time is silently dropped by libtool
and produces a dynamically linked binary. `build.sh` fails if the result
depends on any shared library.
