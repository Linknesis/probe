#!/bin/sh
set -eux

apk add --no-cache build-base linux-headers curl

IPERF_VERSION=3.21
IPERF_SHA256=656e4405ebd620121de7ceca3eaf43a88f79ea1b857d041a6a0b1314801acdd8

cd /build
if [ ! -f "iperf-${IPERF_VERSION}.tar.gz" ]; then
  curl -fsSL -o "iperf-${IPERF_VERSION}.tar.gz" "https://downloads.es.net/pub/iperf/iperf-${IPERF_VERSION}.tar.gz"
fi
echo "${IPERF_SHA256}  iperf-${IPERF_VERSION}.tar.gz" | sha256sum -c -
rm -rf "iperf-${IPERF_VERSION}"
tar xzf "iperf-${IPERF_VERSION}.tar.gz"
cd "iperf-${IPERF_VERSION}"

# "-all-static" is a libtool-only flag (tells libtool's own link wrapper to
# force a fully static link) -- it is NOT a valid raw gcc flag, so it must
# never be present during ./configure's own compiler sanity-check compile
# (that broke the previous attempt: "C compiler cannot create executables").
# Configure normally, then apply -all-static only at the final `make` link
# step.
./configure --enable-static --disable-shared
make -j"$(nproc)" LDFLAGS="-all-static"

cp src/.libs/iperf3 /build/iperf3-linux-x86_64 2>/dev/null || cp src/iperf3 /build/iperf3-linux-x86_64
strip /build/iperf3-linux-x86_64
# Must not depend on any shared library.
if ldd /build/iperf3-linux-x86_64 2>&1 | grep -q '=>'; then echo "not statically linked" >&2; exit 1; fi
