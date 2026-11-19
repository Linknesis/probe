# Linknesis Probe

This is the source code of the **Linknesis Probe**, the agent that runs on
your servers and performs network measurements (iperf3 throughput tests and
MTR route tracing) for a [Linknesis](https://www.linknesis.com) Core.

The code is **source-available, not open source**. It is published so that
you can audit what the Probe does on your machines and verify that it
corresponds to the official releases. See [LICENSE](LICENSE) for what you
may and may not do with it. In short: you may read it, compile it and run
your own unmodified builds with your licensed Linknesis Core; you may not
modify or redistribute it. This repository does not accept contributions.

Each official stable release is published here as one commit, tagged with
its version as `v<version>`.

## What the Probe does

- Connects **outbound** to your Linknesis Core over TLS (WebSocket). It does
  not need any inbound port, except the iperf3 test ports when it acts as a
  test destination.
- Runs the tests the Core asks for: iperf3 (TCP/UDP, as client or server)
  and MTR route tracing, and sends the results back to your Core.
- Updates itself when your Core offers a newer version, checking the
  download against the SHA-256 the Core provides.
- Talks only to your own Core, apart from discovering its own public IP
  address through public "what is my IP" services, tried in order when it
  connects to the Core (at most once an hour): api.ipify.org /
  api6.ipify.org, checkip.amazonaws.com, ipv4.icanhazip.com /
  ipv6.icanhazip.com, ifconfig.me and Cloudflare (1.1.1.1). See
  `probe/src/ip_discovery.zig`. The Probe itself never contacts Linknesis;
  the Linux install script downloads its files from linknesis.com and from
  your Core.

## Repository layout

| Path | Contents |
|---|---|
| `probe/src/` | The Probe source code (Zig) |
| `probe/build.zig` | Build script |
| `probe/install-windows.nsi`, `probe/*.ps1` | Windows installer and its helper scripts |
| `probe/linknesis-probe-update.service` | Linux systemd unit for manual updates |
| `probe/iperf3-linux-static/` | Script that builds the static Linux iperf3 |
| `probe/iperf3-win-patch/` | Patch that adds TCP statistics to the Windows iperf3 |
| `scripts/` | Linux install, update and uninstall scripts, and the version generator |
| `VERSION` | The release version, embedded into the binary |
| `IPERF3-SHA256.txt` | SHA-256 of the iperf3 binaries embedded in this release |

## iperf3 binaries are not included

The Probe embeds an iperf3 binary, which it writes next to itself at
startup. Those binaries are not stored in this repository; build them from
the upstream iperf3 source before compiling the Probe:

- **Linux:** run `probe/iperf3-linux-static/build.sh` as described in
  [its README](probe/iperf3-linux-static/README.md). It produces
  `probe/iperf3-linux-static/iperf3-linux-x86_64`. The build is
  reproducible: the result should match the SHA-256 in `IPERF3-SHA256.txt`.
- **Windows:** build the patched iperf3 with Cygwin as described in
  [probe/iperf3-win-patch/README.md](probe/iperf3-win-patch/README.md), and
  place it at `probe/iperf3-win-patch/iperf3.exe`.

You can also check the iperf3 binary on a machine where the official Probe
is installed: it sits next to the Probe executable (`/opt/linknesis/probe/`
on Linux by default, the install folder on Windows), and its SHA-256 should
match `IPERF3-SHA256.txt`.

## Building the Probe

Requirements:

- [Zig](https://ziglang.org/download/) **0.15.2** (the version used for
  official builds);
- for the Linux build, the OpenSSL development files (for example
  `libssl-dev` on Debian/Ubuntu);
- the iperf3 binaries described above.

```bash
cd probe

# Linux x86_64 (output: zig-out/bin/linknesis-probe)
zig build --release=safe

# Windows x86_64 (output: zig-out/bin/linknesis-probe.exe)
zig build -Dtarget=x86_64-windows --release=safe

# Unit tests
zig build test
```

These are the same commands used for official releases, which are built on
Debian 13. The Linux binary links the system's OpenSSL dynamically, so your
build will not be byte-for-byte identical to the official one, but it is
built from exactly this source.

To check which version you are running: `linknesis-probe --version`.

## Running your own build

You may run your own unmodified build instead of the official binary.
Install the Probe normally from your Core's Probes page, then replace the
executable with your build:

- **Linux:** stop the service (`systemctl stop linknesis-probe`), replace
  `/opt/linknesis/probe/linknesis-probe` (keep the owner and permissions),
  and start the service again.
- **Windows:** exit the Probe from its tray icon (Exit), replace
  `linknesis-probe.exe` in the install folder, and start it again with the
  `LinknesisProbe` task in Task Scheduler (or sign out and back in).

When your Core releases a new version, the Probe replaces itself with the
official binary of that version. To keep running your own builds, rebuild
from the new release tag here and replace the binary again.

## Security

Please report security issues privately to support@linknesis.com. See
[SECURITY.md](SECURITY.md).

## License

Source-available, see [LICENSE](LICENSE). Third-party components are
licensed under their own terms: see `probe/LICENSE-THIRD-PARTY.txt` and
`probe/iperf3_license.txt`.
