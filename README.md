# blazma.nt

Professional network monitoring and traffic analysis for Windows.

blazma.nt watches a network you own — or are authorised to monitor — and shows
you what is actually on the wire: which devices are connected, what they talk
to, which protocols they use, and which of that traffic is travelling
unencrypted. It is strictly **passive and read-only**.

---

## What it will not do

These are design constraints, not missing features:

- **No decryption.** HTTPS/TLS traffic is never decrypted or intercepted. Only
  what TLS sends in the clear (SNI, negotiated version, and certificate names
  when the handshake exposes them) is displayed.
- **No credentials.** Passwords, cookies, session identifiers, authorisation
  headers and API keys are never collected. In the HTTP parser this is enforced
  by an allowlist: unlisted headers are dropped before the record is built, so
  there is no code path where a secret is captured and filtered afterwards.
- **No ARP spoofing, MITM or DNS hijacking.** blazma.nt never transmits on the
  network. It cannot disrupt or redirect traffic because it has no write path.
- **No telemetry, no cloud.** Nothing leaves the machine. Vendor lookup for MAC
  addresses is an offline table, precisely so that your device addresses are not
  sent to a third party.

**Only monitor networks you own or have permission to monitor.**

---

## Requirements

| Requirement | Notes |
| --- | --- |
| Windows 10 (1809+) or Windows 11 | x64 |
| [Npcap](https://npcap.com/#download) | Required for packet capture |
| [Wireshark](https://www.wireshark.org/download.html) | Provides `dumpcap.exe`, the capture helper |
| Node.js 20+ | Development only |

### Installing Npcap

1. Download the installer from <https://npcap.com/#download>.
2. Run it as Administrator.
3. Enable **"Install Npcap in WinPcap API-compatible Mode"**.
4. Leave **"Restrict Npcap driver's access to Administrators only"** unchecked
   if you want to capture without running blazma.nt elevated.
5. Restart blazma.nt. Settings → Capture shows the detected state.

### Capture backends

blazma.nt picks the best available capture path automatically:

1. **Npcap + dumpcap (preferred).** A true live stream with the lowest latency.
   `dumpcap` — the capture-only tool bundled with Wireshark — performs no
   dissection; it hands over raw frames and every byte of analysis happens
   inside blazma.nt. Needs no native compilation.
2. **pktmon (built-in fallback).** Windows ships `pktmon`, so this path needs
   **nothing installed** — it works the moment blazma.nt is installed. It
   requires running blazma.nt **as Administrator**, and captures in short
   segments (a few seconds of latency rather than instant), because pktmon is
   file-based rather than a live stream. Verify it with
   `node scripts/test-pktmon.mjs` (as Administrator).

> **Why Npcap is not bundled.** Npcap's licence prohibits redistribution inside
> other software without a commercial OEM licence, and its free installer cannot
> run silently. blazma.nt therefore never ships or auto-installs Npcap — instead
> it works out of the box via pktmon, and uses Npcap automatically if you have
> installed it yourself.

If no backend is available, the app still runs and tells you exactly what is
missing and why; it does not silently show empty screens.

---

## Running

```bash
npm install
npm run dev
```

Production build:

```bash
npm run build
npm start
```

Windows installer (`release/NetWatchPro-Setup.exe`):

```bash
npm run dist
```

Tests:

```bash
npm test
```

The suite builds its own packets from fixtures in `tests/fixtures.ts`; it never
touches a real network and contains no captured traffic.

---

## Architecture

```
Npcap driver
    │
    ▼
dumpcap -P -w -            classic pcap on stdout
    │
    ▼
PcapStreamReader           reassembles records across pipe chunks
    │
    ▼
parsePacket()              Ethernet/VLAN → IPv4/IPv6/ARP → TCP/UDP/ICMP
    │                      → DNS · HTTP · TLS · DHCP · QUIC · NTP …
    ▼
Engine  ── FlowTracker      bidirectional 5-tuple table, TCP state machine
        ── DeviceRegistry   MAC/IP identity, offline OUI vendor lookup
        ── AlertEngine      threshold rules with stated reasons
        │
        │  aggregates once per second, publishes at uiUpdateHz
        ▼
    SQLite (node:sqlite)  +  EventBus
                                │
                                ▼
                        preload bridge (allowlisted channels only)
                                │
                                ▼
                        React + Tailwind + Recharts
```

The rule that makes this scale: **the UI never receives a packet.** The engine
folds packets into in-memory tables, flushes aggregates to SQLite once per
second, and pushes batched summaries to the renderer a couple of times per
second. Packet rate therefore affects backend CPU, not UI responsiveness.

### Project layout

```
src/
  main/        Electron main process, window lifecycle, IPC handlers
  preload/     The only renderer↔backend bridge (channel allowlist)
  shared/      Types and the IPC contract used by both sides
  backend/
    capture/   Environment probing, dumpcap source, pcap reader, PCAP jobs
    parser/    Pure packet parsers (ethernet, ip, tcp/udp, dns, http, tls, dhcp)
    flows/     Flow tracker and TCP state machine
    devices/   Device registry, interface enumeration, OUI vendors
    alerts/    Threshold rules
    analytics/ Ranges, reports, CSV/JSON/PDF export
    database/  Driver, migrations, repositories
    security/  Input validation
    core/      Event bus, settings, the engine that ties it together
    utils/     Net maths, formatting, logging, PDF writer
  renderer/    React UI (pages, components, i18n)
tests/         Vitest suites over fixtures
build/         Installer customisation
```

### Storage

SQLite via Node's built-in `node:sqlite` (Electron 43 ships Node 24), with
`node-sqlite3-wasm` as an automatic fallback. Either way there is no native
module to compile.

**Raw packets are never stored.** The database holds metadata and aggregates
only: devices, flows, protocol counters, DNS records, redacted HTTP metadata,
TLS handshake facts, alerts and logs. Packets reach the disk only through an
explicit PCAP capture that you start yourself.

Retention is configurable (1 / 7 / 30 / 90 days or unlimited) and enforced at
startup and every 15 minutes. Any category can be deleted manually from
Settings.

---

## Security

- **Renderer sandboxing.** `contextIsolation: true`, `nodeIntegration: false`.
  The renderer is a plain web page with a strict CSP and no network access.
- **IPC allowlist.** The preload bridge exposes a fixed list of channels in both
  directions. There is no generic "invoke any channel" escape hatch.
- **No shell.** Child processes are spawned with argv arrays and `shell: false`.
  No string is ever handed to `cmd.exe`, so there is no command-injection
  surface.
- **Validated inputs.** Interface ids must match the Npcap device pattern; BPF
  filters are checked against a keyword allowlist and cannot begin with `-`, so
  extra options cannot be smuggled into the capture tool; output paths must be
  absolute with an allowed extension.
- **Parameterised SQL.** Every caller-supplied value is a bound parameter. Sort
  columns come from a fixed set, never from the request.
- **Scrubbed logs.** The logger strips credential-shaped text as a second line
  of defence.
- **Least privilege.** The app requests `asInvoker`. Elevation is only needed
  for capture if Npcap was installed with the Administrators-only restriction.

## Privacy

**Privacy Mode** (Settings → Privacy) stops recording anything derived from
packet payloads — DNS queries, HTTP metadata and TLS server names — while
devices, flows and byte counters keep working. DNS history can be deleted at any
time, and storage of DNS and unencrypted metadata can each be switched off
independently.

---

## Troubleshooting

**"Npcap is required to monitor network traffic."**
Npcap is not installed, or was installed without WinPcap API-compatible mode.
Reinstall it from npcap.com with that option enabled and restart the app.

**"dumpcap.exe was not found."**
Install Wireshark. blazma.nt looks in `C:\Program Files\Wireshark`,
`C:\Program Files (x86)\Wireshark` and `%LOCALAPPDATA%\Programs\Wireshark`.

**The interface list shows "no capture device".**
That adapter has no Npcap capture handle — usually because Npcap is missing, or
because the adapter is virtual. Adapters that can be captured are listed first
and marked *capturable*.

**Capture starts, then stops immediately.**
Npcap was probably installed with "restrict to Administrators". Either
reinstall without that option, or run blazma.nt as Administrator.

**Devices appear with a "Randomized MAC" vendor.**
Modern phones randomise their MAC per network. The address is locally
administered, so no vendor can be derived from it — the app says so instead of
guessing.

**Packets are being dropped** (shown in the header).
Lower the UI update rate in Settings → Performance, or apply a capture filter to
reduce the volume reaching the parser.

---

## Licence

MIT.
