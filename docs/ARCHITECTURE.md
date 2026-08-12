# Architecture

## Why this stack

The specification asked for Rust + Tauri. That was reconsidered against a hard
constraint: the build machine had no Rust toolchain, no MSVC build tools and no
Windows SDK, and installing them is a multi-gigabyte interactive step requiring
administrator rights. The development rules also required an application that is
genuinely buildable, runnable and verified — not source that had never been
compiled.

The chosen stack builds and runs today, with no native compilation at any point:

| Layer | Choice | Reason |
| --- | --- | --- |
| Shell | Electron 43 | Prebuilt binaries; no toolchain needed |
| Capture | Npcap via `dumpcap` | Official, stable, no FFI or native binding |
| Backend | TypeScript in the main process | One language across the app; strict typing |
| Database | `node:sqlite` (Node 24, built into Electron 43) | Zero dependencies, no compilation |
| UI | React 19 + TypeScript + Tailwind 4 + Recharts | As specified |

The capture layer is isolated behind the `CaptureSource` interface
(`src/backend/capture/source.ts`). A future native engine — Rust over the Npcap
SDK — can implement that interface and replace `DumpcapSource` without touching
the parser, the flow tracker, the database or a single line of UI code.

## Data flow

```
                      ┌──────────────┐
   Npcap driver ─────▶│   dumpcap    │  -i <dev> -P -w - -q -s 1024
                      └──────┬───────┘
                             │  classic pcap on stdout
                      ┌──────▼────────────┐
                      │ PcapStreamReader  │  buffers partial records
                      └──────┬────────────┘
                             │  PcapPacket { ts, wireLength, data }
                      ┌──────▼────────────┐
                      │   parsePacket()   │  pure, never throws
                      └──────┬────────────┘
                             │  ParsedPacket
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
  DeviceRegistry        FlowTracker          AlertEngine
  (MAC/IP identity)     (5-tuple table)      (threshold rules)
        └────────────────────┼────────────────────┘
                             │  once per second
                      ┌──────▼────────────┐
                      │  flushToDatabase  │  one transaction per tick
                      └──────┬────────────┘
                             │  at uiUpdateHz (default 2 Hz)
                      ┌──────▼────────────┐
                      │     EventBus      │
                      └──────┬────────────┘
                             │  ipcMain → webContents.send
                      ┌──────▼────────────┐
                      │   React renderer  │
                      └───────────────────┘
```

## The aggregation contract

The single most important performance decision: **no per-packet message ever
crosses a boundary.**

- The parser runs synchronously on the capture callback; a packet becomes a few
  counter increments in existing Map entries.
- Flow and device deltas accumulate in memory. `drainDeltas()` returns only what
  changed since the last tick and resets the counters.
- One database transaction per second covers traffic samples, device counters,
  flow upserts, protocol totals, DNS rows and alerts.
- The UI receives a batch at `uiUpdateHz`. The device table — the most expensive
  query — is published at a fixed 0.5 Hz regardless.

Consequences: memory is bounded (the flow table evicts least-recently-seen
entries past 20 000 flows, the device registry past 4 096), and the UI cost is a
function of the update rate, not the packet rate.

## Protocol identification

Ports are hints, never conclusions. `analyzeApp()` tries header inspection
first, and each flow records how its label was reached:

| Confidence | Meaning |
| --- | --- |
| `header` | The payload structure identified it (DNS message, TLS record, HTTP start line, DHCP magic cookie, QUIC long header) |
| `heuristic` | Structure matched on a non-standard port |
| `port-hint` | No usable payload; the well-known port was used, and the UI marks the label with `?` |
| `unknown` | Neither applied |

A header-derived label always overrides an earlier port hint on the same flow.

## Flow orientation

Both directions of a conversation collapse onto one key, produced by ordering
the two `ip|port` endpoints lexicographically. The stored record is oriented so
the local device is `src`, which is what makes "upload" and "download" mean the
same thing on every row. TCP state comes from observed flags only — there is no
assumed handshake.

## Privacy enforcement points

Redaction is structural rather than a post-processing filter:

1. **Snap length.** dumpcap captures 1024 bytes per frame. Full payloads are
   never read into the process at all; the wire length from the pcap record
   keeps byte accounting exact.
2. **HTTP allowlist.** `HEADER_ALLOWLIST` in `parser/http.ts` enumerates the
   headers that may be kept. Everything else is discarded during parsing, and
   the record is flagged `redacted`. Query strings are stripped from both the
   path and the `Referer`.
3. **TLS.** `parser/tls.ts` reads the record header, the ClientHello SNI and —
   only when the handshake sends it unencrypted — certificate Common Names. No
   key exchange or decryption code exists in the project.
4. **Privacy Mode.** Checked in `inspectApplicationLayer()` before any
   payload-derived row is created, so nothing is written and then hidden.
5. **Logger scrubbing.** A final regex pass over log lines.

## Limitations, stated plainly

- **You see what the adapter sees.** On a switched network, a host observes its
  own traffic plus broadcast and multicast. Full visibility of other devices
  requires a monitor/SPAN port or a router-side capture. blazma.nt does not
  ARP-spoof to widen its view, and never will.
- **Wi-Fi in managed mode** shows the machine's own traffic, not the whole WLAN.
- **TLS 1.3** encrypts the certificate exchange, so certificate names are
  unavailable there. SNI remains visible unless ECH is in use.
- **DNS over HTTPS/TLS** is opaque by design; those flows appear as HTTPS.
- **The system-only fallback** (`capture/systemPoller.ts`) reports this
  computer's sockets, the ARP neighbour table and the local DNS cache. That is
  real data, but it is not packet analysis, and the UI says so.
