/**
 * blazma.nt — shared contract between the backend (Electron main) and the UI (renderer).
 * Everything crossing IPC is described here. Keep this file free of runtime imports.
 */

import type { RouterStatus } from './router.js'

/* ------------------------------------------------------------------ */
/* Interfaces                                                          */
/* ------------------------------------------------------------------ */

export interface NetworkInterfaceInfo {
  /** Stable id used to start capture (Npcap device name when available). */
  id: string
  /** Friendly Windows name, e.g. "Wi-Fi". */
  name: string
  description: string
  ipv4: string[]
  ipv6: string[]
  mac: string | null
  gateway: string | null
  /** Up / Down / Disconnected / Unknown, as reported by Windows. */
  status: string
  /** Link speed in bits per second, null when unknown. */
  speedBps: number | null
  /** Prefix length of the primary IPv4 address, used to scope the local subnet. */
  prefixLength: number | null
  isLoopback: boolean
  isVirtual: boolean
  /** True when a packet-capture handle exists for this adapter. */
  capturable: boolean
}

/* ------------------------------------------------------------------ */
/* Capture engine                                                      */
/* ------------------------------------------------------------------ */

export type CaptureBackendId = 'npcap-dumpcap' | 'npcap-tshark' | 'pktmon' | 'system-only'

export interface CaptureBackendStatus {
  id: CaptureBackendId
  available: boolean
  /** Human readable reason when unavailable. */
  reason: string | null
  /** Absolute path to the external tool, when the backend uses one. */
  toolPath: string | null
  version: string | null
  requiresElevation: boolean
}

export interface EnvironmentReport {
  npcapInstalled: boolean
  npcapVersion: string | null
  elevated: boolean
  backends: CaptureBackendStatus[]
  /** The backend the engine will pick right now, or null when none can run. */
  selectedBackend: CaptureBackendId | null
  nodeVersion: string
  electronVersion: string
  platform: string
}

export type EngineState = 'stopped' | 'starting' | 'running' | 'stopping' | 'error'

export interface EngineStatus {
  state: EngineState
  interfaceId: string | null
  interfaceName: string | null
  backend: CaptureBackendId | null
  startedAt: number | null
  error: string | null
  privacyMode: boolean
  /** Packets the capture backend reported as dropped. */
  droppedPackets: number
  packetsProcessed: number
  bytesProcessed: number
}

/* ------------------------------------------------------------------ */
/* Devices                                                             */
/* ------------------------------------------------------------------ */

export interface DeviceRecord {
  id: number
  mac: string | null
  ipv4: string | null
  ipv6: string | null
  hostname: string | null
  vendor: string | null
  /** User supplied label, wins over hostname in the UI. */
  label: string | null
  firstSeen: number
  lastSeen: number
  online: boolean
  bytesUp: number
  bytesDown: number
  packetsUp: number
  packetsDown: number
  connections: number
  isLocal: boolean
  /** User toggles: paused devices keep their history but stop accumulating. */
  paused: boolean
  ignored: boolean
}

/* ------------------------------------------------------------------ */
/* Flows / connections                                                 */
/* ------------------------------------------------------------------ */

export type FlowState = 'NEW' | 'ESTABLISHED' | 'CLOSING' | 'CLOSED' | 'TIME_WAIT'
export type TransportProtocol = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP' | 'OTHER'
export type Direction = 'up' | 'down' | 'local' | 'unknown'
export type EncryptionStatus = 'encrypted' | 'unencrypted' | 'unknown'

export interface FlowRecord {
  /** Deterministic 5-tuple key. */
  key: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  transport: TransportProtocol
  /** Application protocol decided by header inspection, not by port alone. */
  appProtocol: string
  /** How the app protocol was decided — shown in the UI so guesses are visible. */
  protocolConfidence: 'header' | 'heuristic' | 'port-hint' | 'unknown'
  encryption: EncryptionStatus
  direction: Direction
  state: FlowState
  firstSeen: number
  lastSeen: number
  bytesUp: number
  bytesDown: number
  packetsUp: number
  packetsDown: number
  /** TLS SNI or HTTP Host when observed unencrypted on the wire. */
  serverName: string | null
  /** Reverse-resolved from observed DNS answers only, never guessed. */
  remoteHostname: string | null
  deviceMac: string | null
  deviceIp: string | null
}

/* ------------------------------------------------------------------ */
/* Live traffic events (aggregated, never one message per packet)      */
/* ------------------------------------------------------------------ */

export interface LiveFlowUpdate {
  key: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  transport: TransportProtocol
  appProtocol: string
  encryption: EncryptionStatus
  direction: Direction
  state: FlowState
  lastSeen: number
  /** Bytes accumulated during this tick only. */
  deltaBytes: number
  deltaPackets: number
  totalBytes: number
  serverName: string | null
}

/* ------------------------------------------------------------------ */
/* Protocols                                                           */
/* ------------------------------------------------------------------ */

export interface ProtocolStat {
  protocol: string
  transport: TransportProtocol | 'MIXED'
  packets: number
  bytes: number
  connections: number
  encryption: EncryptionStatus
}

/* ------------------------------------------------------------------ */
/* DNS                                                                 */
/* ------------------------------------------------------------------ */

export interface DnsQueryRecord {
  id: number
  ts: number
  deviceIp: string | null
  deviceMac: string | null
  server: string
  query: string
  recordType: string
  /** Comma separated answers, empty when the response was not observed. */
  response: string | null
  responseCode: string | null
  latencyMs: number | null
}

/* ------------------------------------------------------------------ */
/* Unencrypted traffic                                                 */
/* ------------------------------------------------------------------ */

export interface UnencryptedEvent {
  id: number
  ts: number
  deviceIp: string | null
  deviceMac: string | null
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  protocol: string
  bytes: number
  /**
   * Non-sensitive metadata only. The redaction layer strips credentials,
   * cookies, tokens and bodies before this ever reaches the database.
   */
  metadata: string
  redacted: boolean
}

/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

export interface TlsSessionRecord {
  id: number
  ts: number
  deviceIp: string | null
  serverIp: string
  serverPort: number
  /** From the ClientHello SNI extension, which is sent in the clear. */
  sni: string | null
  version: string | null
  /** From the ServerHello / Certificate message when sent unencrypted (TLS 1.2). */
  certSubject: string | null
  certIssuer: string | null
  bytes: number
  durationMs: number
}

/* ------------------------------------------------------------------ */
/* Statistics                                                          */
/* ------------------------------------------------------------------ */

export interface TrafficSample {
  ts: number
  bytesUp: number
  bytesDown: number
  packets: number
}

export interface DashboardSnapshot {
  devicesTotal: number
  devicesOnline: number
  bytesTotal: number
  bytesUp: number
  bytesDown: number
  activeConnections: number
  packetsPerSec: number
  bytesPerSec: number
  topTalkers: Array<{ label: string; ip: string; bytes: number }>
  topProtocols: Array<{ protocol: string; bytes: number }>
  topDestinations: Array<{ label: string; bytes: number; connections: number }>
}

export type TimeRange = '1m' | '5m' | '15m' | '1h' | '24h' | '7d' | '30d'

/* ------------------------------------------------------------------ */
/* Alerts                                                              */
/* ------------------------------------------------------------------ */

export type AlertSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH'

export type AlertKind =
  | 'new-device'
  | 'unencrypted-protocol'
  | 'traffic-spike'
  | 'high-bandwidth'
  | 'port-scan-pattern'
  | 'excessive-dns'
  | 'large-upload'
  | 'unknown-protocol'

export interface AlertRecord {
  id: number
  ts: number
  kind: AlertKind
  severity: AlertSeverity
  title: string
  /** Plain language explanation of *why* this fired. Never asserts malice. */
  reason: string
  deviceIp: string | null
  deviceMac: string | null
  acknowledged: boolean
  /** Structured context, JSON encoded. */
  details: string | null
}

/* ------------------------------------------------------------------ */
/* Analytics                                                           */
/* ------------------------------------------------------------------ */

export interface AnalyticsReport {
  range: TimeRange
  from: number
  to: number
  avgBandwidthBps: number
  peakBandwidthBps: number
  peakAt: number | null
  avgPacketsPerSec: number
  totalBytes: number
  bytesUp: number
  bytesDown: number
  upDownRatio: number
  connectionCount: number
  topDevice: { label: string; bytes: number } | null
  topDestination: { label: string; bytes: number } | null
  topProtocol: { protocol: string; bytes: number } | null
  series: TrafficSample[]
}

/* ------------------------------------------------------------------ */
/* Packet capture (PCAP) — explicit, opt-in only                       */
/* ------------------------------------------------------------------ */

export interface PcapJobOptions {
  interfaceId: string
  /** BPF filter string. Validated against a strict allowlist before use. */
  filter: string
  maxSeconds: number
  maxMegabytes: number
  outputPath: string
}

export interface PcapJobStatus {
  running: boolean
  outputPath: string | null
  startedAt: number | null
  bytesWritten: number
  secondsElapsed: number
  error: string | null
}

/* ------------------------------------------------------------------ */
/* Settings                                                            */
/* ------------------------------------------------------------------ */

export type RetentionPolicy = '1d' | '7d' | '30d' | '90d' | 'unlimited'
export type Theme = 'dark' | 'light' | 'system'
export type Language = 'ar' | 'en'
export type LogLevel = 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR'

export interface AppSettings {
  interfaceId: string | null
  autoStart: boolean
  /**
   * Privacy Mode: suppresses payload-derived detail everywhere.
   * DNS queries, HTTP metadata and SNI are not persisted and are
   * masked in the live stream.
   */
  privacyMode: boolean
  storeDnsQueries: boolean
  storeUnencryptedMetadata: boolean
  retention: RetentionPolicy
  notificationsEnabled: boolean
  notifyMinSeverity: AlertSeverity
  theme: Theme
  language: Language
  /** Flow updates pushed to the UI per second. Lower = lighter UI. */
  uiUpdateHz: number
  maxLiveFlows: number
  logLevel: LogLevel
  telemetry: false
}

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

export interface LogEntry {
  id: number
  ts: number
  level: LogLevel
  scope: string
  message: string
}

/* ------------------------------------------------------------------ */
/* Search & filter                                                     */
/* ------------------------------------------------------------------ */

export interface FlowQuery {
  text?: string
  transport?: TransportProtocol[]
  appProtocol?: string[]
  encryption?: EncryptionStatus[]
  direction?: Direction[]
  deviceIp?: string
  port?: number
  from?: number
  to?: number
  limit?: number
  offset?: number
  sortBy?: 'lastSeen' | 'bytes' | 'firstSeen'
  sortDir?: 'asc' | 'desc'
}

/* ------------------------------------------------------------------ */
/* IPC event channel payloads (backend -> UI)                          */
/* ------------------------------------------------------------------ */

export interface EventMap {
  'engine:status': EngineStatus
  'stats:tick': { snapshot: DashboardSnapshot; sample: TrafficSample }
  'flows:update': { flows: LiveFlowUpdate[]; closed: string[] }
  'devices:update': DeviceRecord[]
  'dns:update': DnsQueryRecord[]
  'unencrypted:update': UnencryptedEvent[]
  'tls:update': TlsSessionRecord[]
  'alerts:new': AlertRecord[]
  'protocols:update': ProtocolStat[]
  'pcap:status': PcapJobStatus
  'log:new': LogEntry
  'router:status': RouterStatus
}

export type EventChannel = keyof EventMap
