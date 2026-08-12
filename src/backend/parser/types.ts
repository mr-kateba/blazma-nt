import type { TransportProtocol } from '../../shared/types.js'

export interface TcpFlags {
  fin: boolean
  syn: boolean
  rst: boolean
  psh: boolean
  ack: boolean
  urg: boolean
}

export interface ArpInfo {
  operation: 'request' | 'reply' | 'other'
  senderMac: string
  senderIp: string
  targetMac: string
  targetIp: string
}

export interface DnsAnswer {
  name: string
  type: string
  data: string
  ttl: number
}

export interface DnsInfo {
  id: number
  isResponse: boolean
  opcode: number
  responseCode: string
  questions: Array<{ name: string; type: string }>
  answers: DnsAnswer[]
}

export interface HttpInfo {
  kind: 'request' | 'response'
  method: string | null
  path: string | null
  version: string | null
  statusCode: number | null
  host: string | null
  /** Already redacted: only non-sensitive headers survive this far. */
  safeHeaders: Array<[string, string]>
  /** True when at least one header or the body was withheld. */
  redacted: boolean
}

export interface TlsInfo {
  kind: 'client-hello' | 'server-hello' | 'certificate' | 'application-data' | 'alert' | 'other'
  version: string | null
  sni: string | null
  certSubject: string | null
  certIssuer: string | null
}

export interface DhcpInfo {
  messageType: string
  clientMac: string | null
  requestedIp: string | null
  /** DHCP option 12; a device-supplied name, useful for device discovery. */
  hostname: string | null
}

export type AppLayer =
  | { protocol: 'DNS'; dns: DnsInfo }
  | { protocol: 'HTTP'; http: HttpInfo }
  | { protocol: 'TLS'; tls: TlsInfo }
  | { protocol: 'DHCP'; dhcp: DhcpInfo }
  | { protocol: 'QUIC' }
  | { protocol: 'NTP' }
  | { protocol: 'SSH'; banner: string | null }
  | { protocol: 'FTP' }
  | { protocol: 'SMTP' }
  | { protocol: 'IMAP' }
  | { protocol: 'POP3' }
  | { protocol: 'TELNET' }
  | { protocol: 'MDNS'; dns: DnsInfo }
  | { protocol: 'NBNS' }
  | { protocol: 'SSDP' }

export interface ParsedPacket {
  ts: number
  /** Length on the wire, which may exceed the captured slice. */
  wireLength: number
  capturedLength: number
  ethSrc: string | null
  ethDst: string | null
  etherType: number | null
  vlanId: number | null
  network: 'IPv4' | 'IPv6' | 'ARP' | 'other'
  srcIp: string | null
  dstIp: string | null
  ipProtocol: number | null
  ttl: number | null
  transport: TransportProtocol
  srcPort: number
  dstPort: number
  tcpFlags: TcpFlags | null
  payloadOffset: number
  payloadLength: number
  arp: ArpInfo | null
  app: AppLayer | null
  /** Resolved application protocol label, e.g. "HTTP", "HTTPS/TLS", "DNS". */
  appProtocol: string
  /** How the app protocol was determined. */
  confidence: 'header' | 'heuristic' | 'port-hint' | 'unknown'
  /** True when the payload is known-encrypted (TLS records, QUIC, SSH). */
  encrypted: boolean | null
}
