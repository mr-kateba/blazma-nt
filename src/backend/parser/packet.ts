import { ipv4ToString, ipv6ToString, macToString } from '../utils/net.js'
import { parseDhcp } from './dhcp.js'
import { parseDns } from './dns.js'
import { looksLikeHttp, parseHttp } from './http.js'
import { looksLikeTlsRecord, parseTls } from './tls.js'
import type { AppLayer, ParsedPacket, TcpFlags } from './types.js'

export const LINKTYPE_ETHERNET = 1
export const LINKTYPE_RAW = 101
export const LINKTYPE_NULL = 0

const ETHERTYPE_IPV4 = 0x0800
const ETHERTYPE_ARP = 0x0806
const ETHERTYPE_IPV6 = 0x86dd
const ETHERTYPE_VLAN = 0x8100

const IPPROTO_ICMP = 1
const IPPROTO_TCP = 6
const IPPROTO_UDP = 17
const IPPROTO_ICMPV6 = 58

function emptyPacket(ts: number, wireLength: number, capturedLength: number): ParsedPacket {
  return {
    ts,
    wireLength,
    capturedLength,
    ethSrc: null,
    ethDst: null,
    etherType: null,
    vlanId: null,
    network: 'other',
    srcIp: null,
    dstIp: null,
    ipProtocol: null,
    ttl: null,
    transport: 'OTHER',
    srcPort: 0,
    dstPort: 0,
    tcpFlags: null,
    payloadOffset: 0,
    payloadLength: 0,
    arp: null,
    app: null,
    appProtocol: 'OTHER',
    confidence: 'unknown',
    encrypted: null
  }
}

function readTcpFlags(byte: number): TcpFlags {
  return {
    fin: (byte & 0x01) !== 0,
    syn: (byte & 0x02) !== 0,
    rst: (byte & 0x04) !== 0,
    psh: (byte & 0x08) !== 0,
    ack: (byte & 0x10) !== 0,
    urg: (byte & 0x20) !== 0
  }
}

/**
 * Application protocol identification.
 *
 * Header inspection is attempted first and always wins. A port number is only
 * used as a hint when the payload gives us nothing, and the resulting
 * confidence is reported so the UI can show how the label was reached.
 */
const PORT_HINTS: Record<number, { protocol: string; encrypted: boolean }> = {
  20: { protocol: 'FTP-DATA', encrypted: false },
  21: { protocol: 'FTP', encrypted: false },
  22: { protocol: 'SSH', encrypted: true },
  23: { protocol: 'TELNET', encrypted: false },
  25: { protocol: 'SMTP', encrypted: false },
  53: { protocol: 'DNS', encrypted: false },
  67: { protocol: 'DHCP', encrypted: false },
  68: { protocol: 'DHCP', encrypted: false },
  80: { protocol: 'HTTP', encrypted: false },
  110: { protocol: 'POP3', encrypted: false },
  123: { protocol: 'NTP', encrypted: false },
  137: { protocol: 'NBNS', encrypted: false },
  143: { protocol: 'IMAP', encrypted: false },
  443: { protocol: 'HTTPS', encrypted: true },
  465: { protocol: 'SMTPS', encrypted: true },
  587: { protocol: 'SMTP', encrypted: false },
  853: { protocol: 'DNS-over-TLS', encrypted: true },
  993: { protocol: 'IMAPS', encrypted: true },
  995: { protocol: 'POP3S', encrypted: true },
  1900: { protocol: 'SSDP', encrypted: false },
  3389: { protocol: 'RDP', encrypted: true },
  5353: { protocol: 'mDNS', encrypted: false },
  8080: { protocol: 'HTTP', encrypted: false }
}

function isQuic(payload: Uint8Array, srcPort: number, dstPort: number): boolean {
  if (payload.length < 5) return false
  const first = payload[0]
  // Long header form with a supported QUIC version (RFC 9000 onwards).
  if ((first & 0xc0) === 0xc0) {
    const version = (payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]
    if (version === 0x00000001 || (version >>> 8) === 0xff0000 || version === 0x6b3343cf) return true
  }
  // Short header packets carry no version, so fall back to the well-known port.
  return (first & 0xc0) === 0x40 && (srcPort === 443 || dstPort === 443)
}

function analyzeApp(
  packet: ParsedPacket,
  payload: Uint8Array
): { app: AppLayer | null; protocol: string; confidence: ParsedPacket['confidence']; encrypted: boolean | null } {
  const { srcPort, dstPort, transport } = packet

  if (payload.length === 0) {
    const hint = PORT_HINTS[dstPort] ?? PORT_HINTS[srcPort]
    return hint
      ? { app: null, protocol: hint.protocol, confidence: 'port-hint', encrypted: hint.encrypted }
      : { app: null, protocol: transport, confidence: 'unknown', encrypted: null }
  }

  if (transport === 'UDP') {
    if (srcPort === 5353 || dstPort === 5353) {
      const dns = parseDns(payload)
      if (dns) return { app: { protocol: 'MDNS', dns }, protocol: 'mDNS', confidence: 'header', encrypted: false }
    }
    if (srcPort === 53 || dstPort === 53) {
      const dns = parseDns(payload)
      if (dns) return { app: { protocol: 'DNS', dns }, protocol: 'DNS', confidence: 'header', encrypted: false }
    }
    if (srcPort === 67 || dstPort === 67 || srcPort === 68 || dstPort === 68) {
      const dhcp = parseDhcp(payload)
      if (dhcp) return { app: { protocol: 'DHCP', dhcp }, protocol: 'DHCP', confidence: 'header', encrypted: false }
    }
    if (isQuic(payload, srcPort, dstPort)) {
      return { app: { protocol: 'QUIC' }, protocol: 'QUIC', confidence: 'header', encrypted: true }
    }
    if ((srcPort === 123 || dstPort === 123) && payload.length >= 48 && (payload[0] & 0x38) >> 3 <= 4) {
      return { app: { protocol: 'NTP' }, protocol: 'NTP', confidence: 'header', encrypted: false }
    }
    if (srcPort === 1900 || dstPort === 1900) {
      return { app: { protocol: 'SSDP' }, protocol: 'SSDP', confidence: 'port-hint', encrypted: false }
    }
    // Some resolvers use non-standard ports; try DNS parsing as a last resort.
    const dns = parseDns(payload)
    if (dns && dns.questions.length > 0) {
      return { app: { protocol: 'DNS', dns }, protocol: 'DNS', confidence: 'heuristic', encrypted: false }
    }
  }

  if (transport === 'TCP') {
    if (looksLikeTlsRecord(payload)) {
      const tls = parseTls(payload)
      if (tls) return { app: { protocol: 'TLS', tls }, protocol: 'HTTPS/TLS', confidence: 'header', encrypted: true }
    }
    if (looksLikeHttp(payload)) {
      const http = parseHttp(payload)
      if (http) return { app: { protocol: 'HTTP', http }, protocol: 'HTTP', confidence: 'header', encrypted: false }
    }
    const head = String.fromCharCode(...payload.subarray(0, Math.min(payload.length, 16)))
    if (head.startsWith('SSH-')) {
      const banner = head.split('\r')[0].slice(0, 64)
      return { app: { protocol: 'SSH', banner }, protocol: 'SSH', confidence: 'header', encrypted: true }
    }
    if (/^\d{3}[ -]/.test(head)) {
      if (srcPort === 21 || dstPort === 21) {
        return { app: { protocol: 'FTP' }, protocol: 'FTP', confidence: 'header', encrypted: false }
      }
      if (srcPort === 25 || dstPort === 25 || srcPort === 587 || dstPort === 587) {
        return { app: { protocol: 'SMTP' }, protocol: 'SMTP', confidence: 'header', encrypted: false }
      }
      if (srcPort === 110 || dstPort === 110) {
        return { app: { protocol: 'POP3' }, protocol: 'POP3', confidence: 'header', encrypted: false }
      }
    }
    if (head.startsWith('* OK') || head.startsWith('A1 ')) {
      if (srcPort === 143 || dstPort === 143) {
        return { app: { protocol: 'IMAP' }, protocol: 'IMAP', confidence: 'header', encrypted: false }
      }
    }
    if ((srcPort === 23 || dstPort === 23) && payload[0] === 0xff) {
      return { app: { protocol: 'TELNET' }, protocol: 'TELNET', confidence: 'header', encrypted: false }
    }
  }

  const hint = PORT_HINTS[dstPort] ?? PORT_HINTS[srcPort]
  if (hint) return { app: null, protocol: hint.protocol, confidence: 'port-hint', encrypted: hint.encrypted }
  return { app: null, protocol: transport, confidence: 'unknown', encrypted: null }
}

function parseIpv4(packet: ParsedPacket, buf: Uint8Array, offset: number): void {
  if (offset + 20 > buf.length) return
  const ihl = (buf[offset] & 0x0f) * 4
  if (ihl < 20 || offset + ihl > buf.length) return

  packet.network = 'IPv4'
  packet.ttl = buf[offset + 8]
  packet.ipProtocol = buf[offset + 9]
  packet.srcIp = ipv4ToString(buf, offset + 12)
  packet.dstIp = ipv4ToString(buf, offset + 16)

  const totalLength = (buf[offset + 2] << 8) | buf[offset + 3]
  const fragmentField = (buf[offset + 6] << 8) | buf[offset + 7]
  const fragmentOffset = fragmentField & 0x1fff
  const ipEnd = Math.min(offset + (totalLength || buf.length - offset), buf.length)

  // Only the first fragment carries transport headers.
  if (fragmentOffset !== 0) {
    packet.transport = 'OTHER'
    return
  }
  parseTransport(packet, buf, offset + ihl, ipEnd)
}

function parseIpv6(packet: ParsedPacket, buf: Uint8Array, offset: number): void {
  if (offset + 40 > buf.length) return
  packet.network = 'IPv6'
  packet.ttl = buf[offset + 7]
  packet.srcIp = ipv6ToString(buf, offset + 8)
  packet.dstIp = ipv6ToString(buf, offset + 24)

  let nextHeader = buf[offset + 6]
  let cursor = offset + 40
  const payloadLength = (buf[offset + 4] << 8) | buf[offset + 5]
  const end = Math.min(offset + 40 + payloadLength, buf.length)

  // Walk the extension header chain to reach the transport header.
  const EXTENSIONS = new Set([0, 43, 60])
  let guard = 0
  while (EXTENSIONS.has(nextHeader) && cursor + 8 <= end && guard++ < 8) {
    const headerLength = (buf[cursor + 1] + 1) * 8
    nextHeader = buf[cursor]
    cursor += headerLength
  }

  packet.ipProtocol = nextHeader
  parseTransport(packet, buf, cursor, end)
}

function parseTransport(packet: ParsedPacket, buf: Uint8Array, offset: number, end: number): void {
  const protocol = packet.ipProtocol

  if (protocol === IPPROTO_TCP) {
    if (offset + 20 > buf.length) return
    packet.transport = 'TCP'
    packet.srcPort = (buf[offset] << 8) | buf[offset + 1]
    packet.dstPort = (buf[offset + 2] << 8) | buf[offset + 3]
    packet.tcpFlags = readTcpFlags(buf[offset + 13])
    const dataOffset = ((buf[offset + 12] & 0xf0) >> 4) * 4
    if (dataOffset < 20) return
    packet.payloadOffset = offset + dataOffset
    packet.payloadLength = Math.max(0, Math.min(end, buf.length) - packet.payloadOffset)
    return
  }

  if (protocol === IPPROTO_UDP) {
    if (offset + 8 > buf.length) return
    packet.transport = 'UDP'
    packet.srcPort = (buf[offset] << 8) | buf[offset + 1]
    packet.dstPort = (buf[offset + 2] << 8) | buf[offset + 3]
    const udpLength = (buf[offset + 4] << 8) | buf[offset + 5]
    packet.payloadOffset = offset + 8
    packet.payloadLength = Math.max(
      0,
      Math.min(udpLength > 8 ? offset + udpLength : end, buf.length) - packet.payloadOffset
    )
    return
  }

  if (protocol === IPPROTO_ICMP) {
    packet.transport = 'ICMP'
    return
  }
  if (protocol === IPPROTO_ICMPV6) {
    packet.transport = 'ICMPv6'
    return
  }
  packet.transport = 'OTHER'
}

function parseArp(packet: ParsedPacket, buf: Uint8Array, offset: number): void {
  if (offset + 28 > buf.length) return
  const hardwareSize = buf[offset + 4]
  const protocolSize = buf[offset + 5]
  if (hardwareSize !== 6 || protocolSize !== 4) return

  const operation = (buf[offset + 6] << 8) | buf[offset + 7]
  packet.network = 'ARP'
  packet.transport = 'ARP'
  packet.arp = {
    operation: operation === 1 ? 'request' : operation === 2 ? 'reply' : 'other',
    senderMac: macToString(buf, offset + 8),
    senderIp: ipv4ToString(buf, offset + 14),
    targetMac: macToString(buf, offset + 18),
    targetIp: ipv4ToString(buf, offset + 24)
  }
  packet.srcIp = packet.arp.senderIp
  packet.dstIp = packet.arp.targetIp
  packet.confidence = 'header'
}

/**
 * Parses one captured frame. Never throws: a malformed packet yields a partial
 * result, because a hostile or corrupt frame must not stop the capture loop.
 */
export function parsePacket(
  data: Uint8Array,
  ts: number,
  wireLength: number,
  linkType = LINKTYPE_ETHERNET
): ParsedPacket {
  const packet = emptyPacket(ts, wireLength, data.length)

  try {
    let offset = 0

    if (linkType === LINKTYPE_ETHERNET) {
      if (data.length < 14) return packet
      packet.ethDst = macToString(data, 0)
      packet.ethSrc = macToString(data, 6)
      let etherType = (data[12] << 8) | data[13]
      offset = 14

      // Up to two stacked VLAN tags (802.1Q / QinQ).
      let vlanDepth = 0
      while ((etherType === ETHERTYPE_VLAN || etherType === 0x88a8) && offset + 4 <= data.length && vlanDepth++ < 2) {
        packet.vlanId = ((data[offset] & 0x0f) << 8) | data[offset + 1]
        etherType = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4
      }
      packet.etherType = etherType

      if (etherType === ETHERTYPE_IPV4) parseIpv4(packet, data, offset)
      else if (etherType === ETHERTYPE_IPV6) parseIpv6(packet, data, offset)
      else if (etherType === ETHERTYPE_ARP) parseArp(packet, data, offset)
    } else if (linkType === LINKTYPE_RAW) {
      const version = (data[0] ?? 0) >> 4
      if (version === 4) parseIpv4(packet, data, 0)
      else if (version === 6) parseIpv6(packet, data, 0)
    } else if (linkType === LINKTYPE_NULL) {
      if (data.length < 4) return packet
      const family = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
      if (family === 2) parseIpv4(packet, data, 4)
      else if (family === 23 || family === 24 || family === 28 || family === 30) parseIpv6(packet, data, 4)
    }

    if (packet.transport === 'TCP' || packet.transport === 'UDP') {
      const payload = data.subarray(packet.payloadOffset, packet.payloadOffset + packet.payloadLength)
      const result = analyzeApp(packet, payload)
      packet.app = result.app
      packet.appProtocol = result.protocol
      packet.confidence = result.confidence
      packet.encrypted = result.encrypted
    } else {
      packet.appProtocol = packet.transport
    }
  } catch {
    // Partial parse is fine — never let a bad frame escape as an exception.
  }

  return packet
}
