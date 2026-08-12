/**
 * Synthetic packet fixtures.
 *
 * Every test builds its frames here rather than replaying a real capture, so
 * the suite never depends on a live network and never contains anyone's real
 * traffic.
 */

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

export function bytes(...parts: Array<number | Uint8Array | number[]>): Uint8Array {
  const chunks: Uint8Array[] = parts.map((p) =>
    typeof p === 'number' ? Uint8Array.of(p) : p instanceof Uint8Array ? p : Uint8Array.from(p)
  )
  const total = chunks.reduce((sum, c) => sum + c.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

export const MAC_A = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
export const MAC_B = Uint8Array.of(0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33)

export function u16(value: number): Uint8Array {
  return Uint8Array.of((value >> 8) & 0xff, value & 0xff)
}

export function u32(value: number): Uint8Array {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)
}

export function ipv4(address: string): Uint8Array {
  return Uint8Array.from(address.split('.').map(Number))
}

// src/dst are annotated rather than inferred from their defaults, which would
// otherwise narrow them to Uint8Array<ArrayBuffer> and reject Buffer-backed views.
export function ethernet(
  etherType: number,
  payload: Uint8Array,
  src: Uint8Array = MAC_A,
  dst: Uint8Array = MAC_B
): Uint8Array {
  return bytes(dst, src, u16(etherType), payload)
}

/** Builds an IPv4 packet. The checksum is left zero; the parser ignores it. */
export function ipv4Packet(protocol: number, src: string, dst: string, payload: Uint8Array): Uint8Array {
  const totalLength = 20 + payload.length
  return bytes(
    0x45,
    0x00,
    u16(totalLength),
    u16(0x1234),
    u16(0x4000),
    64,
    protocol,
    u16(0),
    ipv4(src),
    ipv4(dst),
    payload
  )
}

export function ipv6Packet(nextHeader: number, src: Uint8Array, dst: Uint8Array, payload: Uint8Array): Uint8Array {
  return bytes(0x60, 0x00, 0x00, 0x00, u16(payload.length), nextHeader, 64, src, dst, payload)
}

export function tcpSegment(
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
  flags: { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean } = {}
): Uint8Array {
  const flagByte =
    (flags.fin ? 0x01 : 0) |
    (flags.syn ? 0x02 : 0) |
    (flags.rst ? 0x04 : 0) |
    (flags.psh ? 0x08 : 0) |
    (flags.ack ? 0x10 : 0)
  return bytes(u16(srcPort), u16(dstPort), u32(1000), u32(2000), 0x50, flagByte, u16(65535), u16(0), u16(0), payload)
}

export function udpDatagram(srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  return bytes(u16(srcPort), u16(dstPort), u16(8 + payload.length), u16(0), payload)
}

export function arpFrame(
  operation: 1 | 2,
  senderMac: Uint8Array,
  senderIp: string,
  targetMac: Uint8Array,
  targetIp: string
): Uint8Array {
  return ethernet(
    0x0806,
    bytes(u16(1), u16(0x0800), 6, 4, u16(operation), senderMac, ipv4(senderIp), targetMac, ipv4(targetIp)),
    senderMac,
    targetMac
  )
}

/** Encodes a DNS name as a sequence of length-prefixed labels. */
export function dnsName(name: string): Uint8Array {
  const parts = name.split('.').map((label) => bytes(label.length, Uint8Array.from(Buffer.from(label, 'ascii'))))
  return bytes(...parts, 0)
}

export function dnsQuery(id: number, name: string, type = 1): Uint8Array {
  return bytes(u16(id), u16(0x0100), u16(1), u16(0), u16(0), u16(0), dnsName(name), u16(type), u16(1))
}

export function dnsResponse(id: number, name: string, address: string): Uint8Array {
  return bytes(
    u16(id),
    u16(0x8180),
    u16(1),
    u16(1),
    u16(0),
    u16(0),
    dnsName(name),
    u16(1),
    u16(1),
    // Answer with a compression pointer back to the question name at offset 12.
    u16(0xc00c),
    u16(1),
    u16(1),
    u32(300),
    u16(4),
    ipv4(address)
  )
}

/** Minimal TLS 1.2 ClientHello carrying an SNI extension. */
export function tlsClientHello(serverName: string): Uint8Array {
  const nameBytes = Uint8Array.from(Buffer.from(serverName, 'ascii'))
  const serverNameList = bytes(u16(nameBytes.length + 3), 0x00, u16(nameBytes.length), nameBytes)
  const sniExtension = bytes(u16(0x0000), u16(serverNameList.length), serverNameList)
  const extensions = bytes(u16(sniExtension.length), sniExtension)

  const body = bytes(
    u16(0x0303),
    new Uint8Array(32),
    0x00,
    u16(2),
    u16(0x1301),
    0x01,
    0x00,
    extensions
  )
  const handshake = bytes(0x01, 0x00, u16(body.length), body)
  return bytes(0x16, 0x03, 0x01, u16(handshake.length), handshake)
}

export function tlsApplicationData(length = 64): Uint8Array {
  return bytes(0x17, 0x03, 0x03, u16(length), new Uint8Array(length))
}

export function httpRequest(line: string, headers: string[]): Uint8Array {
  return Uint8Array.from(Buffer.from(`${line}\r\n${headers.join('\r\n')}\r\n\r\n`, 'ascii'))
}

export function dhcpPacket(hostname: string, messageType = 3): Uint8Array {
  const nameBytes = Uint8Array.from(Buffer.from(hostname, 'ascii'))
  const header = bytes(
    0x01,
    0x01,
    0x06,
    0x00,
    u32(0x11223344),
    u16(0),
    u16(0),
    ipv4('0.0.0.0'),
    ipv4('0.0.0.0'),
    ipv4('0.0.0.0'),
    ipv4('0.0.0.0'),
    MAC_A,
    new Uint8Array(10),
    new Uint8Array(64),
    new Uint8Array(128),
    u32(0x63825363)
  )
  return bytes(header, 53, 1, messageType, 12, nameBytes.length, nameBytes, 255)
}

/** Wraps frames into a classic pcap stream, as dumpcap -P would emit. */
export function pcapStream(frames: Uint8Array[], linkType = 1): Uint8Array {
  const header = bytes(
    Uint8Array.of(0xd4, 0xc3, 0xb2, 0xa1), // little-endian magic
    Uint8Array.of(0x02, 0x00, 0x04, 0x00), // version 2.4
    new Uint8Array(8),
    Uint8Array.of(0x00, 0x00, 0x04, 0x00), // snaplen 262144
    Uint8Array.of(linkType & 0xff, (linkType >> 8) & 0xff, 0x00, 0x00)
  )
  const le32 = (value: number): Uint8Array =>
    Uint8Array.of(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff)

  const records = frames.map((frame) => bytes(le32(1700000000), le32(500000), le32(frame.length), le32(frame.length), frame))
  return bytes(header, ...records)
}
