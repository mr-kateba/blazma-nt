import { ipv4ToString, ipv6ToString } from '../utils/net.js'
import type { DnsAnswer, DnsInfo } from './types.js'

const TYPES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  35: 'NAPTR',
  43: 'DS',
  48: 'DNSKEY',
  64: 'SVCB',
  65: 'HTTPS',
  255: 'ANY'
}

const RCODES: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED'
}

/** Reads a (possibly compressed) DNS name. Guards against pointer loops. */
function readName(buf: Uint8Array, start: number): { name: string; next: number } {
  const labels: string[] = []
  let offset = start
  let next = -1
  let jumps = 0

  while (offset < buf.length) {
    const len = buf[offset]
    if (len === 0) {
      offset += 1
      break
    }
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= buf.length) break
      const pointer = ((len & 0x3f) << 8) | buf[offset + 1]
      if (next < 0) next = offset + 2
      if (++jumps > 16 || pointer >= buf.length || pointer === offset) break
      offset = pointer
      continue
    }
    if (len > 63 || offset + 1 + len > buf.length) break
    labels.push(new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(offset + 1, offset + 1 + len)))
    offset += 1 + len
  }

  return { name: labels.join('.'), next: next >= 0 ? next : offset }
}

function readRdata(buf: Uint8Array, view: DataView, type: number, offset: number, length: number): string {
  if (offset + length > buf.length) return ''
  switch (type) {
    case 1:
      return length === 4 ? ipv4ToString(buf, offset) : ''
    case 28:
      return length === 16 ? ipv6ToString(buf, offset) : ''
    case 5:
    case 2:
    case 12:
      return readName(buf, offset).name
    case 15:
      return length > 2 ? readName(buf, offset + 2).name : ''
    case 16: {
      const txtLen = buf[offset]
      return txtLen && offset + 1 + txtLen <= buf.length
        ? new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(offset + 1, offset + 1 + txtLen))
        : ''
    }
    case 33:
      return length > 6 ? `${view.getUint16(offset + 4)} ${readName(buf, offset + 6).name}` : ''
    default:
      return ''
  }
}

/**
 * Parses a DNS message (also used for mDNS, same wire format).
 * Returns null when the buffer is not a plausible DNS message.
 */
export function parseDns(buf: Uint8Array): DnsInfo | null {
  if (buf.length < 12) return null
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)

  const id = view.getUint16(0)
  const flags = view.getUint16(2)
  const qdCount = view.getUint16(4)
  const anCount = view.getUint16(6)

  const opcode = (flags >> 11) & 0x0f
  if (opcode > 5) return null
  if (qdCount > 64 || anCount > 128) return null

  const isResponse = (flags & 0x8000) !== 0
  const rcode = flags & 0x0f

  let offset = 12
  const questions: Array<{ name: string; type: string }> = []
  for (let i = 0; i < qdCount && offset < buf.length; i++) {
    const { name, next } = readName(buf, offset)
    offset = next
    if (offset + 4 > buf.length) return null
    const type = view.getUint16(offset)
    offset += 4
    if (!name) continue
    questions.push({ name, type: TYPES[type] ?? `TYPE${type}` })
  }

  const answers: DnsAnswer[] = []
  for (let i = 0; i < anCount && offset < buf.length; i++) {
    const { next } = readName(buf, offset)
    offset = next
    if (offset + 10 > buf.length) break
    const type = view.getUint16(offset)
    const ttl = view.getUint32(offset + 4)
    const rdLength = view.getUint16(offset + 8)
    offset += 10
    const data = readRdata(buf, view, type, offset, rdLength)
    offset += rdLength
    answers.push({ name: questions[0]?.name ?? '', type: TYPES[type] ?? `TYPE${type}`, data, ttl })
  }

  if (questions.length === 0 && answers.length === 0) return null

  return {
    id,
    isResponse,
    opcode,
    responseCode: RCODES[rcode] ?? `RCODE${rcode}`,
    questions,
    answers
  }
}
