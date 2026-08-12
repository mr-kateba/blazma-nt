import type { TlsInfo } from './types.js'

/**
 * TLS record inspection. We read only what the protocol sends in the clear:
 * the record header, the ClientHello SNI extension, the negotiated version and
 * — for TLS 1.2 and earlier, where it is not encrypted — the Common Name of the
 * server certificate. No decryption is attempted anywhere in this file.
 */

const VERSIONS: Record<number, string> = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3'
}

export function looksLikeTlsRecord(buf: Uint8Array): boolean {
  if (buf.length < 5) return false
  const type = buf[0]
  // handshake / alert / application data / change cipher spec
  if (type < 20 || type > 23) return false
  const major = buf[1]
  const minor = buf[2]
  if (major !== 0x03 || minor > 0x04) return false
  const length = (buf[3] << 8) | buf[4]
  return length > 0 && length <= 16384 + 2048
}

function readSni(buf: Uint8Array, extStart: number, extLength: number): string | null {
  let offset = extStart
  const end = Math.min(extStart + extLength, buf.length)
  while (offset + 4 <= end) {
    const type = (buf[offset] << 8) | buf[offset + 1]
    const length = (buf[offset + 2] << 8) | buf[offset + 3]
    offset += 4
    if (type === 0x0000 && offset + 5 <= end) {
      // server_name extension: list length (2) + name type (1) + name length (2)
      const nameLength = (buf[offset + 3] << 8) | buf[offset + 4]
      const nameStart = offset + 5
      if (nameLength > 0 && nameLength <= 253 && nameStart + nameLength <= buf.length) {
        const name = new TextDecoder('utf-8', { fatal: false }).decode(
          buf.subarray(nameStart, nameStart + nameLength)
        )
        return /^[A-Za-z0-9.\-_*]+$/.test(name) ? name : null
      }
      return null
    }
    offset += length
  }
  return null
}

function parseClientHello(buf: Uint8Array, start: number, end: number): TlsInfo {
  let offset = start + 4 // handshake header
  const info: TlsInfo = { kind: 'client-hello', version: null, sni: null, certSubject: null, certIssuer: null }
  if (offset + 34 > end) return info

  info.version = VERSIONS[(buf[offset] << 8) | buf[offset + 1]] ?? null
  offset += 2 + 32 // client version + random

  const sessionIdLength = buf[offset]
  offset += 1 + sessionIdLength
  if (offset + 2 > end) return info

  const cipherLength = (buf[offset] << 8) | buf[offset + 1]
  offset += 2 + cipherLength
  if (offset + 1 > end) return info

  const compressionLength = buf[offset]
  offset += 1 + compressionLength
  if (offset + 2 > end) return info

  const extensionsLength = (buf[offset] << 8) | buf[offset + 1]
  offset += 2
  info.sni = readSni(buf, offset, extensionsLength)
  return info
}

/**
 * Pulls the Common Name out of a DER-encoded X.509 name by scanning for the
 * CN attribute OID (2.5.4.3 -> 06 03 55 04 03). Deliberately shallow: this is
 * display metadata, not a validation path.
 */
function scanCommonNames(buf: Uint8Array, start: number, end: number): string[] {
  const found: string[] = []
  for (let i = start; i + 7 < end && found.length < 4; i++) {
    if (buf[i] === 0x06 && buf[i + 1] === 0x03 && buf[i + 2] === 0x55 && buf[i + 3] === 0x04 && buf[i + 4] === 0x03) {
      const tag = buf[i + 5]
      // PrintableString / UTF8String / IA5String
      if (tag !== 0x13 && tag !== 0x0c && tag !== 0x16) continue
      const length = buf[i + 6]
      if (length === 0 || length > 100 || i + 7 + length > end) continue
      const value = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(i + 7, i + 7 + length))
      if (/^[\x20-\x7e]+$/.test(value)) found.push(value)
      i += 6 + length
    }
  }
  return found
}

export function parseTls(buf: Uint8Array): TlsInfo | null {
  if (!looksLikeTlsRecord(buf)) return null
  const recordType = buf[0]
  const recordLength = (buf[3] << 8) | buf[4]
  const end = Math.min(5 + recordLength, buf.length)

  if (recordType === 23) {
    return { kind: 'application-data', version: null, sni: null, certSubject: null, certIssuer: null }
  }
  if (recordType === 21) {
    return { kind: 'alert', version: null, sni: null, certSubject: null, certIssuer: null }
  }
  if (recordType !== 22 || end <= 6) {
    return { kind: 'other', version: null, sni: null, certSubject: null, certIssuer: null }
  }

  const handshakeType = buf[5]
  if (handshakeType === 0x01) return parseClientHello(buf, 5, end)

  if (handshakeType === 0x02) {
    const version = end > 11 ? (VERSIONS[(buf[9] << 8) | buf[10]] ?? null) : null
    return { kind: 'server-hello', version, sni: null, certSubject: null, certIssuer: null }
  }

  if (handshakeType === 0x0b) {
    // Certificate. In TLS 1.3 this record is encrypted and never reaches here.
    // Within a certificate, DER orders issuer before subject, so the first two
    // Common Names we meet belong to the leaf certificate.
    const names = scanCommonNames(buf, 5, end)
    return {
      kind: 'certificate',
      version: null,
      sni: null,
      certSubject: names[1] ?? null,
      certIssuer: names[0] ?? null
    }
  }

  return { kind: 'other', version: null, sni: null, certSubject: null, certIssuer: null }
}
