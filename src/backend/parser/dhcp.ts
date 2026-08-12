import { ipv4ToString, macToString } from '../utils/net.js'
import type { DhcpInfo } from './types.js'

const MESSAGE_TYPES: Record<number, string> = {
  1: 'DISCOVER',
  2: 'OFFER',
  3: 'REQUEST',
  4: 'DECLINE',
  5: 'ACK',
  6: 'NAK',
  7: 'RELEASE',
  8: 'INFORM'
}

const MAGIC_COOKIE = 0x63825363

/**
 * Parses BOOTP/DHCP. Option 12 (host name) is the single most reliable source
 * of a real device name on a LAN, which is why device discovery listens for it.
 */
export function parseDhcp(buf: Uint8Array): DhcpInfo | null {
  if (buf.length < 240) return null
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)

  const op = buf[0]
  if (op !== 1 && op !== 2) return null
  if (view.getUint32(236) !== MAGIC_COOKIE) return null

  const info: DhcpInfo = {
    messageType: 'UNKNOWN',
    clientMac: buf[2] === 6 ? macToString(buf, 28) : null,
    requestedIp: null,
    hostname: null
  }

  let offset = 240
  while (offset < buf.length) {
    const code = buf[offset]
    if (code === 255) break
    if (code === 0) {
      offset += 1
      continue
    }
    if (offset + 1 >= buf.length) break
    const length = buf[offset + 1]
    const valueStart = offset + 2
    if (valueStart + length > buf.length) break

    switch (code) {
      case 53:
        if (length === 1) info.messageType = MESSAGE_TYPES[buf[valueStart]] ?? 'UNKNOWN'
        break
      case 50:
        if (length === 4) info.requestedIp = ipv4ToString(buf, valueStart)
        break
      case 12: {
        const name = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(valueStart, valueStart + length))
        if (/^[\x20-\x7e]{1,63}$/.test(name)) info.hostname = name
        break
      }
      default:
        break
    }
    offset = valueStart + length
  }

  return info
}
