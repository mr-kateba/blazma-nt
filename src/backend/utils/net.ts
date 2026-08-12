/** IP / MAC helpers. Pure functions, unit tested in tests/net.test.ts. */

export function ipv4ToString(buf: Uint8Array, offset: number): string {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`
}

export function ipv6ToString(buf: Uint8Array, offset: number): string {
  const groups: string[] = []
  for (let i = 0; i < 16; i += 2) {
    groups.push(((buf[offset + i] << 8) | buf[offset + i + 1]).toString(16))
  }
  // RFC 5952: collapse the longest run of zero groups (>= 2) into "::".
  let bestStart = -1
  let bestLen = 0
  let curStart = -1
  let curLen = 0
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) curStart = i
      curLen++
      if (curLen > bestLen) {
        bestLen = curLen
        bestStart = curStart
      }
    } else {
      curStart = -1
      curLen = 0
    }
  }
  if (bestLen < 2) return groups.join(':')
  const head = groups.slice(0, bestStart).join(':')
  const tail = groups.slice(bestStart + bestLen).join(':')
  return `${head}::${tail}`
}

export function macToString(buf: Uint8Array, offset: number): string {
  const parts: string[] = []
  for (let i = 0; i < 6; i++) parts.push(buf[offset + i].toString(16).padStart(2, '0').toUpperCase())
  return parts.join(':')
}

export function normalizeMac(mac: string | null | undefined): string | null {
  if (!mac) return null
  const hex = mac.replace(/[^0-9a-fA-F]/g, '')
  if (hex.length !== 12) return null
  return (hex.toUpperCase().match(/.{2}/g) as string[]).join(':')
}

export function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    const n = Number(p)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = (out << 8) | n
  }
  return out >>> 0
}

export function isIpv4(ip: string): boolean {
  return ipv4ToInt(ip) !== null
}

/** True when `ip` sits inside the CIDR block described by base/prefix. */
export function inSubnet(ip: string, base: string, prefixLength: number): boolean {
  const a = ipv4ToInt(ip)
  const b = ipv4ToInt(base)
  if (a === null || b === null) return false
  if (prefixLength <= 0) return true
  if (prefixLength > 32) return false
  const mask = prefixLength === 32 ? 0xffffffff : (0xffffffff << (32 - prefixLength)) >>> 0
  return ((a & mask) >>> 0) === ((b & mask) >>> 0)
}

const PRIVATE_V4: Array<[string, number]> = [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['169.254.0.0', 16],
  ['127.0.0.0', 8],
  ['100.64.0.0', 10]
]

export function isPrivateIp(ip: string): boolean {
  if (ip.includes(':')) {
    const lower = ip.toLowerCase()
    return (
      lower === '::1' ||
      lower.startsWith('fe80') ||
      lower.startsWith('fc') ||
      lower.startsWith('fd') ||
      lower.startsWith('ff')
    )
  }
  return PRIVATE_V4.some(([base, prefix]) => inSubnet(ip, base, prefix))
}

export function isMulticastOrBroadcast(ip: string): boolean {
  if (ip.includes(':')) return ip.toLowerCase().startsWith('ff')
  if (ip === '255.255.255.255') return true
  const first = Number(ip.split('.')[0])
  return first >= 224 && first <= 239
}

/**
 * Deterministic key for a flow. The endpoint pair is ordered so that both
 * directions of the same conversation land on one record; `initiator` records
 * which side we saw first so up/down stays meaningful.
 */
export function flowKey(
  aIp: string,
  aPort: number,
  bIp: string,
  bPort: number,
  transport: string
): { key: string; swapped: boolean } {
  const left = `${aIp}|${aPort}`
  const right = `${bIp}|${bPort}`
  const swapped = left > right
  const key = swapped ? `${transport}|${right}|${left}` : `${transport}|${left}|${right}`
  return { key, swapped }
}
