/**
 * Input validation for every value that reaches a child process or the file
 * system. Arguments are already passed as argv arrays (never through a shell),
 * so this layer exists to reject nonsense early and to keep capture filters
 * from smuggling extra flags into the capture tool.
 */

import { isAbsolute, normalize } from 'node:path'

export class ValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ValidationError'
  }
}

/**
 * Npcap device names look like \Device\NPF_{GUID}; the "alias:" form is used
 * for adapters we can enumerate but not capture from.
 */
export function validateInterfaceId(id: unknown): string {
  if (typeof id !== 'string' || id.length === 0 || id.length > 256) {
    throw new ValidationError('Interface id must be a non-empty string.')
  }
  if (/^\\Device\\NPF_\{[0-9A-Fa-f-]{36}\}$/.test(id)) return id
  if (/^alias:[\w \-.()#]{1,128}$/.test(id)) return id
  if (/^\\Device\\NPF_Loopback$/.test(id)) return id
  throw new ValidationError(`Unsupported interface id: ${id.slice(0, 64)}`)
}

/**
 * BPF capture filters are a small language. Rather than trying to parse it we
 * allow only the characters and keywords that appear in legitimate filters, and
 * reject anything that could be read as an extra command-line option.
 */
const BPF_KEYWORDS = new Set([
  'and',
  'or',
  'not',
  'host',
  'net',
  'mask',
  'port',
  'portrange',
  'src',
  'dst',
  'ether',
  'gateway',
  'ip',
  'ip6',
  'arp',
  'rarp',
  'tcp',
  'udp',
  'icmp',
  'icmp6',
  'vlan',
  'proto',
  'broadcast',
  'multicast',
  'less',
  'greater',
  'len'
])

export function validateBpfFilter(filter: unknown): string {
  if (filter === undefined || filter === null) return ''
  if (typeof filter !== 'string') throw new ValidationError('Capture filter must be a string.')
  const trimmed = filter.trim()
  if (trimmed.length === 0) return ''
  if (trimmed.length > 512) throw new ValidationError('Capture filter is too long (max 512 characters).')
  if (trimmed.startsWith('-')) throw new ValidationError('Capture filter must not start with "-".')
  if (!/^[A-Za-z0-9 ()\[\]:.\-_/><=!&|]+$/.test(trimmed)) {
    throw new ValidationError('Capture filter contains unsupported characters.')
  }

  // Only tokens that begin with a letter are keywords; addresses, ports and
  // masks are numeric and are left to the capture tool's own parser.
  for (const word of trimmed.match(/[A-Za-z][A-Za-z0-9]*/g) ?? []) {
    if (!BPF_KEYWORDS.has(word.toLowerCase())) {
      throw new ValidationError(`Unsupported keyword in capture filter: ${word.slice(0, 32)}`)
    }
  }
  return trimmed
}

export function validateSavePath(path: unknown, allowedExtensions: string[]): string {
  if (typeof path !== 'string' || path.length === 0 || path.length > 32767) {
    throw new ValidationError('Output path must be a non-empty string.')
  }
  const normalized = normalize(path)
  if (!isAbsolute(normalized)) throw new ValidationError('Output path must be absolute.')
  if (normalized.includes('\0')) throw new ValidationError('Output path contains a null byte.')
  const lower = normalized.toLowerCase()
  if (!allowedExtensions.some((ext) => lower.endsWith(ext))) {
    throw new ValidationError(`Output file must end with one of: ${allowedExtensions.join(', ')}`)
  }
  return normalized
}

export function validateInt(value: unknown, min: number, max: number, name: string): number {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < min || n > max) {
    throw new ValidationError(`${name} must be an integer between ${min} and ${max}.`)
  }
  return n
}

export function validateSearchText(value: unknown, maxLength = 128): string | undefined {
  if (value === undefined || value === null || value === '') return undefined
  if (typeof value !== 'string') throw new ValidationError('Search text must be a string.')
  // Bound the length; the value is only ever used as a bound SQL parameter.
  return value.slice(0, maxLength)
}
