import type { HttpInfo } from './types.js'

/**
 * Plaintext HTTP inspection.
 *
 * Only the request line, the status line and an explicit allowlist of
 * non-sensitive headers are extracted. Credentials, cookies, tokens and bodies
 * are never read into the returned structure — the allowlist is the mechanism,
 * so there is no code path where a secret is captured and filtered later.
 */

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'] as const

/** Headers that describe the request/response, not the user or their session. */
const HEADER_ALLOWLIST = new Set([
  'host',
  'user-agent',
  'content-type',
  'content-length',
  'accept',
  'accept-encoding',
  'accept-language',
  'connection',
  'server',
  'location',
  'cache-control',
  'content-encoding',
  'transfer-encoding',
  'upgrade',
  'referer'
])

/** Query strings frequently carry tokens, so values are dropped from the path. */
function sanitizePath(path: string): { path: string; redacted: boolean } {
  const q = path.indexOf('?')
  if (q < 0) return { path: path.slice(0, 512), redacted: false }
  return { path: `${path.slice(0, q)}?[query redacted]`.slice(0, 512), redacted: true }
}

/** `Referer` can embed a session in its own query string, so strip it too. */
function sanitizeHeaderValue(name: string, value: string): string {
  if (name === 'referer') {
    const q = value.indexOf('?')
    return (q < 0 ? value : `${value.slice(0, q)}?[query redacted]`).slice(0, 256)
  }
  return value.slice(0, 256)
}

export function looksLikeHttp(buf: Uint8Array): boolean {
  if (buf.length < 6) return false
  const head = String.fromCharCode(...buf.subarray(0, 8))
  if (head.startsWith('HTTP/')) return true
  return METHODS.some((m) => head.startsWith(`${m} `))
}

export function parseHttp(buf: Uint8Array): HttpInfo | null {
  if (!looksLikeHttp(buf)) return null

  // Read the header block only. The body is never decoded.
  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, Math.min(buf.length, 8192)))
  const headerEnd = text.indexOf('\r\n\r\n')
  const headerBlock = headerEnd < 0 ? text : text.slice(0, headerEnd)
  const lines = headerBlock.split('\r\n')
  const startLine = lines[0] ?? ''
  if (!startLine) return null

  let redacted = headerEnd >= 0 && buf.length > headerEnd + 4
  const info: HttpInfo = {
    kind: 'request',
    method: null,
    path: null,
    version: null,
    statusCode: null,
    host: null,
    safeHeaders: [],
    redacted
  }

  if (startLine.startsWith('HTTP/')) {
    const [version, status] = startLine.split(' ')
    info.kind = 'response'
    info.version = version ?? null
    info.statusCode = Number.isInteger(Number(status)) ? Number(status) : null
  } else {
    const [method, rawPath, version] = startLine.split(' ')
    if (!METHODS.includes(method as (typeof METHODS)[number])) return null
    const clean = sanitizePath(rawPath ?? '')
    info.method = method
    info.path = clean.path
    info.version = version ?? null
    redacted = redacted || clean.redacted
  }

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    const name = line.slice(0, colon).trim().toLowerCase()
    const value = line.slice(colon + 1).trim()
    if (!HEADER_ALLOWLIST.has(name)) {
      // Anything not explicitly allowed is dropped without being recorded.
      redacted = true
      continue
    }
    if (name === 'host') info.host = value.slice(0, 253)
    info.safeHeaders.push([name, sanitizeHeaderValue(name, value)])
  }

  info.redacted = redacted
  return info
}

/** One-line summary shown on the Unencrypted Traffic page. */
export function summarizeHttp(info: HttpInfo): string {
  const parts: string[] = []
  if (info.kind === 'request') {
    parts.push(`${info.method ?? '?'} ${info.path ?? '/'}`)
    if (info.host) parts.push(`Host: ${info.host}`)
  } else {
    parts.push(`${info.version ?? 'HTTP'} ${info.statusCode ?? ''}`.trim())
    const type = info.safeHeaders.find(([k]) => k === 'content-type')
    if (type) parts.push(`Content-Type: ${type[1]}`)
  }
  if (info.redacted) parts.push('[Sensitive data redacted]')
  return parts.join('  |  ')
}
