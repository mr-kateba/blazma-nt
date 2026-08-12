/**
 * Coded errors.
 *
 * Errors crossing IPC arrive at the renderer as a plain message string, so the
 * code travels as a prefix. The backend still carries a readable English
 * fallback, which is what gets logged; the UI translates the code when it
 * recognises it and shows the fallback when it does not.
 */

export const ERROR_CODES = [
  'E_NPCAP_MISSING',
  'E_DUMPCAP_MISSING',
  'E_IFACE_NOT_CAPTURABLE',
  'E_IFACE_UNKNOWN',
  'E_ALREADY_RUNNING',
  'E_CAPTURE_FAILED',
  'E_CAPTURE_ENDED',
  'E_ROUTER_UNSUPPORTED',
  'E_ROUTER_LOGIN',
  'E_ROUTER_NOT_CONNECTED',
  'E_ROUTER_ACTION'
] as const

export type ErrorCode = (typeof ERROR_CODES)[number]

const SEPARATOR = '|'

export function codedError(code: ErrorCode, fallback: string): Error {
  return new Error(`${code}${SEPARATOR}${fallback}`)
}

export function codedMessage(code: ErrorCode, fallback: string): string {
  return `${code}${SEPARATOR}${fallback}`
}

/** Splits a message back into its code and human-readable text. */
export function parseCoded(message: string): { code: ErrorCode | null; text: string } {
  const index = message.indexOf(SEPARATOR)
  if (index < 0) return { code: null, text: message }
  const code = message.slice(0, index) as ErrorCode
  const text = message.slice(index + 1)
  return ERROR_CODES.includes(code) ? { code, text } : { code: null, text: message }
}
