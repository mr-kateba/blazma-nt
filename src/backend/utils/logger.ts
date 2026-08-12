import type { LogLevel } from '../../shared/types.js'
import type { EventBus } from '../core/bus.js'
import type { Store } from '../database/store.js'

const ORDER: Record<LogLevel, number> = { DEBUG: 10, INFO: 20, WARNING: 30, ERROR: 40 }

/**
 * Patterns that must never reach the log file. Capture code should not pass
 * secrets to the logger in the first place; this is the second line of defence.
 */
const SCRUB: Array<[RegExp, string]> = [
  // Header-style secrets run to the end of the line, so the whole value goes.
  [/\b(authorization|proxy-authorization)\s*[:=][^\r\n]*/gi, '$1: [redacted]'],
  [/\b(cookie|set-cookie)\s*[:=][^\r\n]*/gi, '$1: [redacted]'],
  [/\b(password|passwd|pwd|secret|token|api[_-]?key|session[_-]?id)\s*[:=]\s*\S+/gi, '$1=[redacted]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]+=*/g, 'Bearer [redacted]']
]

export function scrub(message: string): string {
  let out = message
  for (const [re, replacement] of SCRUB) out = out.replace(re, replacement)
  return out
}

export class Logger {
  private minLevel: LogLevel = 'INFO'

  constructor(
    private readonly store: Store,
    private readonly bus: EventBus
  ) {}

  setLevel(level: LogLevel): void {
    this.minLevel = level
  }

  private write(level: LogLevel, scope: string, message: string): void {
    if (ORDER[level] < ORDER[this.minLevel]) return
    const safe = scrub(message).slice(0, 2000)
    const ts = Date.now()
    let id = 0
    try {
      id = this.store.insertLog(ts, level, scope, safe)
    } catch {
      // Logging must never throw into the caller.
    }
    this.bus.emit('log:new', { id, ts, level, scope, message: safe })
    if (level === 'ERROR' || level === 'WARNING') {
      console.error(`[${level}] ${scope}: ${safe}`)
    }
  }

  debug(scope: string, message: string): void {
    this.write('DEBUG', scope, message)
  }
  info(scope: string, message: string): void {
    this.write('INFO', scope, message)
  }
  warn(scope: string, message: string): void {
    this.write('WARNING', scope, message)
  }
  error(scope: string, message: string, err?: unknown): void {
    const detail = err instanceof Error ? `${message}: ${err.message}` : message
    this.write('ERROR', scope, detail)
  }
}
