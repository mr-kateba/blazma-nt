import type { TimeRange } from '@shared/types'

/** Window length for each range, mirroring the backend's ranges module. */
const WINDOW_MS: Record<TimeRange, number> = {
  '1m': 60_000,
  '5m': 5 * 60_000,
  '15m': 15 * 60_000,
  '1h': 60 * 60_000,
  '24h': 24 * 60 * 60_000,
  '7d': 7 * 24 * 60 * 60_000,
  '30d': 30 * 24 * 60 * 60_000
}

export function resolveRangeMs(range: TimeRange): number {
  return WINDOW_MS[range] ?? WINDOW_MS['15m']
}
